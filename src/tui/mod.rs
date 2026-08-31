use std::{
    io::{
        self,
        Stdout,
    },
    time::Duration,
};

use anyhow::Result;
use crossterm::{
    event::{
        self,
        Event,
        KeyCode,
        KeyEventKind,
    },
    execute,
    terminal::{
        EnterAlternateScreen,
        LeaveAlternateScreen,
        disable_raw_mode,
        enable_raw_mode,
    },
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{
        Alignment,
        Constraint,
        Direction,
        Layout,
    },
    style::{
        Color,
        Modifier,
        Style,
    },
    text::{
        Line,
        Span,
        Text,
    },
    widgets::{
        Block,
        Borders,
        List,
        ListItem,
        ListState,
        Paragraph,
        Wrap,
    },
};
use strum::IntoEnumIterator;

use crate::{
    core::{
        Command,
        FeatureAction,
        State,
        Store,
        TuiAction,
    },
    sanitize_terminal,
};

#[derive(Clone, Copy)]
struct Theme {
    canvas: Color,
    elevated: Color,
    ink: Color,
    body: Color,
    accent: Color,
    accent_soft: Color,
    hairline: Color,
    muted: Color,
    error: Color,
}

impl Theme {
    const fn active() -> Self {
        Self {
            canvas: Color::Rgb(250, 250, 250),
            elevated: Color::Rgb(255, 255, 255),
            ink: Color::Rgb(23, 23, 23),
            body: Color::Rgb(77, 77, 77),
            accent: Color::Rgb(0, 112, 243),
            accent_soft: Color::Rgb(211, 229, 255),
            hairline: Color::Rgb(235, 235, 235),
            muted: Color::Rgb(143, 143, 143),
            error: Color::Rgb(238, 0, 0),
        }
    }

    fn card(self, title: &'static str) -> Block<'static> {
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .style(Style::default().fg(self.body).bg(self.elevated))
            .border_style(Style::default().fg(self.hairline).bg(self.elevated))
            .title_style(
                Style::default()
                    .fg(self.muted)
                    .bg(self.elevated)
                    .add_modifier(Modifier::BOLD),
            )
    }
}

#[derive(Default)]
struct UiState {
    selected: FeatureAction,
    input: Option<String>,
    output: String,
    output_scroll: u16,
    dry_run: bool,
    message: String,
}

pub fn run(store: &Store, state: &mut State) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error.into());
    }
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(terminal) => terminal,
        Err(error) => {
            let mut stdout = io::stdout();
            let _ = execute!(stdout, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            return Err(error.into());
        }
    };
    let result = event_loop(&mut terminal, store, state);
    let raw_result = disable_raw_mode();
    let screen_result = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let cursor_result = terminal.show_cursor();
    result?;
    raw_result?;
    screen_result?;
    cursor_result?;
    Ok(())
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    store: &Store,
    state: &mut State,
) -> Result<()> {
    let mut ui = UiState::default();
    loop {
        if let Err(error) =
            crate::core::Connections::new(store, state).status(!ui.dry_run)
        {
            ui.output = format!("connection recovery required: {error:#}");
            ui.output_scroll = 0;
            ui.message = "Connection recovery required".into();
        }
        terminal.draw(|frame| render(frame, state, &ui))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Some(input) = &mut ui.input {
            match key.code {
                KeyCode::Esc => ui.input = None,
                KeyCode::Enter => {
                    let input = ui.input.take().unwrap_or_default();
                    run_action(store, state, &mut ui, &input);
                }
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(character) => input.push(character),
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Up | KeyCode::Char('k') => ui.selected = previous_action(ui.selected),
            KeyCode::Down | KeyCode::Char('j') => ui.selected = next_action(ui.selected),
            KeyCode::PageUp => ui.output_scroll = ui.output_scroll.saturating_sub(1),
            KeyCode::PageDown => ui.output_scroll = ui.output_scroll.saturating_add(1),
            KeyCode::Char('p') => {
                ui.dry_run = !ui.dry_run;
                ui.message = if ui.dry_run {
                    "Preview mode enabled".into()
                } else {
                    "Preview mode disabled".into()
                };
            }
            KeyCode::Enter => {
                if ui.selected.info().prompt.is_empty() {
                    run_action(store, state, &mut ui, "");
                } else {
                    ui.input = Some(String::new());
                }
            }
            KeyCode::Char('c') => {
                run_command(store, state, &mut ui, Command::Connect { profile: None })
            }
            KeyCode::Char('d') => run_command(store, state, &mut ui, Command::Disconnect),
            KeyCode::Char('r') => {
                match store.load() {
                    Ok(loaded) => {
                        *state = loaded;
                        ui.message = "Reloaded".into();
                    }
                    Err(error) => {
                        ui.output = format!("Error\n\n{error:#}");
                        ui.output_scroll = 0;
                        ui.message = "Reload failed".into();
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn previous_action(selected: FeatureAction) -> FeatureAction {
    let mut previous = selected;
    for action in FeatureAction::iter() {
        if action == selected {
            return previous;
        }
        previous = action;
    }
    selected
}

fn next_action(selected: FeatureAction) -> FeatureAction {
    let mut actions = FeatureAction::iter();
    while let Some(action) = actions.next() {
        if action == selected {
            return actions.next().unwrap_or(selected);
        }
    }
    selected
}

fn run_action(store: &Store, state: &mut State, ui: &mut UiState, input: &str) {
    let action = ui.selected;
    let info = action.info();
    let result = parse_action(action, input)
        .and_then(|command| crate::core::execute(store, state, command, ui.dry_run));
    match result {
        Ok(output) => {
            ui.output = if output.is_empty() {
                format!("{} completed", info.label)
            } else {
                output
            };
            ui.output_scroll = 0;
            ui.message = format!("{} / {}", info.category, info.label);
        }
        Err(error) => {
            ui.output = format!("Error\n\n{error:#}");
            ui.output_scroll = 0;
            ui.message = "Action failed".into();
        }
    }
}

fn run_command(store: &Store, state: &mut State, ui: &mut UiState, command: Command) {
    match crate::core::execute(store, state, command, ui.dry_run) {
        Ok(output) => {
            ui.output = output;
            ui.output_scroll = 0;
            ui.message = "Connection action completed".into();
        }
        Err(error) => {
            ui.output = format!("Error\n\n{error:#}");
            ui.output_scroll = 0;
            ui.message = "Connection action failed".into();
        }
    }
}

fn parse_action(action: FeatureAction, input: &str) -> Result<Command> {
    action.parse(input)
}

fn render(frame: &mut ratatui::Frame<'_>, state: &State, ui: &UiState) {
    let theme = Theme::active();
    frame.render_widget(
        Block::default().style(Style::default().fg(theme.body).bg(theme.canvas)),
        frame.area(),
    );
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(frame.area());
    let header_area = layout[0];
    let overview_area = layout[1];
    let workspace_area = layout[2];
    let command_area = layout[3];
    let footer_area = layout[4];

    let header_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(header_area);
    let header_block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(theme.hairline).bg(theme.canvas));
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " AmneziaVPN",
                Style::default()
                    .fg(theme.ink)
                    .bg(theme.canvas)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Linux VPN client", Style::default().fg(theme.muted)),
        ]))
        .style(Style::default().bg(theme.canvas))
        .block(header_block.clone()),
        header_columns[0],
    );
    let connection_label = if state.connection.is_some() {
        "● Connected"
    } else {
        "○ Disconnected"
    };
    let mode = if ui.dry_run { "  ·  Preview" } else { "" };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(connection_label, Style::default().fg(theme.accent)),
            Span::styled(mode, Style::default().fg(theme.muted)),
            Span::raw(" "),
        ]))
        .alignment(Alignment::Right)
        .style(Style::default().bg(theme.canvas))
        .block(header_block),
        header_columns[1],
    );

    let active_profile = state
        .connection
        .as_ref()
        .and_then(|connection| state.profiles.get(&connection.profile_id))
        .map(|profile| sanitize_terminal(&profile.name))
        .unwrap_or_else(|| "None".into());
    let overview = [
        ("CONNECTION", if state.connection.is_some() { "Connected".to_owned() } else { "Disconnected".to_owned() }),
        ("ACTIVE PROFILE", active_profile),
        ("PROFILES", state.profiles.len().to_string()),
        ("MODE", if ui.dry_run { "Preview".to_owned() } else { "Live".to_owned() }),
    ];
    let overview_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 4); 4])
        .split(overview_area);
    for ((label, value), area) in overview.into_iter().zip(overview_columns.iter()) {
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(
                    format!(" {label}"),
                    Style::default()
                        .fg(theme.muted)
                        .bg(theme.elevated)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::styled(
                    format!(" {value}"),
                    Style::default()
                        .fg(theme.ink)
                        .bg(theme.elevated)
                        .add_modifier(Modifier::BOLD),
                ),
            ])
            .block(theme.card("")),
            *area,
        );
    }

    let action_width = if workspace_area.width >= 100 { 34 } else { 28 };
    let workspace = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(action_width), Constraint::Min(36)])
        .split(workspace_area);
    let mut previous_category = "";
    let actions = FeatureAction::iter()
        .map(|action| {
            let info = action.info();
            let mut lines = Vec::new();
            if previous_category != info.category {
                previous_category = info.category;
                lines.push(Line::styled(
                    format!(" {}", info.category.to_ascii_uppercase()),
                    Style::default()
                        .fg(theme.muted)
                        .bg(theme.elevated)
                        .add_modifier(Modifier::BOLD),
                ));
            }
            lines.push(Line::styled(
                format!("   {}", info.label),
                Style::default().fg(theme.body).bg(theme.elevated),
            ));
            ListItem::new(lines)
        })
        .collect::<Vec<_>>();
    let selected = FeatureAction::iter().position(|action| action == ui.selected);
    let mut list_state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(
        List::new(actions)
            .style(Style::default().fg(theme.body).bg(theme.elevated))
            .block(theme.card(" ACTIONS "))
            .highlight_style(
                Style::default()
                    .bg(theme.accent_soft)
                    .fg(theme.ink)
                    .add_modifier(Modifier::BOLD),
            ),
        workspace[0],
        &mut list_state,
    );

    let info = ui.selected.info();
    let eyebrow = Style::default()
        .fg(theme.muted)
        .bg(theme.elevated)
        .add_modifier(Modifier::BOLD);
    let mut result_lines = vec![
        Line::styled("SELECTED ACTION", eyebrow),
        Line::styled(
            info.label,
            Style::default()
                .fg(theme.ink)
                .bg(theme.elevated)
                .add_modifier(Modifier::BOLD),
        ),
        Line::from(vec![
            Span::styled("Command  ", eyebrow),
            Span::styled(
                format!("{} {}", info.command, info.prompt).trim().to_owned(),
                Style::default().fg(theme.body).bg(theme.elevated),
            ),
        ]),
        Line::default(),
        Line::styled("ACTIVITY", eyebrow),
        Line::default(),
    ];
    let output = sanitize_terminal(&ui.output);
    if output.trim().is_empty() {
        result_lines.push(Line::styled(
            "Run an action to see its result here.",
            Style::default().fg(theme.muted).bg(theme.elevated),
        ));
    } else {
        result_lines.extend(output.lines().enumerate().map(|(index, line)| {
            if index == 0 && line.eq_ignore_ascii_case("error") {
                Line::styled(
                    line.to_owned(),
                    Style::default()
                        .fg(theme.error)
                        .bg(theme.elevated)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Line::styled(
                    line.to_owned(),
                    Style::default().fg(theme.body).bg(theme.elevated),
                )
            }
        }));
    }
    frame.render_widget(
        Paragraph::new(Text::from(result_lines))
            .scroll((ui.output_scroll, 0))
            .wrap(Wrap { trim: false })
            .block(theme.card(" DETAILS ")),
        workspace[1],
    );

    let command = match &ui.input {
        Some(value) => format!("{} {}  {value}_", info.command, info.prompt),
        None if info.prompt.is_empty() => format!("Press Enter to run {}.", info.label.to_lowercase()),
        None => format!("Press Enter to run {}  ·  {}", info.label.to_lowercase(), info.prompt),
    };
    let input_width = command_area.width.saturating_sub(2) as usize;
    let input_scroll = ui
        .input
        .as_ref()
        .map(|_| Line::raw(command.as_str()).width().saturating_sub(input_width) as u16)
        .unwrap_or(0);
    frame.render_widget(
        Paragraph::new(command)
            .style(Style::default().fg(theme.ink).bg(theme.elevated))
            .scroll((0, input_scroll))
            .block(theme.card(" COMMAND ")),
        command_area,
    );

    let shortcuts = if footer_area.width >= 120 {
        " ↑↓ Navigate   PgUp PgDn Scroll   P Preview   Enter Run   C Connect   D Disconnect   R Reload   Q Quit"
    } else {
        " ↑↓ Navigate   Enter Run   P Preview   Q Quit"
    };
    let footer_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(footer_area);
    let footer_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(theme.hairline).bg(theme.canvas));
    frame.render_widget(
        Paragraph::new(shortcuts)
            .style(Style::default().fg(theme.muted).bg(theme.canvas))
            .block(footer_block.clone()),
        footer_columns[0],
    );
    frame.render_widget(
        Paragraph::new(sanitize_terminal(&ui.message))
            .alignment(Alignment::Right)
            .style(Style::default().fg(theme.body).bg(theme.canvas))
            .block(footer_block),
        footer_columns[1],
    );
}

pub fn render_snapshot(state: &State, width: u16, height: u16) -> Result<String> {
    render_snapshot_with_ui(state, &UiState::default(), width, height)
}

fn render_snapshot_with_ui(
    state: &State,
    ui: &UiState,
    width: u16,
    height: u16,
) -> Result<String> {
    use ratatui::backend::TestBackend;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend)?;
    terminal.draw(|frame| render(frame, state, ui))?;
    let buffer = terminal.backend().buffer();
    let mut output = String::new();
    for y in 0..height {
        for x in 0..width {
            if let Some(cell) = buffer.cell((x, y)) {
                output.push_str(cell.symbol());
            }
        }
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_exposes_all_feature_groups() {
        let snapshot = render_snapshot(&State::default(), 120, 60).unwrap();
        assert!(snapshot.contains("AmneziaVPN"));
        assert!(snapshot.contains("CONNECTION"));
        assert!(snapshot.contains("PROFILES"));
        assert!(snapshot.contains("SETTINGS"));
        assert!(snapshot.contains("SPLIT TUNNEL"));
        assert!(!snapshot.contains("Connection / Status"));
    }

    #[test]
    fn dashboard_applies_configured_colors() {
        use ratatui::backend::TestBackend;
        let theme = Theme::active();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, &State::default(), &UiState::default()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        for color in [
            theme.canvas,
            theme.elevated,
            theme.ink,
            theme.body,
            theme.accent,
            theme.hairline,
            theme.muted,
        ] {
            assert!(
                buffer
                    .content()
                    .iter()
                    .any(|cell| cell.fg == color || cell.bg == color),
                "missing configured color {color:?}"
            );
        }
    }

    #[test]
    fn profile_output_uses_readable_numbered_rows() {
        let mut state = State::default();
        state.profiles.insert(
            "internal-a".into(),
            crate::core::model::Profile {
                id: "internal-a".into(),
                name: "KR 027".into(),
                protocol: crate::core::model::Protocol::Xray,
                source: "/private/profile.json".into(),
                enabled: true,
            },
        );
        state.profiles.insert(
            "internal-b".into(),
            crate::core::model::Profile {
                id: "internal-b".into(),
                name: "JP 005".into(),
                protocol: crate::core::model::Protocol::AmneziaWg,
                source: "/private/profile.conf".into(),
                enabled: true,
            },
        );
        let ui = UiState {
            output: "  1. XRay        KR 027  default\n  2. AmneziaWG   JP 005".into(),
            ..UiState::default()
        };

        let snapshot = render_snapshot_with_ui(&state, &ui, 160, 40).unwrap();

        assert!(snapshot.contains("Disconnected"));
        assert!(snapshot.contains("ACTIVE PROFILE"));
        assert!(snapshot.contains("None"));
        assert!(snapshot.contains("1. XRay        KR 027"));
        assert!(snapshot.contains("2. AmneziaWG   JP 005"));
        assert!(!snapshot.contains("internal-a"));
        println!("{snapshot}");
    }

    #[test]
    fn narrow_layout_keeps_errors_and_input_cursor_visible() {
        let ui = UiState {
            selected: FeatureAction::ProfileImport,
            input: Some(
                "/home/user/very/long/path/to/backups/amnezia/备份/配置.backup".into(),
            ),
            output: "Error\n\nThe selected backup could not be opened".into(),
            message: "Action failed".into(),
            ..UiState::default()
        };

        let snapshot = render_snapshot_with_ui(&State::default(), &ui, 80, 32).unwrap();

        assert!(snapshot.contains("The selected backup"));
        assert!(snapshot.contains("Action failed"));
        assert!(snapshot.contains("backup_"));
        println!("{snapshot}");
    }

    #[test]
    fn action_parser_uses_clap_commands() {
        let command = parse_action(FeatureAction::ProfileRename, "1 \"New Name\"").unwrap();
        assert!(matches!(
            command,
            Command::Profile(crate::core::ProfileCommand::Rename { order: 1, .. })
        ));
    }
}
