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
    background: Color,
    foreground: Color,
    accent: Color,
    accent_text: Color,
    border: Color,
    muted: Color,
}

impl Theme {
    const fn active() -> Self {
        Self {
            background: Color::Rgb(26, 27, 38),
            foreground: Color::Rgb(192, 202, 245),
            accent: Color::Rgb(122, 162, 247),
            accent_text: Color::Rgb(26, 27, 38),
            border: Color::Rgb(86, 95, 137),
            muted: Color::Rgb(169, 177, 214),
        }
    }

    fn block(self, title: &'static str) -> Block<'static> {
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.border).bg(self.background))
            .title_style(
                Style::default()
                    .fg(self.accent)
                    .bg(self.background)
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
        Block::default().style(Style::default().fg(theme.foreground).bg(theme.background)),
        frame.area(),
    );
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
            Constraint::Length(4),
        ])
        .split(frame.area());
    let mut areas = layout.iter().copied();
    let title_area = areas.next().expect("title area");
    let main_area = areas.next().expect("main area");
    let action_area = areas.next().expect("action area");
    let footer_area = areas.next().expect("footer area");
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            " AmneziaVPN TUI ",
            Style::default()
                .fg(theme.accent_text)
                .bg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            if state.connection.is_some() {
                " CONNECTED"
            } else {
                " DISCONNECTED"
            },
            Style::default().fg(theme.foreground).bg(theme.background),
        ),
        Span::styled(
            if ui.dry_run { "  PREVIEW" } else { "" },
            Style::default().fg(theme.muted).bg(theme.background),
        ),
    ]))
    .style(Style::default().fg(theme.foreground).bg(theme.background))
    .block(theme.block(""));
    frame.render_widget(title, title_area);

    let column_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(main_area);
    let mut columns = column_layout.iter().copied();
    let features_area = columns.next().expect("features area");
    let result_area = columns.next().expect("result area");
    let actions = FeatureAction::iter()
        .map(|action| {
            let info = action.info();
            ListItem::new(format!("{} / {}", info.category, info.label))
        })
        .collect::<Vec<_>>();
    let selected = FeatureAction::iter().position(|action| action == ui.selected);
    let mut list_state = ListState::default().with_selected(selected);
    let list = List::new(actions)
        .style(Style::default().fg(theme.foreground).bg(theme.background))
        .block(theme.block("Actions"))
        .highlight_style(
            Style::default()
                .bg(theme.accent)
                .fg(theme.accent_text)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, features_area, &mut list_state);

    let active_profile = state
        .connection
        .as_ref()
        .and_then(|connection| state.profiles.get(&connection.profile_id))
        .map(|profile| sanitize_terminal(&profile.name))
        .unwrap_or_else(|| "—".into());
    let connection = if state.connection.is_some() {
        "Connected"
    } else {
        "Disconnected"
    };
    let label_style = Style::default()
        .fg(theme.muted)
        .bg(theme.background)
        .add_modifier(Modifier::BOLD);
    let value_style = Style::default().fg(theme.foreground).bg(theme.background);
    let mut result_lines = vec![
        Line::from(vec![
            Span::styled("Connection  ", label_style),
            Span::styled(connection, value_style),
        ]),
        Line::from(vec![
            Span::styled("Active      ", label_style),
            Span::styled(active_profile, value_style),
        ]),
        Line::from(vec![
            Span::styled("Profiles    ", label_style),
            Span::styled(state.profiles.len().to_string(), value_style),
        ]),
    ];
    let output = sanitize_terminal(&ui.output);
    if !output.trim().is_empty() {
        result_lines.push(Line::default());
        result_lines.push(Line::styled("Output", label_style));
        result_lines.push(Line::default());
        result_lines.extend(output.lines().map(|line| Line::raw(line.to_owned())));
    }
    frame.render_widget(
        Paragraph::new(Text::from(result_lines))
            .style(Style::default().fg(theme.foreground).bg(theme.background))
            .scroll((ui.output_scroll, 0))
            .wrap(Wrap { trim: false })
            .block(theme.block("Details")),
        result_area,
    );

    let info = ui.selected.info();
    let input = match &ui.input {
        Some(value) => format!("{} {}: {value}_", info.command, info.prompt),
        None => format!("Enter: {} / {}  {}", info.category, info.label, info.prompt),
    };
    let input_width = action_area.width.saturating_sub(2) as usize;
    let input_scroll = ui
        .input
        .as_ref()
        .map(|_| Line::raw(input.as_str()).width().saturating_sub(input_width) as u16)
        .unwrap_or(0);
    frame.render_widget(
        Paragraph::new(input)
            .style(Style::default().fg(theme.foreground).bg(theme.background))
            .scroll((0, input_scroll))
            .block(theme.block("Action")),
        action_area,
    );

    let shortcuts = if footer_area.width >= 120 {
        "↑/↓ select  PgUp/PgDn details  p preview  Enter run  c connect  d disconnect  r reload  q quit"
    } else {
        "↑/↓ select  Enter run  p preview  q quit"
    };
    let footer = Text::from(vec![
        Line::raw(shortcuts),
        Line::styled(
            sanitize_terminal(&ui.message),
            Style::default().fg(theme.foreground),
        ),
    ]);
    frame.render_widget(
        Paragraph::new(footer)
            .style(Style::default().fg(theme.muted).bg(theme.background))
            .block(theme.block("")),
        footer_area,
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
        let snapshot = render_snapshot(&State::default(), 120, 40).unwrap();
        assert!(snapshot.contains("AmneziaVPN TUI"));
        assert!(snapshot.contains("Connection / Status"));
        assert!(snapshot.contains("Profiles / List"));
        assert!(snapshot.contains("Settings / Show"));
        assert!(snapshot.contains("Split tunnel / List"));
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
        assert!(buffer.content().iter().any(|cell| cell.fg == theme.accent));
        assert!(
            buffer
                .content()
                .iter()
                .any(|cell| cell.bg == theme.background)
        );
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

        assert!(snapshot.contains("Connection  Disconnected"));
        assert!(snapshot.contains("Active      —"));
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
