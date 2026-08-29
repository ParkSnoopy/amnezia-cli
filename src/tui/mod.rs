use crate::core::runner;
use crate::core::{Command, FeatureAction, State, Store, TuiAction};
use crate::sanitize_terminal;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use std::io::{self, Stdout};
use std::time::Duration;
use strum::IntoEnumIterator;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColorProfile {
    FullColor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColorPalette {
    TokioNight,
}

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
        let profile = ColorProfile::FullColor;
        let palette = ColorPalette::TokioNight;
        match (profile, palette) {
            (ColorProfile::FullColor, ColorPalette::TokioNight) => Self {
                background: Color::Rgb(26, 27, 38),
                foreground: Color::Rgb(192, 202, 245),
                accent: Color::Rgb(122, 162, 247),
                accent_text: Color::Rgb(26, 27, 38),
                border: Color::Rgb(86, 95, 137),
                muted: Color::Rgb(169, 177, 214),
            },
        }
    }

    const fn profile_name() -> &'static str { "FullColor" }
    const fn palette_name() -> &'static str { "tokio-night" }

    fn block(self, title: &'static str) -> Block<'static> {
        Block::default().title(title).borders(Borders::ALL)
            .border_style(Style::default().fg(self.border).bg(self.background))
            .title_style(Style::default().fg(self.accent).bg(self.background).add_modifier(Modifier::BOLD))
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

fn event_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, store: &Store, state: &mut State) -> Result<()> {
    let mut ui = UiState::default();
    loop {
        let had_connection = state.connection.is_some();
        runner::refresh_connection(state);
        if had_connection && state.connection.is_none() {
            store.save(state)?;
        }
        terminal.draw(|frame| render(frame, state, &ui))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else { continue };
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
                KeyCode::Backspace => { input.pop(); }
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
                ui.message = if ui.dry_run { "Preview mode enabled".into() } else { "Preview mode disabled".into() };
            }
            KeyCode::Enter => {
                if ui.selected.info().prompt.is_empty() {
                    run_action(store, state, &mut ui, "");
                } else {
                    ui.input = Some(String::new());
                }
            }
            KeyCode::Char('c') => run_command(store, state, &mut ui, Command::Connect { profile: None }),
            KeyCode::Char('d') => run_command(store, state, &mut ui, Command::Disconnect),
            KeyCode::Char('r') => match store.load() {
                Ok(loaded) => {
                    *state = loaded;
                    ui.message = "Reloaded".into();
                }
                Err(error) => ui.message = format!("Error: {error:#}"),
            },
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
    let result = parse_action(action, input).and_then(|command| crate::core::execute(store, state, command, ui.dry_run));
    match result {
        Ok(output) => {
            ui.output = if output.is_empty() { format!("{} completed", info.label) } else { output };
            ui.output_scroll = 0;
            ui.message = format!("{} / {}", info.category, info.label);
        }
        Err(error) => ui.message = format!("Error: {error:#}"),
    }
}

fn run_command(store: &Store, state: &mut State, ui: &mut UiState, command: Command) {
    match crate::core::execute(store, state, command, ui.dry_run) {
        Ok(output) => {
            ui.output = output;
            ui.output_scroll = 0;
            ui.message = "Connection action completed".into();
        }
        Err(error) => ui.message = format!("Error: {error:#}"),
    }
}

fn parse_action(action: FeatureAction, input: &str) -> Result<Command> {
    action.parse(input)
}

fn render(frame: &mut ratatui::Frame<'_>, state: &State, ui: &UiState) {
    let theme = Theme::active();
    frame.render_widget(Block::default().style(Style::default().fg(theme.foreground).bg(theme.background)), frame.area());
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(3), Constraint::Length(3)])
        .split(frame.area());
    let mut areas = layout.iter().copied();
    let title_area = areas.next().expect("title area");
    let main_area = areas.next().expect("main area");
    let action_area = areas.next().expect("action area");
    let footer_area = areas.next().expect("footer area");
    let title = Paragraph::new(Line::from(vec![
        Span::styled(" AmneziaVPN TUI ", Style::default().fg(theme.accent_text).bg(theme.accent).add_modifier(Modifier::BOLD)),
        Span::styled(if state.connection.is_some() { " CONNECTED" } else { " DISCONNECTED" }, Style::default().fg(theme.foreground).bg(theme.background)),
        Span::styled(if ui.dry_run { "  PREVIEW" } else { "" }, Style::default().fg(theme.muted).bg(theme.background)),
        Span::styled(format!("  {} / {}", Theme::profile_name(), Theme::palette_name()), Style::default().fg(theme.muted).bg(theme.background)),
    ]))
    .style(Style::default().fg(theme.foreground).bg(theme.background))
    .block(theme.block(""));
    frame.render_widget(title, title_area);

    let column_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
        .split(main_area);
    let mut columns = column_layout.iter().copied();
    let features_area = columns.next().expect("features area");
    let result_area = columns.next().expect("result area");
    let actions = FeatureAction::iter().map(|action| {
        let info = action.info();
        ListItem::new(format!("{} / {}", info.category, info.label))
    }).collect::<Vec<_>>();
    let selected = FeatureAction::iter().position(|action| action == ui.selected);
    let mut list_state = ListState::default().with_selected(selected);
    let list = List::new(actions)
        .style(Style::default().fg(theme.foreground).bg(theme.background))
        .block(theme.block("All features"))
        .highlight_style(Style::default().bg(theme.accent).fg(theme.accent_text).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, features_area, &mut list_state);

    let profile = state.connection.as_ref()
        .and_then(|connection| state.profiles.get(&connection.profile_id))
        .map(|profile| sanitize_terminal(&profile.name))
        .unwrap_or_else(|| "None".into());
    let summary = format!(
        "Profile: {profile}\nProfiles: {}\nServers: {}\n\n{}",
        state.profiles.len(),
        state.servers.len(),
        sanitize_terminal(&ui.output)
    );
    frame.render_widget(
        Paragraph::new(summary).style(Style::default().fg(theme.foreground).bg(theme.background))
            .scroll((ui.output_scroll, 0)).wrap(Wrap { trim: false }).block(theme.block("Result")),
        result_area,
    );

    let info = ui.selected.info();
    let input = match &ui.input {
        Some(value) => format!("{} {}: {value}_", info.command, info.prompt),
        None => format!("Enter: {} / {}  {}", info.category, info.label, info.prompt),
    };
    frame.render_widget(Paragraph::new(input).style(Style::default().fg(theme.foreground).bg(theme.background)).block(theme.block("Action")), action_area);

    let message = format!("↑/↓ select  PgUp/PgDn result  p preview  Enter run  c connect  d disconnect  r reload  q quit    {}", sanitize_terminal(&ui.message));
    frame.render_widget(Paragraph::new(message).style(Style::default().fg(theme.muted).bg(theme.background)).block(theme.block("")), footer_area);
}

pub fn render_snapshot(state: &State, width: u16, height: u16) -> Result<String> {
    use ratatui::backend::TestBackend;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend)?;
    terminal.draw(|frame| render(frame, state, &UiState::default()))?;
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
        assert!(snapshot.contains("Servers / List"));
        assert!(snapshot.contains("Settings / Show"));
        assert!(snapshot.contains("Split tunnel / List"));
        assert!(snapshot.contains("FullColor / tokio-night"));
    }

    #[test]
    fn dashboard_uses_full_color_tokio_night_palette() {
        use ratatui::backend::TestBackend;
        let theme = Theme::active();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &State::default(), &UiState::default())).unwrap();
        let buffer = terminal.backend().buffer();
        assert!(buffer.content().iter().any(|cell| cell.fg == theme.accent));
        assert!(buffer.content().iter().any(|cell| cell.bg == theme.background));
        assert_eq!(Theme::profile_name(), "FullColor");
        assert_eq!(Theme::palette_name(), "tokio-night");
    }

    #[test]
    fn action_parser_uses_clap_commands() {
        let command = parse_action(FeatureAction::ProfileRename, "profile-id \"New Name\"").unwrap();
        assert!(matches!(command, Command::Profile(crate::core::ProfileCommand::Rename { .. })));
    }
}
