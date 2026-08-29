use crate::model::State;
use crate::runner;
use crate::sanitize_terminal;
use crate::store::Store;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use std::io::{self, Stdout};
use std::time::Duration;

pub fn run(store: &Store, state: &mut State) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = event_loop(&mut terminal, store, state);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, store: &Store, state: &mut State) -> Result<()> {
    let mut message = String::new();
    loop {
        let had_connection = state.connection.is_some();
        runner::refresh_connection(state);
        if had_connection && state.connection.is_none() {
            store.save(state)?;
        }
        terminal.draw(|frame| render(frame, state, &message))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('c') => {
                    message = runner::connect(store, state, None, false).unwrap_or_else(|error| error.to_string());
                }
                KeyCode::Char('d') => {
                    message = runner::disconnect(store, state, false).unwrap_or_else(|error| error.to_string());
                }
                KeyCode::Char('r') => {
                    *state = store.load()?;
                    message = "reloaded".into();
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub fn render(frame: &mut ratatui::Frame<'_>, state: &State, message: &str) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8), Constraint::Length(4)])
        .split(frame.area());
    let title = Paragraph::new(Line::from(vec![
        Span::styled(" Amnezia ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" Qt-free VPN console"),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, areas[0]);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(areas[1]);
    let profiles = if state.profiles.is_empty() {
        vec![ListItem::new("No profiles. Use: amn profile import FILE")]
    } else {
        state.profiles.values().map(|profile| {
            let default = if state.default_profile.as_deref() == Some(&profile.id) { "*" } else { " " };
            ListItem::new(format!("{default} {} [{}]", sanitize_terminal(&profile.name), profile.protocol))
        }).collect()
    };
    frame.render_widget(List::new(profiles).block(Block::default().title("Profiles").borders(Borders::ALL)), columns[0]);

    let connection = match &state.connection {
        Some(connection) => {
            let profile = state.profiles.get(&connection.profile_id).map(|value| value.name.as_str()).unwrap_or("missing profile");
            format!("CONNECTED\nProfile: {}\nPID: {}\nInterface: {}", sanitize_terminal(profile), connection.pid.map(|value| value.to_string()).unwrap_or_else(|| "managed by protocol tool".into()), sanitize_terminal(connection.interface.as_deref().unwrap_or("n/a")))
        }
        None => "DISCONNECTED".into(),
    };
    let details = format!(
        "{connection}\n\nServers: {}\nDNS: {}, {}\nRoute mode: {:?}\nKill switch: {}",
        state.servers.len(), sanitize_terminal(&state.settings.primary_dns), sanitize_terminal(&state.settings.secondary_dns),
        state.settings.route_mode, if state.settings.kill_switch { "on" } else { "off" }
    );
    frame.render_widget(Paragraph::new(details).wrap(Wrap { trim: true }).block(Block::default().title("Status").borders(Borders::ALL)), columns[1]);

    let footer = Paragraph::new(vec![
        Line::from("c connect   d disconnect   r reload   q quit"),
        Line::styled(sanitize_terminal(message), Style::default().fg(if message.contains("error") || message.contains("not ") { Color::Red } else { Color::Yellow })),
    ])
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, areas[2]);
}

pub fn render_snapshot(state: &State, width: u16, height: u16) -> Result<String> {
    use ratatui::backend::TestBackend;
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend)?;
    terminal.draw(|frame| render(frame, state, ""))?;
    let buffer = terminal.backend().buffer();
    let mut output = String::new();
    for y in 0..height {
        for x in 0..width {
            output.push_str(buffer[(x, y)].symbol());
        }
        output.push('\n');
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_renders_disconnected_state_and_help() {
        let snapshot = render_snapshot(&State::default(), 80, 24).unwrap();
        assert!(snapshot.contains("DISCONNECTED"));
        assert!(snapshot.contains("No profiles"));
        assert!(snapshot.contains("c connect"));
    }
}
