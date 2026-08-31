use std::{
    io::{self, Stdout},
    net::IpAddr,
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use strum::IntoEnumIterator;

use crate::{
    core::{
        BackupCommand, Command, FeatureAction, LogsCommand, ProfileCommand, SettingsCommand,
        SplitKind, SplitMode, SplitTunnelCommand, State, Store, TuiAction,
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
            canvas: Color::Rgb(0, 0, 0),
            elevated: Color::Rgb(17, 17, 17),
            ink: Color::Rgb(237, 237, 237),
            body: Color::Rgb(161, 161, 161),
            accent: Color::Rgb(0, 112, 243),
            accent_soft: Color::Rgb(16, 42, 67),
            hairline: Color::Rgb(51, 51, 51),
            muted: Color::Rgb(102, 102, 102),
            error: Color::Rgb(255, 26, 26),
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

#[derive(Clone)]
enum Choice {
    Profile(usize),
    Logging,
    DnsServers,
    Boolean(bool),
    Mode(SplitMode),
    Route(String),
}

#[derive(Clone)]
struct ChoiceItem {
    label: String,
    value: Choice,
}

#[derive(Clone, Copy)]
enum PickerKind {
    Connect,
    ProfileShow,
    ProfileExport,
    ProfileRemove,
    ProfileRename,
    ProfileEnable,
    ProfileDisable,
    ProfileDefault,
    SettingKey,
    Logging,
    SplitRemove,
    SplitMode,
}

#[derive(Clone, Copy)]
enum FormKind {
    ProfileImport,
    ProfileExport(usize),
    ProfileRename(usize),
    SplitAdd,
    BackupCreate,
    BackupRestore,
    LogsExport,
}

struct Field {
    label: &'static str,
    value: String,
    optional: bool,
}

enum Dialog {
    Picker {
        title: &'static str,
        kind: PickerKind,
        choices: Vec<ChoiceItem>,
        selected: usize,
        error: String,
    },
    Form {
        title: &'static str,
        kind: FormKind,
        fields: Vec<Field>,
        selected: usize,
        error: String,
    },
    IpList {
        values: Vec<String>,
        selected: usize,
        error: String,
    },
}

impl Dialog {
    fn move_previous(&mut self) {
        let (selected, count) = match self {
            Self::Picker { selected, choices, .. } => (selected, choices.len()),
            Self::Form { selected, fields, .. } => (selected, fields.len()),
            Self::IpList { selected, values, .. } => (selected, values.len()),
        };
        *selected = selected.saturating_sub(1);
        if count == 0 {
            *selected = 0;
        }
    }

    fn move_next(&mut self) {
        let (selected, count) = match self {
            Self::Picker { selected, choices, .. } => (selected, choices.len()),
            Self::Form { selected, fields, .. } => (selected, fields.len()),
            Self::IpList { selected, values, .. } => (selected, values.len()),
        };
        if *selected + 1 < count {
            *selected += 1;
        }
    }

    fn edit(&mut self, character: char) {
        if character.is_control() {
            return;
        }
        match self {
            Self::Form { fields, selected, error, .. } => {
                if let Some(field) = fields.get_mut(*selected) {
                    field.value.push(character);
                    error.clear();
                }
            }
            Self::IpList { values, selected, error } => {
                if let Some(value) = values.get_mut(*selected) {
                    value.push(character);
                    error.clear();
                }
            }
            Self::Picker { .. } => {}
        }
    }

    fn backspace(&mut self) {
        match self {
            Self::Form { fields, selected, error, .. } => {
                if let Some(field) = fields.get_mut(*selected) {
                    field.value.pop();
                    error.clear();
                }
            }
            Self::IpList { values, selected, error } => {
                if let Some(value) = values.get_mut(*selected) {
                    value.pop();
                    error.clear();
                }
            }
            Self::Picker { .. } => {}
        }
    }

    fn add_ip_row(&mut self) {
        if let Self::IpList { values, selected, error } = self {
            let insert_at = (*selected + 1).min(values.len());
            values.insert(insert_at, String::new());
            *selected = insert_at;
            error.clear();
        }
    }

    fn remove_ip_row(&mut self) {
        if let Self::IpList { values, selected, error } = self {
            if values.len() > 1 {
                values.remove(*selected);
                *selected = (*selected).min(values.len() - 1);
            } else {
                values[0].clear();
            }
            error.clear();
        }
    }

    fn set_error(&mut self, message: String) {
        match self {
            Self::Picker { error, .. }
            | Self::Form { error, .. }
            | Self::IpList { error, .. } => *error = message,
        }
    }
}

#[derive(Default)]
struct UiState {
    selected: FeatureAction,
    dialog: Option<Dialog>,
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
        if let Err(error) = crate::core::Connections::new(store, state).status(!ui.dry_run) {
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
        if ui.dialog.is_some() {
            handle_dialog_key(store, state, &mut ui, key.code);
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
            KeyCode::Enter => open_selected_action(store, state, &mut ui),
            KeyCode::Char('c') => run_command(store, state, &mut ui, Command::Connect { profile: None }),
            KeyCode::Char('d') => run_command(store, state, &mut ui, Command::Disconnect),
            KeyCode::Char('r') => reload_state(store, state, &mut ui),
            _ => {}
        }
    }
    Ok(())
}

fn reload_state(store: &Store, state: &mut State, ui: &mut UiState) {
    match store.load() {
        Ok(loaded) => {
            *state = loaded;
            ui.message = "Reloaded".into();
        }
        Err(error) => set_error(ui, "Reload failed", &error),
    }
}

fn handle_dialog_key(store: &Store, state: &mut State, ui: &mut UiState, key: KeyCode) {
    match key {
        KeyCode::Esc => ui.dialog = None,
        KeyCode::Up => ui.dialog.as_mut().expect("dialog exists").move_previous(),
        KeyCode::Down | KeyCode::Tab => ui.dialog.as_mut().expect("dialog exists").move_next(),
        KeyCode::Backspace => ui.dialog.as_mut().expect("dialog exists").backspace(),
        KeyCode::Insert => ui.dialog.as_mut().expect("dialog exists").add_ip_row(),
        KeyCode::Delete => ui.dialog.as_mut().expect("dialog exists").remove_ip_row(),
        KeyCode::Char(character) => ui.dialog.as_mut().expect("dialog exists").edit(character),
        KeyCode::Enter => submit_dialog(store, state, ui),
        _ => {}
    }
}

fn submit_dialog(store: &Store, state: &mut State, ui: &mut UiState) {
    let Some(dialog) = ui.dialog.take() else {
        return;
    };
    match resolve_dialog(dialog, state) {
        Ok(DialogResolution::Command(command)) => run_command(store, state, ui, command),
        Ok(DialogResolution::Dialog(dialog)) => ui.dialog = Some(dialog),
        Err((mut dialog, error)) => {
            dialog.set_error(format!("{error:#}"));
            ui.dialog = Some(dialog);
        }
    }
}

enum DialogResolution {
    Command(Command),
    Dialog(Dialog),
}

fn resolve_dialog(
    dialog: Dialog,
    state: &State,
) -> std::result::Result<DialogResolution, (Dialog, anyhow::Error)> {
    let result = resolve_dialog_inner(&dialog, state);
    result.map_err(|error| (dialog, error))
}

fn resolve_dialog_inner(dialog: &Dialog, state: &State) -> Result<DialogResolution> {
    match dialog {
        Dialog::Picker { kind, choices, selected, .. } => {
            let choice = choices.get(*selected).context("no selectable value is available")?;
            resolve_choice(*kind, &choice.value, state)
        }
        Dialog::Form { kind, fields, selected, .. } => {
            if *selected + 1 < fields.len() {
                let mut next = clone_form(dialog)?;
                if let Dialog::Form { selected, .. } = &mut next {
                    *selected += 1;
                }
                return Ok(DialogResolution::Dialog(next));
            }
            form_command(*kind, fields).map(DialogResolution::Command)
        }
        Dialog::IpList { values, .. } => {
            let servers = validate_ip_rows(values)?;
            Ok(DialogResolution::Command(Command::Settings(SettingsCommand::Set {
                key: "dns-servers".into(),
                value: servers.join(","),
            })))
        }
    }
}

fn clone_form(dialog: &Dialog) -> Result<Dialog> {
    let Dialog::Form { title, kind, fields, selected, error } = dialog else {
        bail!("selected dialog is not a form");
    };
    Ok(Dialog::Form {
        title,
        kind: *kind,
        fields: fields
            .iter()
            .map(|field| Field {
                label: field.label,
                value: field.value.clone(),
                optional: field.optional,
            })
            .collect(),
        selected: *selected,
        error: error.clone(),
    })
}

fn resolve_choice(kind: PickerKind, choice: &Choice, state: &State) -> Result<DialogResolution> {
    let command = match (kind, choice) {
        (PickerKind::Connect, Choice::Profile(order)) => Command::Connect { profile: Some(*order) },
        (PickerKind::ProfileShow, Choice::Profile(order)) => {
            Command::Profile(ProfileCommand::Show { order: *order })
        }
        (PickerKind::ProfileRemove, Choice::Profile(order)) => {
            Command::Profile(ProfileCommand::Remove { order: *order })
        }
        (PickerKind::ProfileEnable, Choice::Profile(order)) => {
            Command::Profile(ProfileCommand::Enable { order: *order })
        }
        (PickerKind::ProfileDisable, Choice::Profile(order)) => {
            Command::Profile(ProfileCommand::Disable { order: *order })
        }
        (PickerKind::ProfileDefault, Choice::Profile(order)) => {
            Command::Profile(ProfileCommand::Default { order: *order })
        }
        (PickerKind::ProfileExport, Choice::Profile(order)) => {
            return Ok(DialogResolution::Dialog(text_form(
                " EXPORT PROFILE ",
                FormKind::ProfileExport(*order),
                vec![("Destination", String::new(), false)],
            )));
        }
        (PickerKind::ProfileRename, Choice::Profile(order)) => {
            let current = state.profiles.values().nth(order - 1).map(|profile| profile.name.clone()).unwrap_or_default();
            return Ok(DialogResolution::Dialog(text_form(
                " RENAME PROFILE ",
                FormKind::ProfileRename(*order),
                vec![("Name", current, false)],
            )));
        }
        (PickerKind::SettingKey, Choice::Logging) => {
            return Ok(DialogResolution::Dialog(picker(
                " LOGGING ",
                PickerKind::Logging,
                vec![
                    ChoiceItem { label: "Enabled".into(), value: Choice::Boolean(true) },
                    ChoiceItem { label: "Disabled".into(), value: Choice::Boolean(false) },
                ],
                usize::from(!state.settings.logging),
            )));
        }
        (PickerKind::SettingKey, Choice::DnsServers) => {
            return Ok(DialogResolution::Dialog(Dialog::IpList {
                values: if state.settings.dns_servers.is_empty() { vec![String::new()] } else { state.settings.dns_servers.clone() },
                selected: 0,
                error: String::new(),
            }));
        }
        (PickerKind::Logging, Choice::Boolean(value)) => {
            Command::Settings(SettingsCommand::Set { key: "logging".into(), value: value.to_string() })
        }
        (PickerKind::SplitRemove, Choice::Route(value)) => Command::SplitTunnel(
            SplitTunnelCommand::Remove { kind: SplitKind::Route, value: value.clone() },
        ),
        (PickerKind::SplitMode, Choice::Mode(mode)) => {
            Command::SplitTunnel(SplitTunnelCommand::Mode { mode: mode.clone() })
        }
        _ => bail!("selected value does not belong to this action"),
    };
    Ok(DialogResolution::Command(command))
}

fn form_command(kind: FormKind, fields: &[Field]) -> Result<Command> {
    for field in fields {
        if !field.optional && field.value.trim().is_empty() {
            bail!("{} is required", field.label);
        }
    }
    let value = |index: usize| fields[index].value.trim();
    Ok(match kind {
        FormKind::ProfileImport => Command::Profile(ProfileCommand::Import {
            path: PathBuf::from(value(0)),
            name: (!value(1).is_empty()).then(|| value(1).to_owned()),
        }),
        FormKind::ProfileExport(order) => Command::Profile(ProfileCommand::Export {
            order,
            destination: PathBuf::from(value(0)),
        }),
        FormKind::ProfileRename(order) => Command::Profile(ProfileCommand::Rename {
            order,
            name: value(0).to_owned(),
        }),
        FormKind::SplitAdd => {
            let route = crate::core::routing::Network::parse(value(0))?.cidr();
            Command::SplitTunnel(SplitTunnelCommand::Add {
                kind: SplitKind::Route,
                value: route,
            })
        }
        FormKind::BackupCreate => Command::Backup(BackupCommand::Create {
            destination: PathBuf::from(value(0)),
        }),
        FormKind::BackupRestore => Command::Backup(BackupCommand::Restore {
            source: PathBuf::from(value(0)),
        }),
        FormKind::LogsExport => Command::Logs(LogsCommand::Export {
            destination: PathBuf::from(value(0)),
        }),
    })
}

fn validate_ip_rows(values: &[String]) -> Result<Vec<String>> {
    let values = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpAddr>()
                .with_context(|| format!("{value} is not a valid IP address"))
                .map(|address| address.to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    if values.is_empty() {
        bail!("at least one DNS server is required");
    }
    Ok(values)
}

fn open_selected_action(store: &Store, state: &mut State, ui: &mut UiState) {
    match action_dialog_or_command(ui.selected, state) {
        Ok(Some(DialogResolution::Dialog(dialog))) => ui.dialog = Some(dialog),
        Ok(Some(DialogResolution::Command(command))) => run_command(store, state, ui, command),
        Ok(None) => {}
        Err(error) => set_error(ui, "Action unavailable", &error),
    }
}

fn action_dialog_or_command(action: FeatureAction, state: &State) -> Result<Option<DialogResolution>> {
    let profile_picker = |title, kind| {
        profile_choices(state).map(|choices| DialogResolution::Dialog(picker(title, kind, choices, 0)))
    };
    let result = match action {
        FeatureAction::Status => DialogResolution::Command(Command::Status),
        FeatureAction::Connect => {
            let choices = state
                .profiles
                .values()
                .enumerate()
                .filter(|(_, profile)| profile.enabled)
                .map(|(index, profile)| ChoiceItem {
                    label: format!(
                        "{}. {}  [{}]",
                        index + 1,
                        sanitize_terminal(&profile.name),
                        profile.protocol
                    ),
                    value: Choice::Profile(index + 1),
                })
                .collect::<Vec<_>>();
            if choices.is_empty() {
                bail!("there are no enabled profiles to connect");
            }
            DialogResolution::Dialog(picker(" CONNECT ", PickerKind::Connect, choices, 0))
        }
        FeatureAction::Disconnect => DialogResolution::Command(Command::Disconnect),
        FeatureAction::Reconnect => DialogResolution::Command(Command::Reconnect),
        FeatureAction::ProfileList => DialogResolution::Command(Command::Profile(ProfileCommand::List)),
        FeatureAction::ProfileShow => return profile_picker(" SHOW PROFILE ", PickerKind::ProfileShow).map(Some),
        FeatureAction::ProfileImport => DialogResolution::Dialog(text_form(
            " IMPORT PROFILE ",
            FormKind::ProfileImport,
            vec![("Source path", String::new(), false), ("Name", String::new(), true)],
        )),
        FeatureAction::ProfileExport => return profile_picker(" EXPORT PROFILE ", PickerKind::ProfileExport).map(Some),
        FeatureAction::ProfileRemove => return profile_picker(" REMOVE PROFILE ", PickerKind::ProfileRemove).map(Some),
        FeatureAction::ProfileRename => return profile_picker(" RENAME PROFILE ", PickerKind::ProfileRename).map(Some),
        FeatureAction::ProfileEnable => return profile_picker(" ENABLE PROFILE ", PickerKind::ProfileEnable).map(Some),
        FeatureAction::ProfileDisable => return profile_picker(" DISABLE PROFILE ", PickerKind::ProfileDisable).map(Some),
        FeatureAction::ProfileDefault => return profile_picker(" DEFAULT PROFILE ", PickerKind::ProfileDefault).map(Some),
        FeatureAction::SettingsShow => DialogResolution::Command(Command::Settings(SettingsCommand::Show)),
        FeatureAction::SettingsSet => DialogResolution::Dialog(picker(
            " EDIT SETTING ",
            PickerKind::SettingKey,
            vec![
                ChoiceItem { label: "Connection logging".into(), value: Choice::Logging },
                ChoiceItem { label: "DNS servers".into(), value: Choice::DnsServers },
            ],
            0,
        )),
        FeatureAction::SettingsReset => DialogResolution::Command(Command::Settings(SettingsCommand::Reset)),
        FeatureAction::SplitList => DialogResolution::Command(Command::SplitTunnel(SplitTunnelCommand::List)),
        FeatureAction::SplitAdd => DialogResolution::Dialog(text_form(
            " ADD ROUTE ",
            FormKind::SplitAdd,
            vec![("Network", String::new(), false)],
        )),
        FeatureAction::SplitRemove => {
            if state.settings.split_routes.is_empty() {
                bail!("there are no split-tunnel routes to remove");
            }
            DialogResolution::Dialog(picker(
                " REMOVE ROUTE ",
                PickerKind::SplitRemove,
                state.settings.split_routes.iter().map(|route| ChoiceItem { label: route.clone(), value: Choice::Route(route.clone()) }).collect(),
                0,
            ))
        }
        FeatureAction::SplitClear => DialogResolution::Command(Command::SplitTunnel(SplitTunnelCommand::Clear { kind: SplitKind::Route })),
        FeatureAction::SplitMode => DialogResolution::Dialog(picker(
            " ROUTING MODE ",
            PickerKind::SplitMode,
            vec![
                ChoiceItem { label: "All traffic".into(), value: Choice::Mode(SplitMode::All) },
                ChoiceItem { label: "Only listed routes".into(), value: Choice::Mode(SplitMode::OnlyListed) },
                ChoiceItem { label: "All except listed routes".into(), value: Choice::Mode(SplitMode::ExceptListed) },
            ],
            match state.settings.route_mode {
                crate::core::model::RouteMode::All => 0,
                crate::core::model::RouteMode::OnlyListed => 1,
                crate::core::model::RouteMode::ExceptListed => 2,
            },
        )),
        FeatureAction::BackupCreate => DialogResolution::Dialog(text_form(
            " CREATE BACKUP ",
            FormKind::BackupCreate,
            vec![("Destination", String::new(), false)],
        )),
        FeatureAction::BackupRestore => DialogResolution::Dialog(text_form(
            " RESTORE BACKUP ",
            FormKind::BackupRestore,
            vec![("Source path", String::new(), false)],
        )),
        FeatureAction::LogsShow => DialogResolution::Command(Command::Logs(LogsCommand::Show)),
        FeatureAction::LogsExport => DialogResolution::Dialog(text_form(
            " EXPORT LOGS ",
            FormKind::LogsExport,
            vec![("Destination", String::new(), false)],
        )),
        FeatureAction::LogsClear => DialogResolution::Command(Command::Logs(LogsCommand::Clear)),
        FeatureAction::Doctor => DialogResolution::Command(Command::Doctor),
        FeatureAction::Install => DialogResolution::Command(Command::Install),
    };
    Ok(Some(result))
}

fn profile_choices(state: &State) -> Result<Vec<ChoiceItem>> {
    if state.profiles.is_empty() {
        bail!("there are no profiles to select");
    }
    Ok(state
        .profiles
        .values()
        .enumerate()
        .map(|(index, profile)| ChoiceItem {
            label: format!("{}. {}  [{}]", index + 1, sanitize_terminal(&profile.name), profile.protocol),
            value: Choice::Profile(index + 1),
        })
        .collect())
}

fn picker(
    title: &'static str,
    kind: PickerKind,
    choices: Vec<ChoiceItem>,
    selected: usize,
) -> Dialog {
    Dialog::Picker { title, kind, choices, selected, error: String::new() }
}

fn text_form(
    title: &'static str,
    kind: FormKind,
    fields: Vec<(&'static str, String, bool)>,
) -> Dialog {
    Dialog::Form {
        title,
        kind,
        fields: fields.into_iter().map(|(label, value, optional)| Field { label, value, optional }).collect(),
        selected: 0,
        error: String::new(),
    }
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

fn run_command(store: &Store, state: &mut State, ui: &mut UiState, command: Command) {
    match crate::core::execute(store, state, command, ui.dry_run) {
        Ok(output) => {
            ui.output = output;
            ui.output_scroll = 0;
            ui.message = "Action completed".into();
        }
        Err(error) => set_error(ui, "Action failed", &error),
    }
}

fn set_error(ui: &mut UiState, message: &str, error: &anyhow::Error) {
    ui.output = format!("Error\n\n{error:#}");
    ui.output_scroll = 0;
    ui.message = message.into();
}

fn render(frame: &mut ratatui::Frame<'_>, state: &State, ui: &UiState) {
    let theme = Theme::active();
    frame.render_widget(Block::default().style(Style::default().fg(theme.body).bg(theme.canvas)), frame.area());
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
    render_header(frame, state, ui, layout[0], theme);
    render_overview(frame, state, ui, layout[1], theme);
    render_workspace(frame, ui, layout[2], theme);
    render_action_hint(frame, ui, layout[3], theme);
    render_footer(frame, ui, layout[4], theme);
    if let Some(dialog) = &ui.dialog {
        render_dialog(frame, dialog, theme);
    }
}

fn render_header(frame: &mut ratatui::Frame<'_>, state: &State, ui: &UiState, area: Rect, theme: Theme) {
    let columns = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(65), Constraint::Percentage(35)]).split(area);
    let block = Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(theme.hairline).bg(theme.canvas));
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" AmneziaVPN", Style::default().fg(theme.ink).bg(theme.canvas).add_modifier(Modifier::BOLD)),
            Span::styled("  Linux VPN client", Style::default().fg(theme.muted)),
        ])).style(Style::default().bg(theme.canvas)).block(block.clone()),
        columns[0],
    );
    let connection = if state.connection.is_some() { "● Connected" } else { "○ Disconnected" };
    let mode = if ui.dry_run { "  ·  Preview" } else { "" };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(connection, Style::default().fg(theme.accent)),
            Span::styled(mode, Style::default().fg(theme.muted)),
            Span::raw(" "),
        ])).alignment(Alignment::Right).style(Style::default().bg(theme.canvas)).block(block),
        columns[1],
    );
}

fn render_overview(frame: &mut ratatui::Frame<'_>, state: &State, ui: &UiState, area: Rect, theme: Theme) {
    let active_profile = state.connection.as_ref().and_then(|connection| state.profiles.get(&connection.profile_id)).map(|profile| sanitize_terminal(&profile.name)).unwrap_or_else(|| "None".into());
    let overview = [
        ("CONNECTION", if state.connection.is_some() { "Connected".to_owned() } else { "Disconnected".to_owned() }),
        ("ACTIVE PROFILE", active_profile),
        ("PROFILES", state.profiles.len().to_string()),
        ("MODE", if ui.dry_run { "Preview".to_owned() } else { "Live".to_owned() }),
    ];
    let columns = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Ratio(1, 4); 4]).split(area);
    for ((label, value), column) in overview.into_iter().zip(columns.iter()) {
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(format!(" {label}"), Style::default().fg(theme.muted).bg(theme.elevated).add_modifier(Modifier::BOLD)),
                Line::styled(format!(" {value}"), Style::default().fg(theme.ink).bg(theme.elevated).add_modifier(Modifier::BOLD)),
            ]).block(theme.card("")),
            *column,
        );
    }
}

fn render_workspace(frame: &mut ratatui::Frame<'_>, ui: &UiState, area: Rect, theme: Theme) {
    let action_width = if area.width >= 100 { 34 } else { 28 };
    let columns = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Length(action_width), Constraint::Min(36)]).split(area);
    let mut previous_category = "";
    let actions = FeatureAction::iter().map(|action| {
        let info = action.info();
        let mut lines = Vec::new();
        if previous_category != info.category {
            previous_category = info.category;
            lines.push(Line::styled(format!(" {}", info.category.to_ascii_uppercase()), Style::default().fg(theme.muted).bg(theme.elevated).add_modifier(Modifier::BOLD)));
        }
        lines.push(Line::styled(format!("   {}", info.label), Style::default().fg(theme.body).bg(theme.elevated)));
        ListItem::new(lines)
    }).collect::<Vec<_>>();
    let selected = FeatureAction::iter().position(|action| action == ui.selected);
    let mut list_state = ListState::default().with_selected(selected);
    frame.render_stateful_widget(
        List::new(actions).style(Style::default().fg(theme.body).bg(theme.elevated)).block(theme.card(" ACTIONS ")).highlight_style(Style::default().bg(theme.accent_soft).fg(theme.ink).add_modifier(Modifier::BOLD)),
        columns[0],
        &mut list_state,
    );

    let info = ui.selected.info();
    let eyebrow = Style::default().fg(theme.muted).bg(theme.elevated).add_modifier(Modifier::BOLD);
    let mut lines = vec![
        Line::styled("SELECTED ACTION", eyebrow),
        Line::styled(info.label, Style::default().fg(theme.ink).bg(theme.elevated).add_modifier(Modifier::BOLD)),
        Line::default(),
        Line::styled("ACTIVITY", eyebrow),
        Line::default(),
    ];
    lines.extend(output_lines(&ui.output, theme));
    frame.render_widget(
        Paragraph::new(Text::from(lines)).scroll((ui.output_scroll, 0)).wrap(Wrap { trim: false }).block(theme.card(" DETAILS ")),
        columns[1],
    );
}

fn output_lines(output: &str, theme: Theme) -> Vec<Line<'static>> {
    let output = sanitize_terminal(output);
    if output.trim().is_empty() {
        return vec![Line::styled("Run an action to see its result here.", Style::default().fg(theme.muted).bg(theme.elevated))];
    }
    let values = json_hierarchy(&output).unwrap_or_else(|| output.lines().map(str::to_owned).collect());
    values.into_iter().enumerate().map(|(index, line)| {
        if index == 0 && line.eq_ignore_ascii_case("error") {
            Line::styled(line, Style::default().fg(theme.error).bg(theme.elevated).add_modifier(Modifier::BOLD))
        } else {
            let depth = line.chars().take_while(|character| character.is_whitespace()).count();
            let line = if depth == 0 || line.trim().is_empty() {
                line
            } else {
                format!("{}└─ {}", "  ".repeat(depth / 2), line.trim())
            };
            Line::styled(line, Style::default().fg(theme.body).bg(theme.elevated))
        }
    }).collect()
}

fn json_hierarchy(output: &str) -> Option<Vec<String>> {
    let value = serde_json::from_str::<serde_json::Value>(output.trim()).ok()?;
    let mut lines = Vec::new();
    render_json_value(&value, 0, None, &mut lines);
    Some(lines)
}

fn render_json_value(value: &serde_json::Value, depth: usize, key: Option<&str>, lines: &mut Vec<String>) {
    let indent = "  ".repeat(depth);
    match value {
        serde_json::Value::Object(values) => {
            if let Some(key) = key {
                lines.push(format!("{indent}{key}"));
            }
            let child_depth = depth + usize::from(key.is_some());
            for (key, value) in values {
                render_json_value(value, child_depth, Some(key), lines);
            }
        }
        serde_json::Value::Array(values) => {
            if let Some(key) = key {
                lines.push(format!("{indent}{key}"));
            }
            let child_depth = depth + usize::from(key.is_some());
            for value in values {
                render_json_value(value, child_depth, Some("item"), lines);
            }
        }
        _ => lines.push(format!("{indent}{}{}", key.map(|key| format!("{key}: ")).unwrap_or_default(), json_scalar(value))),
    }
}

fn json_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn render_action_hint(frame: &mut ratatui::Frame<'_>, ui: &UiState, area: Rect, theme: Theme) {
    let info = ui.selected.info();
    let hint = if action_needs_dialog(ui.selected) {
        format!("Press Enter to choose options for {}.", info.label.to_lowercase())
    } else {
        format!("Press Enter to run {}.", info.label.to_lowercase())
    };
    frame.render_widget(Paragraph::new(hint).style(Style::default().fg(theme.ink).bg(theme.elevated)).block(theme.card(" ACTION ")), area);
}

fn action_needs_dialog(action: FeatureAction) -> bool {
    matches!(action,
        FeatureAction::Connect
        | FeatureAction::ProfileShow
        | FeatureAction::ProfileImport
        | FeatureAction::ProfileExport
        | FeatureAction::ProfileRemove
        | FeatureAction::ProfileRename
        | FeatureAction::ProfileEnable
        | FeatureAction::ProfileDisable
        | FeatureAction::ProfileDefault
        | FeatureAction::SettingsSet
        | FeatureAction::SplitAdd
        | FeatureAction::SplitRemove
        | FeatureAction::SplitMode
        | FeatureAction::BackupCreate
        | FeatureAction::BackupRestore
        | FeatureAction::LogsExport
    )
}

fn render_footer(frame: &mut ratatui::Frame<'_>, ui: &UiState, area: Rect, theme: Theme) {
    let shortcuts = if area.width >= 120 {
        " ↑↓ Navigate   PgUp PgDn Scroll   P Preview   Enter Select   C Connect   D Disconnect   R Reload   Q Quit"
    } else {
        " ↑↓ Navigate   Enter Select   P Preview   Q Quit"
    };
    let columns = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(70), Constraint::Percentage(30)]).split(area);
    let block = Block::default().borders(Borders::TOP).border_style(Style::default().fg(theme.hairline).bg(theme.canvas));
    frame.render_widget(Paragraph::new(shortcuts).style(Style::default().fg(theme.muted).bg(theme.canvas)).block(block.clone()), columns[0]);
    frame.render_widget(Paragraph::new(sanitize_terminal(&ui.message)).alignment(Alignment::Right).style(Style::default().fg(theme.body).bg(theme.canvas)).block(block), columns[1]);
}

fn render_dialog(frame: &mut ratatui::Frame<'_>, dialog: &Dialog, theme: Theme) {
    let (title, height) = match dialog {
        Dialog::Picker { title, choices, .. } => (*title, (choices.len() as u16 + 5).clamp(8, 24)),
        Dialog::Form { title, fields, .. } => (*title, (fields.len() as u16 * 3 + 6).clamp(9, 22)),
        Dialog::IpList { values, .. } => (" DNS SERVERS ", (values.len() as u16 + 7).clamp(10, 24)),
    };
    let area = centered_rect(70, height, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(theme.card(title), area);
    let inner = Rect { x: area.x + 2, y: area.y + 2, width: area.width.saturating_sub(4), height: area.height.saturating_sub(4) };
    match dialog {
        Dialog::Picker { choices, selected, error, .. } => {
            let items = choices.iter().enumerate().map(|(index, choice)| {
                let marker = if index == *selected { "› " } else { "  " };
                ListItem::new(format!("{marker}{}", sanitize_terminal(&choice.label)))
            }).collect::<Vec<_>>();
            frame.render_widget(List::new(items).highlight_style(Style::default().fg(theme.ink).bg(theme.accent_soft)), inner);
            render_dialog_error(frame, area, error, theme);
        }
        Dialog::Form { fields, selected, error, .. } => {
            let value_width = inner.width.saturating_sub(3) as usize;
            let lines = fields.iter().enumerate().flat_map(|(index, field)| {
                let marker = if index == *selected { "›" } else { " " };
                let value = if index == *selected { format!("{}_", field.value) } else { field.value.clone() };
                let value = visible_tail(sanitize_terminal(&value), value_width);
                [
                    Line::styled(format!("{marker} {}{}", field.label, if field.optional { " (optional)" } else { "" }), Style::default().fg(if index == *selected { theme.accent } else { theme.muted })),
                    Line::styled(format!("  {value}"), Style::default().fg(theme.ink).bg(if index == *selected { theme.accent_soft } else { theme.elevated })),
                ]
            }).collect::<Vec<_>>();
            frame.render_widget(Paragraph::new(lines), inner);
            render_dialog_error(frame, area, error, theme);
        }
        Dialog::IpList { values, selected, error } => {
            let value_width = inner.width.saturating_sub(3) as usize;
            let mut lines = vec![Line::styled("One address per line", Style::default().fg(theme.muted))];
            lines.extend(values.iter().enumerate().map(|(index, value)| {
                let marker = if index == *selected { "›" } else { " " };
                let value = if index == *selected { format!("{value}_") } else { value.clone() };
                let value = visible_tail(sanitize_terminal(&value), value_width);
                Line::styled(format!("{marker} {value}"), Style::default().fg(theme.ink).bg(if index == *selected { theme.accent_soft } else { theme.elevated }))
            }));
            lines.push(Line::styled("Ins add  Del remove  Enter save  Esc cancel", Style::default().fg(theme.muted)));
            frame.render_widget(Paragraph::new(lines), inner);
            render_dialog_error(frame, area, error, theme);
        }
    }
}

fn visible_tail(mut value: String, width: usize) -> String {
    while Line::raw(value.as_str()).width() > width {
        if value.is_empty() {
            break;
        }
        value.remove(0);
    }
    value
}

fn render_dialog_error(frame: &mut ratatui::Frame<'_>, area: Rect, error: &str, theme: Theme) {
    if error.is_empty() || area.height < 4 {
        return;
    }
    let error_area = Rect { x: area.x + 2, y: area.bottom().saturating_sub(2), width: area.width.saturating_sub(4), height: 1 };
    frame.render_widget(Paragraph::new(sanitize_terminal(error)).style(Style::default().fg(theme.error).bg(theme.elevated)), error_area);
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let vertical_margin = area.height.saturating_sub(height) / 2;
    let rows = Layout::default().direction(Direction::Vertical).constraints([
        Constraint::Length(vertical_margin),
        Constraint::Length(height.min(area.height)),
        Constraint::Min(0),
    ]).split(area);
    let columns = Layout::default().direction(Direction::Horizontal).constraints([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ]).split(rows[1]);
    columns[1]
}

pub fn render_snapshot(state: &State, width: u16, height: u16) -> Result<String> {
    render_snapshot_with_ui(state, &UiState::default(), width, height)
}

fn render_snapshot_with_ui(state: &State, ui: &UiState, width: u16, height: u16) -> Result<String> {
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

    fn state_with_profiles() -> State {
        let mut state = State::default();
        state.profiles.insert("internal-a".into(), crate::core::model::Profile {
            id: "internal-a".into(), name: "KR 027".into(), protocol: crate::core::model::Protocol::Xray, source: "/private/profile.json".into(), enabled: true,
        });
        state.profiles.insert("internal-b".into(), crate::core::model::Profile {
            id: "internal-b".into(), name: "JP 005".into(), protocol: crate::core::model::Protocol::AmneziaWg, source: "/private/profile.conf".into(), enabled: true,
        });
        state
    }

    #[test]
    fn dashboard_exposes_all_feature_groups() {
        let snapshot = render_snapshot(&State::default(), 120, 60).unwrap();
        for text in ["AmneziaVPN", "CONNECTION", "PROFILES", "SETTINGS", "SPLIT TUNNEL"] {
            assert!(snapshot.contains(text));
        }
        assert!(!snapshot.contains("Connection / Status"));
    }

    #[test]
    fn dashboard_uses_configured_dark_colors() {
        use ratatui::backend::TestBackend;
        let theme = Theme::active();
        let brightness = |color| match color { Color::Rgb(red, green, blue) => u16::from(red) + u16::from(green) + u16::from(blue), _ => panic!("theme color is not RGB") };
        assert!(brightness(theme.canvas) < brightness(theme.ink));
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &State::default(), &UiState::default())).unwrap();
        let buffer = terminal.backend().buffer();
        for color in [theme.canvas, theme.elevated, theme.ink, theme.body, theme.accent, theme.hairline, theme.muted] {
            assert!(buffer.content().iter().any(|cell| cell.fg == color || cell.bg == color), "missing configured color {color:?}");
        }
    }

    #[test]
    fn profile_picker_uses_readable_numbered_rows_without_internal_identity() {
        let state = state_with_profiles();
        let dialog = match action_dialog_or_command(FeatureAction::ProfileShow, &state).unwrap().unwrap() {
            DialogResolution::Dialog(dialog) => dialog,
            DialogResolution::Command(_) => panic!("expected picker"),
        };
        let ui = UiState { selected: FeatureAction::ProfileShow, dialog: Some(dialog), ..UiState::default() };
        let snapshot = render_snapshot_with_ui(&state, &ui, 120, 36).unwrap();
        assert!(snapshot.contains("1. KR 027  [XRay]"));
        assert!(snapshot.contains("2. JP 005  [AmneziaWG]"));
        assert!(!snapshot.contains("internal-a"));
        println!("{snapshot}");
    }

    #[test]
    fn dns_setting_uses_validated_multi_line_editor() {
        let state = State::default();
        let setting_picker = action_dialog_or_command(FeatureAction::SettingsSet, &state).unwrap().unwrap();
        let DialogResolution::Dialog(Dialog::Picker { choices, .. }) = setting_picker else { panic!("expected setting picker") };
        let dns = resolve_choice(PickerKind::SettingKey, &choices[1].value, &state).unwrap();
        let DialogResolution::Dialog(Dialog::IpList { .. }) = dns else { panic!("expected DNS editor") };
        let values = vec!["9.9.9.9".into(), "2001:4860:4860::8888".into()];
        assert_eq!(validate_ip_rows(&values).unwrap(), values);
        assert!(validate_ip_rows(&["not-an-ip".into()]).is_err());
    }

    #[test]
    fn route_form_rejects_invalid_network_before_command_execution() {
        let fields = vec![Field { label: "Network", value: "invalid".into(), optional: false }];
        assert!(form_command(FormKind::SplitAdd, &fields).is_err());
        let fields = vec![Field { label: "Network", value: "10.4.3.2/8".into(), optional: false }];
        let command = form_command(FormKind::SplitAdd, &fields).unwrap();
        assert!(matches!(command, Command::SplitTunnel(SplitTunnelCommand::Add { value, .. }) if value == "10.0.0.0/8"));
    }

    #[test]
    fn raw_json_is_rendered_as_hierarchical_entries() {
        let lines = json_hierarchy(r#"{"network":{"dns":["1.1.1.1","1.0.0.1"]}}"#).unwrap();
        assert_eq!(lines, vec!["network", "  dns", "    item: 1.1.1.1", "    item: 1.0.0.1"]);
        let ui = UiState { output: r#"{"network":{"dns":["1.1.1.1"]}}"#.into(), ..UiState::default() };
        let snapshot = render_snapshot_with_ui(&State::default(), &ui, 120, 32).unwrap();
        assert!(snapshot.contains("network"));
        assert!(snapshot.contains("└─ dns"));
        assert!(!snapshot.contains("{\"network\""));
        println!("{snapshot}");
    }

    #[test]
    fn popup_keeps_unicode_value_cursor_visible() {
        let visible = visible_tail("/备份/配置/very-long-name.backup_".into(), 14);
        assert!(visible.ends_with("backup_"));
        assert!(Line::raw(visible).width() <= 14);
    }

    #[test]
    fn narrow_layout_keeps_popup_validation_visible() {
        let dialog = Dialog::IpList { values: vec!["not-an-ip".into()], selected: 0, error: "not-an-ip is not a valid IP address".into() };
        let ui = UiState { selected: FeatureAction::SettingsSet, dialog: Some(dialog), output: "Error\n\nThe selected backup could not be opened".into(), message: "Action failed".into(), ..UiState::default() };
        let snapshot = render_snapshot_with_ui(&State::default(), &ui, 80, 32).unwrap();
        assert!(snapshot.contains("DNS SERVERS"));
        assert!(snapshot.contains("not-an-ip is not a valid IP address"));
        assert!(snapshot.contains("Action failed"));
        println!("{snapshot}");
    }
}
