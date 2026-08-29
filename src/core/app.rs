use std::{
    fmt::Write as _,
    fs,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use uuid::Uuid;

use crate::{
    core::{
        command::{
            BackupCommand,
            Command,
            LogsCommand,
            ProfileCommand,
            ServerCommand,
            SettingsCommand,
            SplitKind,
            SplitMode,
            SplitTunnelCommand,
        },
        model::{
            self,
            RouteMode,
            Server,
            State,
        },
        runner,
        server,
        store,
        store::Store,
    },
    sanitize_terminal,
};

pub fn execute(
    store: &Store,
    state: &mut State,
    command: Command,
    dry_run: bool,
) -> Result<String> {
    let mut output = String::new();
    match command {
        Command::Status => print_status(state, &mut output)?,
        Command::Connect { profile } => {
            writeln!(
                output,
                "{}",
                runner::connect(store, state, profile.as_deref(), dry_run)?
            )?;
        }
        Command::Disconnect => {
            writeln!(output, "{}", runner::disconnect(store, state, dry_run)?)?;
        }
        Command::Profile(command) => profile_command(store, state, command, &mut output)?,
        Command::Server(command) => server_command(store, state, command, dry_run, &mut output)?,
        Command::Settings(command) => settings_command(store, state, command, &mut output)?,
        Command::SplitTunnel(command) => split_command(store, state, command, &mut output)?,
        Command::Backup(command) => backup_command(store, state, command)?,
        Command::Logs(command) => logs_command(store, command, &mut output)?,
        Command::Doctor => doctor(store, state, &mut output)?,
    }
    Ok(output)
}

fn print_status(state: &State, output: &mut String) -> Result<()> {
    match &state.connection {
        Some(connection) => {
            let name = state
                .profiles
                .get(&connection.profile_id)
                .map(|profile| profile.name.as_str())
                .unwrap_or("unknown");
            writeln!(output, "connected: {}", sanitize_terminal(name))?;
            if let Some(pid) = connection.pid {
                writeln!(output, "pid: {pid}")?;
            }
            if let Some(interface) = &connection.interface {
                writeln!(output, "interface: {interface}")?;
            }
        }
        None => writeln!(output, "disconnected")?,
    }
    writeln!(output, "profiles: {}", state.profiles.len())?;
    writeln!(output, "servers: {}", state.servers.len())?;
    Ok(())
}

fn profile_command(
    store: &Store,
    state: &mut State,
    command: ProfileCommand,
    output: &mut String,
) -> Result<()> {
    match command {
        ProfileCommand::List => {
            for profile in state.profiles.values() {
                let default = if state.default_profile.as_deref() == Some(&profile.id) {
                    " default"
                } else {
                    ""
                };
                writeln!(
                    output,
                    "{}\t{}\t{}{}",
                    profile.id,
                    profile.protocol,
                    sanitize_terminal(&profile.name),
                    default
                )?;
            }
        }
        ProfileCommand::Show { id } => {
            writeln!(
                output,
                "{}",
                serde_json::to_string_pretty(profile(state, &id)?)?
            )?
        }
        ProfileCommand::Import { path, name } => {
            for id in store.import_profile(state, &path, name)? {
                writeln!(output, "{id}")?;
            }
        }
        ProfileCommand::Export { id, destination } => {
            store.export_profile(state, &id, &destination)?
        }
        ProfileCommand::Remove { id } => store.remove_profile(state, &id)?,
        ProfileCommand::Rename { id, name } => {
            update_state(store, state, |updated| {
                profile_mut(updated, &id)?.name = name;
                Ok(())
            })?
        }
        ProfileCommand::Enable { id } => {
            update_state(store, state, |updated| {
                profile_mut(updated, &id)?.enabled = true;
                Ok(())
            })?
        }
        ProfileCommand::Disable { id } => {
            if state
                .connection
                .as_ref()
                .is_some_and(|connection| connection.profile_id == id)
            {
                bail!("profile is connected; disconnect first");
            }
            update_state(store, state, |updated| {
                profile_mut(updated, &id)?.enabled = false;
                Ok(())
            })?;
        }
        ProfileCommand::Default { id } => {
            update_state(store, state, |updated| {
                profile(updated, &id)?;
                updated.default_profile = Some(id);
                Ok(())
            })?
        }
    }
    Ok(())
}

fn server_command(
    store: &Store,
    state: &mut State,
    command: ServerCommand,
    dry_run: bool,
    output: &mut String,
) -> Result<()> {
    match command {
        ServerCommand::List => {
            for server in state.servers.values() {
                let default = if state.default_server.as_deref() == Some(&server.id) {
                    " default"
                } else {
                    ""
                };
                writeln!(
                    output,
                    "{}\t{}@{}:{}\t{}{}",
                    server.id,
                    sanitize_terminal(&server.user),
                    sanitize_terminal(&server.host),
                    server.port,
                    sanitize_terminal(&server.name),
                    default
                )?;
            }
        }
        ServerCommand::Add(args) => {
            let id = Uuid::new_v4().simple().to_string();
            let server = Server {
                id: id.clone(),
                name: args.name.unwrap_or_else(|| args.host.clone()),
                host: args.host,
                port: args.port,
                user: args.user,
                identity_file: args
                    .identity
                    .map(|path| path.to_string_lossy().into_owned()),
            };
            update_state(store, state, |updated| {
                updated.servers.insert(id.clone(), server);
                if updated.default_server.is_none() {
                    updated.default_server = Some(id.clone());
                }
                Ok(())
            })?;
            writeln!(output, "{id}")?;
        }
        ServerCommand::Show { id } => {
            writeln!(
                output,
                "{}",
                serde_json::to_string_pretty(server_ref(state, &id)?)?
            )?
        }
        ServerCommand::Remove { id } => {
            update_state(store, state, |updated| {
                updated
                    .servers
                    .remove(&id)
                    .with_context(|| format!("unknown server: {id}"))?;
                if updated.default_server.as_deref() == Some(&id) {
                    updated.default_server = updated.servers.keys().next().cloned();
                }
                Ok(())
            })?;
        }
        ServerCommand::Rename { id, name } => {
            update_state(store, state, |updated| {
                updated
                    .servers
                    .get_mut(&id)
                    .with_context(|| format!("unknown server: {id}"))?
                    .name = name;
                Ok(())
            })?
        }
        ServerCommand::Default { id } => {
            update_state(store, state, |updated| {
                server_ref(updated, &id)?;
                updated.default_server = Some(id);
                Ok(())
            })?
        }
        ServerCommand::Test { id } => {
            writeln!(
                output,
                "{}",
                sanitize_terminal(&server::run_ssh(
                    server_ref(state, &id)?,
                    &["true"],
                    dry_run
                )?)
            )?
        }
        ServerCommand::Scan { id } => {
            writeln!(
                output,
                "{}",
                sanitize_terminal(&server::scan(server_ref(state, &id)?, dry_run)?)
            )?
        }
        ServerCommand::Reboot { id, yes } => {
            writeln!(
                output,
                "{}",
                sanitize_terminal(&server::reboot(server_ref(state, &id)?, yes, dry_run)?)
            )?
        }
    }
    Ok(())
}

fn settings_command(
    store: &Store,
    state: &mut State,
    command: SettingsCommand,
    output: &mut String,
) -> Result<()> {
    match command {
        SettingsCommand::Show => {
            writeln!(output, "{}", serde_json::to_string_pretty(&state.settings)?)?
        }
        SettingsCommand::Reset => {
            update_state(store, state, |updated| {
                updated.settings = Default::default();
                Ok(())
            })?
        }
        SettingsCommand::Set { key, value } => {
            update_state(store, state, |updated| set_setting(updated, &key, &value))?
        }
    }
    Ok(())
}

fn set_setting(state: &mut State, key: &str, value: &str) -> Result<()> {
    let boolean = || {
        value
            .parse::<bool>()
            .with_context(|| format!("{key} expects true or false"))
    };
    match key {
        "logging" => state.settings.logging = boolean()?,
        _ => bail!("unknown setting: {key}"),
    }
    Ok(())
}

fn split_command(
    store: &Store,
    state: &mut State,
    command: SplitTunnelCommand,
    output: &mut String,
) -> Result<()> {
    if matches!(&command, SplitTunnelCommand::List) {
        writeln!(output, "mode: {:?}", state.settings.route_mode)?;
        for value in &state.settings.split_routes {
            writeln!(output, "route\t{}", sanitize_terminal(value))?;
        }
        return Ok(());
    }
    if state.connection.is_some() {
        bail!("disconnect VPN before changing split-tunnel routing");
    }
    update_state(store, state, |updated| {
        match command {
            SplitTunnelCommand::List => unreachable!("list returned before mutation"),
            SplitTunnelCommand::Add { kind, value } => {
                let value = crate::core::routing::Network::parse(&value)?.cidr();
                add_unique(split_values_mut(updated, kind), value);
            }
            SplitTunnelCommand::Remove { kind, value } => {
                let value = crate::core::routing::Network::parse(&value)?.cidr();
                split_values_mut(updated, kind).retain(|entry| entry != &value);
            }
            SplitTunnelCommand::Clear { kind } => split_values_mut(updated, kind).clear(),
            SplitTunnelCommand::Mode { mode } => {
                updated.settings.route_mode = match mode {
                    SplitMode::All => RouteMode::All,
                    SplitMode::OnlyListed => RouteMode::OnlyListed,
                    SplitMode::ExceptListed => RouteMode::ExceptListed,
                }
            }
        }
        Ok(())
    })
}

fn split_values_mut(state: &mut State, kind: SplitKind) -> &mut Vec<String> {
    match kind {
        SplitKind::Route => &mut state.settings.split_routes,
    }
}

fn add_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn backup_command(store: &Store, state: &mut State, command: BackupCommand) -> Result<()> {
    match command {
        BackupCommand::Create { destination } => store.backup(state, &destination),
        BackupCommand::Restore { source } => {
            if state.connection.is_some() {
                bail!("disconnect VPN before restoring a backup");
            }
            *state = store.restore(&source)?;
            Ok(())
        }
    }
}

fn logs_command(store: &Store, command: LogsCommand, output: &mut String) -> Result<()> {
    let sources = log_paths(store)?;
    match command {
        LogsCommand::Show => {
            for source in &sources {
                let data = fs::read(source)?;
                write!(
                    output,
                    "{}",
                    sanitize_terminal(&String::from_utf8_lossy(&data))
                )?;
            }
        }
        LogsCommand::Export { destination } => {
            let mut data = Vec::new();
            for source in &sources {
                data.extend(fs::read(source)?);
            }
            store::write_private(&destination, &data)?;
        }
        LogsCommand::Clear => {
            for source in sources {
                fs::remove_file(source)?;
            }
        }
    }
    Ok(())
}

fn log_paths(store: &Store) -> Result<Vec<std::path::PathBuf>> {
    let mut paths = fs::read_dir(store.root().join("logs"))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.file_type().is_ok_and(|file_type| file_type.is_file())
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("connection-") && name.ends_with(".log"))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn doctor(store: &Store, state: &State, output: &mut String) -> Result<()> {
    let mut failures = Vec::new();
    for saved_server in state.servers.values() {
        match server::check_dependencies(saved_server) {
            Ok(_) => writeln!(output, "server {}: ok", saved_server.id)?,
            Err(error) => failures.push(format!("server {}: {error:#}", saved_server.id)),
        }
    }
    for profile in state.profiles.values() {
        match profile.protocol {
            model::Protocol::OpenVpn
            | model::Protocol::WireGuard
            | model::Protocol::AmneziaWg
            | model::Protocol::Xray
            | model::Protocol::Shadowsocks
            | model::Protocol::Ikev2 => {
                match runner::check_profile_dependencies(store, profile, &state.settings) {
                    Ok(()) => writeln!(output, "profile {}: ok", profile.id)?,
                    Err(error) => failures.push(format!("profile {}: {error:#}", profile.id)),
                }
            }
        }
    }
    if !failures.is_empty() {
        bail!(
            "required command-line or system dependencies are missing:\n{}",
            sanitize_terminal(&failures.join("\n"))
        );
    }
    Ok(())
}

fn update_state(
    update_store: &Store,
    state: &mut State,
    update: impl FnOnce(&mut State) -> Result<()>,
) -> Result<()> {
    let mut updated = state.clone();
    update(&mut updated)?;
    update_store.save(&updated)?;
    *state = updated;
    Ok(())
}

fn profile<'a>(state: &'a State, id: &str) -> Result<&'a model::Profile> {
    state
        .profiles
        .get(id)
        .with_context(|| format!("unknown profile: {id}"))
}

fn profile_mut<'a>(state: &'a mut State, id: &str) -> Result<&'a mut model::Profile> {
    state
        .profiles
        .get_mut(id)
        .with_context(|| format!("unknown profile: {id}"))
}

fn server_ref<'a>(state: &'a State, id: &str) -> Result<&'a Server> {
    state
        .servers
        .get(id)
        .with_context(|| format!("unknown server: {id}"))
}
