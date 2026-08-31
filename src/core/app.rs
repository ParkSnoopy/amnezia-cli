use std::{
    fmt::Write as _,
    fs,
};

use anyhow::{
    Context,
    Result,
    bail,
};

use crate::{
    core::{
        command::{
            BackupCommand,
            Command,
            LogsCommand,
            ProfileCommand,
            SettingsCommand,
            SplitKind,
            SplitMode,
            SplitTunnelCommand,
        },
        model::{
            self,
            RouteMode,
            State,
        },
        Connections,
        Operation,
        install,
        transaction,
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
    if dry_run
        && !matches!(
            &command,
            Command::Status
                | Command::Connect { .. }
                | Command::Disconnect
                | Command::Reconnect
        )
    {
        bail!("--dry-run is supported only for status and connection commands");
    }
    let mut output = String::new();
    match command {
        Command::Init => writeln!(output, "{}", install::install()?)?,
        Command::Status => {
            let recovery_error = Connections::new(store, state).status(!dry_run).err();
            print_status(state, &mut output)?;
            if let Some(error) = recovery_error {
                writeln!(output, "Recovery required: {error:#}")?;
            }
        }
        Command::Connect { profile } => {
            let profile = profile
                .map(|order| profile_id_by_order(state, order))
                .transpose()?;
            let mut connections = Connections::new(store, state);
            let result = if dry_run {
                connections.preview(Operation::Connect {
                    profile: profile.as_deref(),
                })?
            } else {
                connections.connect(profile.as_deref())?
            };
            writeln!(output, "{}", result)?;
        }
        Command::Disconnect => {
            let mut connections = Connections::new(store, state);
            let result = if dry_run {
                connections.preview(Operation::Disconnect)?
            } else {
                connections.disconnect()?
            };
            writeln!(output, "{}", result)?;
        }
        Command::Reconnect => {
            let result = Connections::new(store, state).reconnect(dry_run)?;
            writeln!(output, "{}", result)?;
        }
        Command::Profile(command) => profile_command(store, state, command, &mut output)?,
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
                if let Some((received, transmitted)) = interface_traffic(interface) {
                    writeln!(output, "received: {received}")?;
                    writeln!(output, "transmitted: {transmitted}")?;
                }
            }
        }
        None => writeln!(output, "disconnected")?,
    }
    writeln!(output, "profiles: {}", state.profiles.len())?;
    Ok(())
}

fn interface_traffic(interface: &str) -> Option<(u64, u64)> {
    if interface.is_empty()
        || !interface
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
    {
        return None;
    }
    let root = std::path::Path::new("/sys/class/net").join(interface).join("statistics");
    let received = fs::read_to_string(root.join("rx_bytes")).ok()?.trim().parse().ok()?;
    let transmitted = fs::read_to_string(root.join("tx_bytes")).ok()?.trim().parse().ok()?;
    Some((received, transmitted))
}

fn profile_command(
    store: &Store,
    state: &mut State,
    command: ProfileCommand,
    output: &mut String,
) -> Result<()> {
    match command {
        ProfileCommand::List => {
            for (index, profile) in state.profiles.values().enumerate() {
                let default = if state.default_profile.as_deref() == Some(&profile.id) {
                    "  default"
                } else {
                    ""
                };
                let disabled = if profile.enabled { "" } else { "  disabled" };
                writeln!(
                    output,
                    "{:>3}. {:<10}  {}{}{}",
                    index + 1,
                    profile.protocol.to_string(),
                    sanitize_terminal(&profile.name),
                    default,
                    disabled,
                )?;
            }
        }
        ProfileCommand::Show { order } => {
            let profile = profile_by_order(state, order)?;
            writeln!(
                output,
                "Profile {order}\n\nName      {}\nProtocol  {}\nEnabled   {}\nDefault   {}",
                sanitize_terminal(&profile.name),
                profile.protocol,
                if profile.enabled { "yes" } else { "no" },
                if state.default_profile.as_deref() == Some(&profile.id) {
                    "yes"
                } else {
                    "no"
                },
            )?;
        }
        ProfileCommand::Import { path, name } => {
            for id in store.import_profile(state, &path, name)? {
                let order = profile_order(state, &id).context("imported profile disappeared")?;
                let profile = profile_by_order(state, order)?;
                writeln!(
                    output,
                    "Imported profile {order}: {} [{}]",
                    sanitize_terminal(&profile.name),
                    profile.protocol,
                )?;
            }
        }
        ProfileCommand::Export { order, destination } => {
            let id = profile_id_by_order(state, order)?;
            store.export_profile(state, &id, &destination)?
        }
        ProfileCommand::Remove { order } => {
            let id = profile_id_by_order(state, order)?;
            store.remove_profile(state, &id)?
        }
        ProfileCommand::Rename { order, name } => {
            let id = profile_id_by_order(state, order)?;
            update_state(store, state, |updated| {
                profile_mut(updated, &id)?.name = name;
                Ok(())
            })?
        }
        ProfileCommand::Enable { order } => {
            let id = profile_id_by_order(state, order)?;
            update_state(store, state, |updated| {
                profile_mut(updated, &id)?.enabled = true;
                Ok(())
            })?
        }
        ProfileCommand::Disable { order } => {
            let id = profile_id_by_order(state, order)?;
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
            })?
        }
        ProfileCommand::Default { order } => {
            let id = profile_id_by_order(state, order)?;
            update_state(store, state, |updated| {
                profile(updated, &id)?;
                updated.default_profile = Some(id);
                Ok(())
            })?
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
            if state.connection.is_some() {
                bail!("disconnect VPN before resetting connection settings");
            }
            update_state(store, state, |updated| {
                updated.settings = Default::default();
                Ok(())
            })?
        }
        SettingsCommand::Set { key, value } => {
            if state.connection.is_some() {
                bail!("disconnect VPN before changing connection settings");
            }
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
        "dns-servers" => {
            let servers = value
                .split(',')
                .map(str::trim)
                .filter(|server| !server.is_empty())
                .map(|server| server.parse::<std::net::IpAddr>().map(|_| server.to_owned()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("dns-servers expects comma-separated IP addresses")?;
            if servers.is_empty() {
                bail!("dns-servers requires at least one IP address");
            }
            state.settings.dns_servers = servers;
        }
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
            *state = store.restore(state, &source)?;
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
    for (index, profile) in state.profiles.values().enumerate() {
        match transaction::check_profile_dependencies(store, profile, &state.settings) {
            Ok(()) => writeln!(
                output,
                "profile {} ({}): ok",
                index + 1,
                sanitize_terminal(&profile.name),
            )?,
            Err(error) => failures.push(format!(
                "profile {} ({}): {error:#}",
                index + 1,
                sanitize_terminal(&profile.name),
            )),
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

fn profile_id_by_order(state: &State, order: usize) -> Result<String> {
    if order == 0 {
        bail!("profile numbers start at 1");
    }
    state
        .profiles
        .keys()
        .nth(order - 1)
        .cloned()
        .with_context(|| format!("unknown profile number: {order}"))
}

fn profile_order(state: &State, id: &str) -> Option<usize> {
    state
        .profiles
        .keys()
        .position(|candidate| candidate == id)
        .map(|index| index + 1)
}

fn profile_by_order(state: &State, order: usize) -> Result<&model::Profile> {
    let id = profile_id_by_order(state, order)?;
    profile(state, &id)
}

fn profile<'a>(state: &'a State, id: &str) -> Result<&'a model::Profile> {
    state
        .profiles
        .get(id)
        .context("selected profile no longer exists")
}

fn profile_mut<'a>(state: &'a mut State, id: &str) -> Result<&'a mut model::Profile> {
    state
        .profiles
        .get_mut(id)
        .context("selected profile no longer exists")
}
