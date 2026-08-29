pub mod cli;
pub mod model;
pub mod runner;
pub mod server;
pub mod store;
pub mod tui;

use crate::cli::{BackupCommand, Cli, Command, LogsCommand, ProfileCommand, ServerCommand, SettingsCommand, SplitKind, SplitMode, SplitTunnelCommand};
use crate::model::{RouteMode, Server, State};
use crate::store::Store;
use anyhow::{Context, Result, bail};
use std::fs;
use uuid::Uuid;

pub fn sanitize_terminal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        } else {
            output.extend(character.escape_default());
        }
    }
    output
}

pub fn run(cli: Cli) -> Result<()> {
    let store = Store::discover(cli.data_dir)?;
    let mut state = store.load()?;
    let had_connection = state.connection.is_some();
    runner::refresh_connection(&mut state);
    if had_connection && state.connection.is_none() {
        store.save(&state)?;
    }
    if cli.tui {
        if cli.command.is_some() {
            bail!("--tui cannot be combined with a CLI command");
        }
        return tui::run(&store, &mut state);
    }
    let command = cli.command.context("no command specified; use --help")?;
    match command {
        Command::Status => print_status(&state),
        Command::Connect { profile } => {
            println!("{}", runner::connect(&store, &mut state, profile.as_deref(), cli.dry_run)?);
            Ok(())
        }
        Command::Disconnect => {
            println!("{}", runner::disconnect(&store, &mut state, cli.dry_run)?);
            Ok(())
        }
        Command::Profile(command) => profile_command(&store, &mut state, command),
        Command::Server(command) => server_command(&store, &mut state, command, cli.dry_run),
        Command::Settings(command) => settings_command(&store, &mut state, command),
        Command::SplitTunnel(command) => split_command(&store, &mut state, command),
        Command::Backup(command) => backup_command(&store, &mut state, command),
        Command::Logs(command) => logs_command(&store, command),
        Command::Doctor => doctor(&state),
    }
}

fn print_status(state: &State) -> Result<()> {
    match &state.connection {
        Some(connection) => {
            let name = state.profiles.get(&connection.profile_id).map(|profile| profile.name.as_str()).unwrap_or("unknown");
            println!("connected: {}", sanitize_terminal(name));
            if let Some(pid) = connection.pid { println!("pid: {pid}"); }
            if let Some(interface) = &connection.interface { println!("interface: {interface}"); }
        }
        None => println!("disconnected"),
    }
    println!("profiles: {}", state.profiles.len());
    println!("servers: {}", state.servers.len());
    Ok(())
}

fn profile_command(store: &Store, state: &mut State, command: ProfileCommand) -> Result<()> {
    match command {
        ProfileCommand::List => {
            for profile in state.profiles.values() {
                let default = if state.default_profile.as_deref() == Some(&profile.id) { " default" } else { "" };
                println!("{}\t{}\t{}{}", profile.id, profile.protocol, sanitize_terminal(&profile.name), default);
            }
        }
        ProfileCommand::Show { id } => println!("{}", serde_json::to_string_pretty(profile(state, &id)?)?),
        ProfileCommand::Import { path, name } => println!("{}", store.import_profile(state, &path, name)?),
        ProfileCommand::Export { id, destination } => store.export_profile(state, &id, &destination)?,
        ProfileCommand::Remove { id } => store.remove_profile(state, &id)?,
        ProfileCommand::Rename { id, name } => {
            profile_mut(state, &id)?.name = name;
            store.save(state)?;
        }
        ProfileCommand::Enable { id } => {
            profile_mut(state, &id)?.enabled = true;
            store.save(state)?;
        }
        ProfileCommand::Disable { id } => {
            if state.connection.as_ref().is_some_and(|connection| connection.profile_id == id) { bail!("profile is connected; disconnect first"); }
            profile_mut(state, &id)?.enabled = false;
            store.save(state)?;
        }
        ProfileCommand::Default { id } => {
            profile(state, &id)?;
            state.default_profile = Some(id);
            store.save(state)?;
        }
    }
    Ok(())
}

fn server_command(store: &Store, state: &mut State, command: ServerCommand, dry_run: bool) -> Result<()> {
    match command {
        ServerCommand::List => for server in state.servers.values() {
            let default = if state.default_server.as_deref() == Some(&server.id) { " default" } else { "" };
            println!("{}\t{}@{}:{}\t{}{}", server.id, sanitize_terminal(&server.user), sanitize_terminal(&server.host), server.port, sanitize_terminal(&server.name), default);
        },
        ServerCommand::Add(args) => {
            let id = Uuid::new_v4().simple().to_string();
            let server = Server {
                id: id.clone(),
                name: args.name.unwrap_or_else(|| args.host.clone()),
                host: args.host,
                port: args.port,
                user: args.user,
                identity_file: args.identity.map(|path| path.to_string_lossy().into_owned()),
                default_profile: None,
                installed_services: Vec::new(),
            };
            state.servers.insert(id.clone(), server);
            if state.default_server.is_none() { state.default_server = Some(id.clone()); }
            store.save(state)?;
            println!("{id}");
        }
        ServerCommand::Show { id } => println!("{}", serde_json::to_string_pretty(server_ref(state, &id)?)?),
        ServerCommand::Remove { id } => {
            state.servers.remove(&id).with_context(|| format!("unknown server: {id}"))?;
            if state.default_server.as_deref() == Some(&id) { state.default_server = state.servers.keys().next().cloned(); }
            store.save(state)?;
        }
        ServerCommand::Rename { id, name } => {
            state.servers.get_mut(&id).with_context(|| format!("unknown server: {id}"))?.name = name;
            store.save(state)?;
        }
        ServerCommand::Default { id } => {
            server_ref(state, &id)?;
            state.default_server = Some(id);
            store.save(state)?;
        }
        ServerCommand::Test { id } => println!("{}", sanitize_terminal(&server::run_ssh(server_ref(state, &id)?, &["true"], dry_run)?)),
        ServerCommand::Scan { id } => println!("{}", sanitize_terminal(&server::scan(server_ref(state, &id)?, dry_run)?)),
        ServerCommand::Reboot { id, yes } => println!("{}", sanitize_terminal(&server::reboot(server_ref(state, &id)?, yes, dry_run)?)),
    }
    Ok(())
}

fn settings_command(store: &Store, state: &mut State, command: SettingsCommand) -> Result<()> {
    match command {
        SettingsCommand::Show => println!("{}", serde_json::to_string_pretty(&state.settings)?),
        SettingsCommand::Reset => {
            state.settings = Default::default();
            store.save(state)?;
        }
        SettingsCommand::Set { key, value } => {
            set_setting(state, &key, &value)?;
            store.save(state)?;
        }
    }
    Ok(())
}

fn set_setting(state: &mut State, key: &str, value: &str) -> Result<()> {
    let boolean = || value.parse::<bool>().with_context(|| format!("{key} expects true or false"));
    match key {
        "primary-dns" => { value.parse::<std::net::IpAddr>().context("primary-dns expects an IP address")?; state.settings.primary_dns = value.into(); }
        "secondary-dns" => { value.parse::<std::net::IpAddr>().context("secondary-dns expects an IP address")?; state.settings.secondary_dns = value.into(); }
        "amnezia-dns" => state.settings.amnezia_dns = boolean()?,
        "kill-switch" => state.settings.kill_switch = boolean()?,
        "strict-kill-switch" => state.settings.strict_kill_switch = boolean()?,
        "auto-connect" => state.settings.auto_connect = boolean()?,
        "auto-start" => state.settings.auto_start = boolean()?,
        "start-minimized" => state.settings.start_minimized = boolean()?,
        "logging" => state.settings.logging = boolean()?,
        "notifications" => state.settings.notifications = boolean()?,
        "screenshots" => state.settings.screenshots = boolean()?,
        "language" => state.settings.language = value.into(),
        "gateway-endpoint" => state.settings.gateway_endpoint = nonempty(value),
        "subscription-key" => state.settings.subscription_key = nonempty(value),
        _ => bail!("unknown setting: {key}"),
    }
    Ok(())
}

fn split_command(store: &Store, state: &mut State, command: SplitTunnelCommand) -> Result<()> {
    match command {
        SplitTunnelCommand::List => {
            println!("mode: {:?}", state.settings.route_mode);
            for value in &state.settings.split_routes { println!("route\t{}", sanitize_terminal(value)); }
            for value in &state.settings.split_apps { println!("app\t{}", sanitize_terminal(value)); }
            for value in &state.settings.kill_switch_exceptions { println!("kill-switch-exception\t{}", sanitize_terminal(value)); }
        }
        SplitTunnelCommand::Add { kind, value } => add_unique(split_values_mut(state, kind), value),
        SplitTunnelCommand::Remove { kind, value } => split_values_mut(state, kind).retain(|entry| entry != &value),
        SplitTunnelCommand::Clear { kind } => split_values_mut(state, kind).clear(),
        SplitTunnelCommand::Mode { mode } => state.settings.route_mode = match mode {
            SplitMode::All => RouteMode::All,
            SplitMode::OnlyListed => RouteMode::OnlyListed,
            SplitMode::ExceptListed => RouteMode::ExceptListed,
        },
    }
    store.save(state)
}

fn split_values_mut(state: &mut State, kind: SplitKind) -> &mut Vec<String> {
    match kind {
        SplitKind::Route => &mut state.settings.split_routes,
        SplitKind::App => &mut state.settings.split_apps,
        SplitKind::KillSwitchException => &mut state.settings.kill_switch_exceptions,
    }
}

fn add_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) { values.push(value); }
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

fn logs_command(store: &Store, command: LogsCommand) -> Result<()> {
    let sources = log_paths(store)?;
    match command {
        LogsCommand::Show => {
            for source in &sources {
                let data = fs::read(source)?;
                print!("{}", sanitize_terminal(&String::from_utf8_lossy(&data)));
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
                && entry.file_name().to_str().is_some_and(|name| {
                    name.starts_with("connection-") && name.ends_with(".log")
                })
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn doctor(state: &State) -> Result<()> {
    let mut programs = Vec::new();
    if !state.servers.is_empty() {
        programs.push("ssh");
    }
    for profile in state.profiles.values() {
        let required: &[&str] = match profile.protocol {
            model::Protocol::WireGuard => &["wg", "wg-quick"],
            model::Protocol::AmneziaWg => &["awg", "awg-quick"],
            model::Protocol::OpenVpn
            | model::Protocol::Xray
            | model::Protocol::Shadowsocks
            | model::Protocol::Ikev2
            | model::Protocol::Amnezia => continue,
        };
        for program in required {
            if !programs.contains(program) { programs.push(program); }
        }
    }
    let mut missing = false;
    for program in programs {
        let present = runner::resolve_program(program).is_ok();
        println!("{program}: {}", if present { "ok" } else { missing = true; "missing" });
    }
    if missing { bail!("required programs are missing"); }
    Ok(())
}

fn profile<'a>(state: &'a State, id: &str) -> Result<&'a model::Profile> {
    state.profiles.get(id).with_context(|| format!("unknown profile: {id}"))
}

fn profile_mut<'a>(state: &'a mut State, id: &str) -> Result<&'a mut model::Profile> {
    state.profiles.get_mut(id).with_context(|| format!("unknown profile: {id}"))
}

fn server_ref<'a>(state: &'a State, id: &str) -> Result<&'a Server> {
    state.servers.get(id).with_context(|| format!("unknown server: {id}"))
}

fn nonempty(value: &str) -> Option<String> {
    if value.is_empty() { None } else { Some(value.into()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_text_escapes_control_sequences() {
        let input = format!("safe{}[31munsafe", char::from(27));
        assert_eq!(sanitize_terminal(&input), "safe\\u{1b}[31munsafe");
    }
}
