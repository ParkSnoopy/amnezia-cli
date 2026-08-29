use crate::core::model::{Connection, Profile, Protocol, Settings, State};
use crate::core::store::Store;
use anyhow::{Context, Result, bail};
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPlan {
    pub program: String,
    pub args: Vec<String>,
    pub long_running: bool,
    pub interface: Option<String>,
}

impl CommandPlan {
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(quote_argument)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn quote_argument(value: &str) -> String {
    if value.chars().all(|character| character.is_ascii_alphanumeric() || "-._/:=@".contains(character)) {
        value.to_owned()
    } else {
        format!("'{value}'", value = value.replace('\'', "'\\''"))
    }
}

pub fn connection_plan(profile: &Profile, _settings: &Settings) -> Result<CommandPlan> {
    let source = profile.source.clone();
    let plan = match profile.protocol {
        Protocol::OpenVpn => bail!("OpenVPN connection requires isolated bundled backend integration"),
        Protocol::WireGuard => CommandPlan {
            program: "wg-quick".into(),
            args: vec!["up".into(), source],
            long_running: false,
            interface: Some(interface_name(&profile.source)),
        },
        Protocol::AmneziaWg => CommandPlan {
            program: "awg-quick".into(),
            args: vec!["up".into(), source],
            long_running: false,
            interface: Some(interface_name(&profile.source)),
        },
        Protocol::Xray => bail!("XRay connection requires bundled XRay and tun2socks backend integration"),
        Protocol::Shadowsocks => bail!("Shadowsocks connection requires bundled tun2socks backend integration"),
        Protocol::Ikev2 => bail!("IKEv2 connection requires privileged platform backend integration"),
        Protocol::Amnezia => bail!("Amnezia full-access bundle must be exported to a native protocol before connection"),
    };

    Ok(plan)
}

pub fn connect(store: &Store, state: &mut State, profile_id: Option<&str>, dry_run: bool) -> Result<String> {
    refresh_connection(state);
    if state.connection.is_some() {
        bail!("VPN already connected");
    }
    let id = profile_id
        .map(str::to_owned)
        .or_else(|| state.default_profile.clone())
        .context("no profile selected")?;
    let profile = state.profiles.get(&id).with_context(|| format!("unknown profile: {id}"))?.clone();
    if !profile.enabled {
        bail!("profile is disabled");
    }
    if state.settings.kill_switch || state.settings.strict_kill_switch {
        bail!("kill switch is enabled but native firewall backend is unavailable; refusing unprotected connection");
    }
    let plan = connection_plan(&profile, &state.settings)?;
    if dry_run {
        return Ok(plan.display());
    }

    let executable = resolve_program(&plan.program)?;
    let mut command = Command::new(&executable);
    command.args(&plan.args).stdin(Stdio::null());
    if state.settings.logging {
        let log_path = store.root().join("logs").join(format!("connection-{}.log", uuid::Uuid::new_v4().simple()));
        let stdout = create_private_log(&log_path)?;
        let stderr = stdout.try_clone()?;
        command.stdout(stdout).stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let pid = if plan.long_running {
        let mut child = command.spawn().with_context(|| format!("start {}", plan.program))?;
        std::thread::sleep(std::time::Duration::from_millis(300));
        if let Some(status) = child.try_wait()? {
            bail!("{} exited during startup with {status}", plan.program);
        }
        Some(child.id())
    } else {
        let status = command.status().with_context(|| format!("run {}", plan.program))?;
        if !status.success() {
            bail!("{} exited with {status}", plan.program);
        }
        None
    };
    let connection = Connection {
        profile_id: id,
        pid,
        interface: plan.interface.clone(),
        started_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    state.connection = Some(connection.clone());
    if let Err(save_error) = store.save(state) {
        state.connection = None;
        let rollback = disconnect_plan(&profile, &connection)
            .and_then(|rollback_plan| {
                let executable = resolve_program(&rollback_plan.program)?;
                let status = Command::new(executable).args(&rollback_plan.args).status()?;
                if status.success() { Ok(()) } else { bail!("rollback exited with {status}") }
            });
        return match rollback {
            Ok(()) => Err(save_error).context("connection rolled back after state save failed"),
            Err(rollback_error) => Err(save_error).context(format!("state save failed and tunnel rollback failed: {rollback_error:#}")),
        };
    }
    Ok("connected".into())
}

pub fn disconnect(store: &Store, state: &mut State, dry_run: bool) -> Result<String> {
    let connection = state.connection.clone().context("VPN is not connected")?;
    let process_is_valid = {
        let profile = state.profiles.get(&connection.profile_id).context("connected profile is missing")?;
        connection.pid.is_none_or(|pid| process_belongs_to_profile(pid, profile))
    };
    if !process_is_valid {
        state.connection = None;
        store.save(state)?;
        bail!("recorded VPN process is no longer running");
    }
    let profile = state.profiles.get(&connection.profile_id).context("connected profile is missing")?;
    let plan = disconnect_plan(profile, &connection)?;
    if dry_run {
        return Ok(plan.display());
    }
    let executable = resolve_program(&plan.program)?;
    let status = Command::new(executable).args(&plan.args).status()?;
    if !status.success() {
        bail!("{} exited with {status}", plan.program);
    }
    state.connection = None;
    store.save(state)?;
    Ok("disconnected".into())
}

fn disconnect_plan(profile: &Profile, connection: &Connection) -> Result<CommandPlan> {
    match profile.protocol {
        Protocol::WireGuard => Ok(CommandPlan {
            program: "wg-quick".into(),
            args: vec!["down".into(), profile.source.clone()],
            long_running: false,
            interface: connection.interface.clone(),
        }),
        Protocol::AmneziaWg => Ok(CommandPlan {
            program: "awg-quick".into(),
            args: vec!["down".into(), profile.source.clone()],
            long_running: false,
            interface: connection.interface.clone(),
        }),
        _ => {
            let pid = connection.pid.context("connected process has no PID")?;
            Ok(CommandPlan {
                program: "kill".into(),
                args: vec!["-TERM".into(), pid.to_string()],
                long_running: false,
                interface: None,
            })
        }
    }
}

pub fn refresh_connection(state: &mut State) {
    let stale = state.connection.as_ref().is_some_and(|connection| {
        let Some(profile) = state.profiles.get(&connection.profile_id) else { return true };
        if let Some(pid) = connection.pid {
            return !process_belongs_to_profile(pid, profile);
        }
        let Some(interface) = connection.interface.as_deref() else { return true };
        let program = if profile.protocol == Protocol::AmneziaWg { "awg" } else { "wg" };
        match resolve_program(program)
            .and_then(|executable| Command::new(executable).args(["show", interface]).status().map_err(Into::into))
        {
            Ok(status) => !status.success(),
            Err(_) => true,
        }
    });
    if stale {
        state.connection = None;
    }
}

fn process_belongs_to_profile(pid: u32, profile: &Profile) -> bool {
    let Ok(command_line) = fs::read(format!("/proc/{pid}/cmdline")) else { return false };
    command_line
        .split(|byte| *byte == 0)
        .any(|argument| argument == profile.source.as_bytes())
}

fn interface_name(source: &str) -> String {
    Path::new(source)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("amnezia")
        .chars()
        .take(15)
        .collect()
}

fn create_private_log(path: &Path) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

pub fn resolve_program(program: &str) -> Result<std::path::PathBuf> {
    let mut directories = Vec::new();
    if let Some(path) = std::env::var_os("AMN_LIBEXEC") {
        directories.push(std::path::PathBuf::from(path));
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        directories.push(directory.join("libexec").join("amn"));
        directories.push(directory.join("..").join("libexec").join("amn"));
    }
    if let Some(path) = std::env::var_os("PATH") {
        directories.extend(std::env::split_paths(&path));
    }
    directories
        .into_iter()
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .with_context(|| format!("required program not found: {program}; install bundle helper or add it to PATH"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(protocol: Protocol) -> Profile {
        Profile { id: "p".into(), name: "test".into(), protocol, source: "/vpn/test.conf".into(), enabled: true, server_id: None }
    }

    #[test]
    fn openvpn_never_runs_untrusted_profile_language() {
        assert!(connection_plan(&profile(Protocol::OpenVpn), &Settings::default()).is_err());
    }

    #[test]
    fn full_bundle_never_claims_native_connection() {
        assert!(connection_plan(&profile(Protocol::Amnezia), &Settings::default()).is_err());
    }
}
