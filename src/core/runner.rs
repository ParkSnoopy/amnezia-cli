use std::{
    fs::{
        self,
        OpenOptions,
    },
    io::{
        BufRead,
        BufReader,
        Write as _,
    },
    net::{
        TcpListener,
        TcpStream,
    },
    os::unix::ffi::OsStringExt,
    path::{
        Path,
        PathBuf,
    },
    process::{
        Command,
        Stdio,
    },
};

use anyhow::{
    Context,
    Result,
    anyhow,
    bail,
};

use crate::core::{
    model::{
        Connection,
        Ikev2RouteIdentity,
        Profile,
        Protocol,
        Settings,
        State,
    },
    store::Store,
};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPlan {
    pub program: String,
    pub args: Vec<String>,
    pub rollback_program: String,
    pub rollback_args: Vec<String>,
    pub interface: Option<String>,
}

pub(crate) struct QuickSpec {
    pub quick_program: &'static str,
    pub probe_program: &'static str,
    pub kernel_module: &'static str,
    pub backend_variable: &'static str,
    pub userspace_backend: &'static str,
}

fn quick_spec(protocol: &Protocol) -> Result<QuickSpec> {
    match protocol {
        Protocol::WireGuard => Ok(crate::core::wireguard::spec()),
        Protocol::AmneziaWg => Ok(crate::core::amneziawg::spec()),
        _ => bail!("protocol does not use a quick-script backend"),
    }
}

impl CommandPlan {
    pub fn display(&self) -> String {
        format!(
            "{}\nrollback: {}",
            format_command(&self.program, &self.args),
            format_command(&self.rollback_program, &self.rollback_args)
        )
    }
}

fn format_command(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(quote_argument)
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_argument(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._/:=@".contains(character))
    {
        value.to_owned()
    } else {
        format!("'{value}'", value = value.replace('\'', "'\\''"))
    }
}

fn quick_connection_plan(profile: &Profile) -> Result<CommandPlan> {
    let source = profile.source.clone();
    let plan = match profile.protocol {
        Protocol::WireGuard | Protocol::AmneziaWg => {
            let spec = quick_spec(&profile.protocol)?;
            CommandPlan {
                program: spec.quick_program.into(),
                args: vec!["up".into(), source],
                rollback_program: spec.quick_program.into(),
                rollback_args: vec!["down".into(), profile.source.clone()],
                interface: Some(interface_name(&profile.source)),
            }
        }
        _ => bail!("protocol does not use a quick-script backend"),
    };

    Ok(plan)
}

struct PreparedPlan {
    program: PathBuf,
    rollback_program: PathBuf,
    args: Vec<String>,
    rollback_args: Vec<String>,
    path: std::ffi::OsString,
    interface_probe: PathBuf,
    interface: String,
    interface_existed: bool,
    expected_peer_keys: Vec<String>,
    runtime_directory: Option<PathBuf>,
    quick_base_created: bool,
    backend_environment: Option<(String, PathBuf)>,
}

impl Drop for PreparedPlan {
    fn drop(&mut self) {
        if let Some(directory) = &self.runtime_directory {
            let _ = fs::remove_dir_all(directory);
        }
        if self.quick_base_created {
            let _ = fs::remove_dir(Path::new("/etc/wireguard"));
        }
    }
}

fn prepare_network_plan(
    store: &Store,
    profile: &Profile,
    plan: &CommandPlan,
    stage_profile: bool,
) -> Result<PreparedPlan> {
    let configuration = store.validated_profile_text(profile)?;
    let program = resolve_network_program(&plan.program)?;
    let rollback_program = resolve_network_program(&plan.rollback_program)?;

    for dependency in ["bash", "ip", "readlink", "grep", "sed", "sort", "stat"] {
        resolve_network_program(dependency)?;
    }

    if configuration_has_key(&configuration, "SaveConfig") {
        for dependency in ["sync", "mv", "rm"] {
            resolve_network_program(dependency)?;
        }
    }
    let spec = quick_spec(&profile.protocol)?;
    let interface_probe = resolve_network_program(spec.probe_program)?;
    let kernel_backend = Some((
        spec.kernel_module,
        spec.backend_variable,
        spec.userspace_backend,
    ));
    if configuration_has_key(&configuration, "DNS") {
        resolve_network_program("resolvconf")?;
    }
    if configuration_has_default_route(&configuration) {
        resolve_network_program("sysctl")?;
        let nft_available = resolve_network_program("nft").is_ok();
        let iptables_available = resolve_network_program("iptables").is_ok();
        if iptables_available {
            for dependency in [
                "ip6tables",
                "iptables-save",
                "ip6tables-save",
                "iptables-restore",
                "ip6tables-restore",
            ] {
                resolve_network_program(dependency)?;
            }
        }
        if !nft_available && !iptables_available {
            bail!("default-route profile requires nft or iptables firewall tools");
        }
    }
    let path =
        std::env::join_paths(network_program_directories()).context("construct dependency PATH")?;

    let backend_environment = kernel_backend
        .map(|(module, fallback_variable, default_fallback)| {
            require_kernel_backend(module, fallback_variable, default_fallback, &path)
        })
        .transpose()?
        .flatten();
    let interface = plan
        .interface
        .clone()
        .context("network plan has no interface")?;
    let interface_existed = interface_exists(&interface_probe, &interface, &path)?;
    let peer_keys = configuration_values(&configuration, "PublicKey");
    if peer_keys.is_empty() {
        bail!("VPN profile has no peer public key");
    }
    if plan.args.first().is_some_and(|action| action == "down")
        && interface_existed
        && !interface_matches_profile(&interface_probe, &interface, &peer_keys, &path)?
    {
        bail!("refusing to modify interface not owned by selected profile: {interface}");
    }
    let (args, rollback_args, runtime_directory, quick_base_created) = if stage_profile {
        if effective_user_id() != Some(0) {
            bail!("VPN interface changes require running amn as root");
        }
        let (directory, quick_base_created) = create_quick_runtime_directory()?;
        let file_name = Path::new(&profile.source)
            .file_name()
            .context("profile source has no filename")?;
        let staged = directory.join(file_name);
        if let Err(error) = crate::core::store::write_private(&staged, configuration.as_bytes()) {
            let _ = fs::remove_dir_all(&directory);
            if quick_base_created {
                let _ = fs::remove_dir(Path::new("/etc/wireguard"));
            }
            return Err(error).context("stage validated VPN profile");
        }
        let staged = staged.to_string_lossy().into_owned();
        (
            replace_profile_argument(&plan.args, &profile.source, &staged),
            replace_profile_argument(&plan.rollback_args, &profile.source, &staged),
            Some(directory),
            quick_base_created,
        )
    } else {
        (plan.args.clone(), plan.rollback_args.clone(), None, false)
    };

    Ok(PreparedPlan {
        program,
        rollback_program,
        args,
        rollback_args,
        path,
        interface_probe,
        interface,
        interface_existed,
        expected_peer_keys: peer_keys,
        runtime_directory,
        quick_base_created,
        backend_environment,
    })
}

pub fn check_profile_dependencies(
    store: &Store,
    profile: &Profile,
    settings: &Settings,
) -> Result<()> {
    if profile.protocol == Protocol::Ikev2 {
        prepare_ikev2(store, profile, settings, None)?;
        return Ok(());
    }
    if profile.protocol == Protocol::OpenVpn {
        prepare_openvpn(store, profile, settings)?;
        return Ok(());
    }
    if matches!(profile.protocol, Protocol::Xray | Protocol::Shadowsocks) {
        prepare_xray(store, profile, settings)?;
        return Ok(());
    }
    let plan = quick_connection_plan(profile)?;
    prepare_network_plan(store, profile, &plan, false)?;
    Ok(())
}

fn configuration_has_key(configuration: &str, expected: &str) -> bool {
    configuration
        .lines()
        .filter_map(|line| line.split_once('='))
        .any(|(key, value)| {
            key.trim().eq_ignore_ascii_case(expected) && !configuration_value(value).is_empty()
        })
}

fn configuration_values(configuration: &str, expected: &str) -> Vec<String> {
    configuration
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let value = configuration_value(value);
            (key.trim().eq_ignore_ascii_case(expected) && !value.is_empty())
                .then(|| value.to_owned())
        })
        .collect()
}

fn configuration_has_default_route(configuration: &str) -> bool {
    configuration
        .lines()
        .filter_map(|line| line.split_once('='))
        .any(|(key, value)| {
            key.trim().eq_ignore_ascii_case("AllowedIPs")
                && configuration_value(value).split(',').any(is_default_route)
        })
}

fn configuration_value(value: &str) -> &str {
    value.split('#').next().unwrap_or_default().trim()
}

fn is_default_route(route: &str) -> bool {
    let Some((address, prefix)) = route.trim().split_once('/') else {
        return false;
    };
    prefix.trim() == "0"
        && address
            .trim()
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_unspecified())
}

fn require_kernel_backend(
    module: &str,
    fallback_variable: &str,
    default_fallback: &str,
    path: &std::ffi::OsStr,
) -> Result<Option<(String, PathBuf)>> {
    if Path::new("/sys/module").join(module).is_dir() {
        return Ok(None);
    }
    let fallback = std::env::var(fallback_variable).unwrap_or_else(|_| default_fallback.to_owned());
    if let Ok(executable) = resolve_network_program(&fallback) {
        return Ok(Some((fallback_variable.to_owned(), executable)));
    }
    let modprobe = resolve_network_program("modprobe")?;
    let status = Command::new(modprobe)
        .args(["--dry-run", "--quiet", module])
        .env("PATH", path)
        .status()
        .with_context(|| format!("check kernel module {module}"))?;
    if !status.success() {
        bail!("required kernel module is unavailable: {module}");
    }
    Ok(None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollbackStrategy {
    None,
    Opposite,
    NormalizeThenOpposite,
}

fn rollback(plan: &CommandPlan, prepared: &PreparedPlan) -> Result<()> {
    let interface_exists_now = interface_exists(
        &prepared.interface_probe,
        &prepared.interface,
        &prepared.path,
    )?;
    let strategy = rollback_strategy(prepared.interface_existed, interface_exists_now);
    if strategy == RollbackStrategy::None {
        return Ok(());
    }
    if interface_exists_now
        && !interface_matches_profile(
            &prepared.interface_probe,
            &prepared.interface,
            &prepared.expected_peer_keys,
            &prepared.path,
        )?
    {
        bail!(
            "refusing rollback because interface ownership is ambiguous: {}",
            prepared.interface
        );
    }
    if strategy == RollbackStrategy::NormalizeThenOpposite {
        let status = network_command(&prepared.program, &prepared.args, prepared)
            .status()
            .with_context(|| format!("normalize failed {} before rollback", plan.program))?;
        if !status.success() {
            bail!(
                "rollback normalization {} exited with {status}",
                plan.program
            );
        }
    }
    let status = network_command(
        &prepared.rollback_program,
        &prepared.rollback_args,
        prepared,
    )
    .status()
    .with_context(|| format!("run rollback {}", plan.rollback_program))?;
    if !status.success() {
        bail!("rollback {} exited with {status}", plan.rollback_program);
    }
    Ok(())
}

fn rollback_strategy(
    interface_existed_before: bool,
    interface_exists_now: bool,
) -> RollbackStrategy {
    match (interface_existed_before, interface_exists_now) {
        (false, false) => RollbackStrategy::None,
        (true, true) => RollbackStrategy::NormalizeThenOpposite,
        _ => RollbackStrategy::Opposite,
    }
}

fn network_command(program: &Path, arguments: &[String], prepared: &PreparedPlan) -> Command {
    const BACKEND_VARIABLES: [&str; 2] = [
        "WG_QUICK_USERSPACE_IMPLEMENTATION",
        "AWG_QUICK_USERSPACE_IMPLEMENTATION",
    ];
    let mut command = Command::new(program);
    command.env("PATH", &prepared.path);
    for variable in BACKEND_VARIABLES {
        command.env_remove(variable);
    }
    if let Some((variable, executable)) = &prepared.backend_environment {
        command.env(variable, executable);
    }
    command.args(arguments);
    command
}

fn interface_exists(probe: &Path, interface: &str, path: &std::ffi::OsStr) -> Result<bool> {
    let status = Command::new(probe)
        .args(["show", interface])
        .env("PATH", path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("inspect network interface {interface}"))?;
    Ok(status.success())
}

fn interface_matches_profile(
    probe: &Path,
    interface: &str,
    expected_peers: &[String],
    path: &std::ffi::OsStr,
) -> Result<bool> {
    let output = Command::new(probe)
        .args(["show", interface, "peers"])
        .env("PATH", path)
        .output()
        .with_context(|| format!("inspect peers for network interface {interface}"))?;
    if !output.status.success() {
        return Ok(false);
    }
    let actual = String::from_utf8(output.stdout).context("interface peer list is not UTF-8")?;
    Ok(peer_sets_match(expected_peers, actual.lines()))
}

fn peer_sets_match<'a>(expected: &[String], actual: impl Iterator<Item = &'a str>) -> bool {
    let expected = expected
        .iter()
        .map(|peer| peer.trim())
        .collect::<std::collections::BTreeSet<_>>();
    let actual = actual
        .map(str::trim)
        .filter(|peer| !peer.is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    expected == actual
}

fn replace_profile_argument(arguments: &[String], source: &str, staged: &str) -> Vec<String> {
    arguments
        .iter()
        .map(|argument| {
            if argument == source {
                staged.to_owned()
            } else {
                argument.clone()
            }
        })
        .collect()
}

fn effective_user_id() -> Option<u32> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()
        })
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_owned_runtime_directory(base: &Path, label: &str) -> Result<PathBuf> {
    match fs::create_dir(base) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(base, fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("create {label} directory")),
    }
    let canonical = fs::canonicalize(base).with_context(|| format!("inspect {label} directory"))?;
    if canonical != base {
        bail!("{label} directory resolves outside its expected path");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{
            MetadataExt,
            PermissionsExt,
        };
        let metadata = fs::metadata(base)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            bail!("{label} directory must be root-owned with mode 0700");
        }
    }
    let directory = base.join(uuid::Uuid::new_v4().simple().to_string());
    create_private_directory(&directory)?;
    Ok(directory)
}

fn create_root_runtime_directory() -> Result<PathBuf> {
    create_owned_runtime_directory(Path::new("/run/amn"), "root VPN runtime")
}

fn create_quick_runtime_directory() -> Result<(PathBuf, bool)> {
    let base = Path::new("/etc/wireguard");
    let base_created = match fs::create_dir(base) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error).context("create WireGuard runtime directory"),
    };
    let result = (|| -> Result<PathBuf> {
        #[cfg(unix)]
        if base_created {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(base, fs::Permissions::from_mode(0o700))?;
        }
        let canonical = fs::canonicalize(base).context("inspect WireGuard runtime directory")?;
        if canonical != base {
            bail!("WireGuard runtime directory resolves outside its expected path");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{
                MetadataExt,
                PermissionsExt,
            };
            let metadata = fs::metadata(base)?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o777 != 0o700
            {
                bail!("WireGuard runtime directory must be root-owned with mode 0700");
            }
        }
        let directory = base.join(uuid::Uuid::new_v4().simple().to_string());
        fs::create_dir(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(error) = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)) {
                let rollback = fs::remove_dir(&directory);
                return match rollback {
                    Ok(()) => Err(error.into()),
                    Err(cleanup_error) => {
                        Err(anyhow!(
                            "{error}; WireGuard child runtime rollback failed: {cleanup_error}"
                        ))
                    }
                };
            }
        }
        Ok(directory)
    })();
    match result {
        Ok(directory) => Ok((directory, base_created)),
        Err(error) => {
            if base_created && let Err(cleanup_error) = fs::remove_dir(base) {
                return Err(anyhow!(
                    "{error:#}; WireGuard runtime rollback failed: {cleanup_error}"
                ));
            }
            Err(error)
        }
    }
}

fn fail_with_rollback<T>(
    plan: &CommandPlan,
    prepared: &PreparedPlan,
    failure: anyhow::Error,
) -> Result<T> {
    match rollback(plan, prepared) {
        Ok(()) => Err(failure).context("network action failed; rollback completed"),
        Err(rollback_error) => {
            Err(failure).context(format!(
                "network action failed and rollback failed: {rollback_error:#}"
            ))
        }
    }
}

struct PreparedOpenVpn {
    configuration: String,
    executable: PathBuf,
    setsid: PathBuf,
    kill: PathBuf,
    ip: PathBuf,
    path: std::ffi::OsString,
    interface: String,
}

fn prepare_openvpn(
    store: &Store,
    profile: &Profile,
    settings: &Settings,
) -> Result<PreparedOpenVpn> {
    let configuration =
        crate::core::openvpn::prepare(&store.validated_profile_text(profile)?, settings)?;
    let executable = resolve_network_program("openvpn")?;
    let version = Command::new(&executable)
        .arg("--version")
        .output()
        .context("check bundled OpenVPN")?;
    if !version.status.success() {
        bail!("bundled OpenVPN failed its dependency check");
    }
    Ok(PreparedOpenVpn {
        configuration: configuration.text,
        executable,
        setsid: resolve_network_program("setsid")?,
        kill: resolve_network_program("kill")?,
        ip: resolve_network_program("ip")?,
        path: std::env::join_paths(network_program_directories())
            .context("construct OpenVPN dependency PATH")?,
        interface: configuration.interface,
    })
}

fn start_openvpn(
    store: &Store,
    prepared: &PreparedOpenVpn,
    logging: bool,
) -> Result<(u32, PathBuf)> {
    if effective_user_id() != Some(0) {
        bail!("OpenVPN interface changes require running amn as root");
    }
    if Command::new(&prepared.ip)
        .args(["link", "show", "dev", &prepared.interface])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        bail!(
            "refusing to connect because interface already exists: {}",
            prepared.interface
        );
    }
    let reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .context("reserve OpenVPN management port")?;
    let management_port = reservation.local_addr()?.port();
    drop(reservation);
    let directory = create_root_runtime_directory()?;
    let configuration = directory.join("openvpn.conf");
    if let Err(error) =
        crate::core::store::write_private(&configuration, prepared.configuration.as_bytes())
    {
        let _ = fs::remove_dir_all(&directory);
        return Err(error).context("stage OpenVPN configuration");
    }
    let management_password = uuid::Uuid::new_v4().simple().to_string();
    let management_password_path = directory.join("management.password");
    if let Err(error) = crate::core::store::write_private(
        &management_password_path,
        format!("{management_password}\n").as_bytes(),
    ) {
        let _ = fs::remove_dir_all(&directory);
        return Err(error).context("stage OpenVPN management password");
    }
    let management_port_text = management_port.to_string();
    let mut command = Command::new(&prepared.setsid);
    command
        .args([
            prepared.executable.as_os_str(),
            std::ffi::OsStr::new("--config"),
            configuration.as_os_str(),
            std::ffi::OsStr::new("--management"),
            std::ffi::OsStr::new("127.0.0.1"),
            std::ffi::OsStr::new(&management_port_text),
            management_password_path.as_os_str(),
        ])
        .env("PATH", &prepared.path)
        .stdin(Stdio::null());
    if logging {
        let log_path = store
            .root()
            .join("logs")
            .join(format!("connection-{}.log", uuid::Uuid::new_v4().simple()));
        let stdout = match create_private_log(&log_path) {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_dir_all(&directory);
                return Err(error);
            }
        };
        let stderr = match stdout.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_dir_all(&directory);
                return Err(error.into());
            }
        };
        command.stdout(stdout).stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_dir_all(&directory);
            return Err(error).context("start isolated OpenVPN process");
        }
    };
    let startup = (|| -> Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut management = loop {
            if let Some(status) = child.try_wait()? {
                bail!("OpenVPN exited during startup with {status}");
            }
            match TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, management_port)) {
                Ok(stream) => break stream,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error).context("connect to OpenVPN management interface"),
            }
            if std::time::Instant::now() >= deadline {
                bail!("OpenVPN did not open its management interface");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        management.set_read_timeout(Some(std::time::Duration::from_millis(250)))?;
        management.write_all(
            format!("{management_password}\nstate on\nstate\nlog on\nbytecount 1\n").as_bytes(),
        )?;
        management.flush()?;
        let mut reader = BufReader::new(management);
        let mut line = String::new();
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("OpenVPN exited during startup with {status}");
            }
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => bail!("OpenVPN closed its management connection during startup"),
                Ok(_)
                    if line.contains(",CONNECTED,SUCCESS,")
                        || line.contains(",CONNECTED,SUCCESS") =>
                {
                    break;
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error).context("read OpenVPN management state"),
            }
            if std::time::Instant::now() >= deadline {
                bail!("OpenVPN did not report a successful connection");
            }
        }
        let interface_exists = Command::new(&prepared.ip)
            .args(["link", "show", "dev", &prepared.interface])
            .env("PATH", &prepared.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        if !interface_exists {
            bail!("OpenVPN reported connected without creating its tunnel interface");
        }
        Ok(())
    })();
    if let Err(error) = startup {
        let _ = stop_process_group(&prepared.kill, &prepared.path, child.id(), "OpenVPN");
        let _ = fs::remove_dir_all(&directory);
        return Err(error).context("OpenVPN startup rolled back");
    }
    Ok((child.id(), directory))
}

fn stop_process_group(kill: &Path, path: &std::ffi::OsStr, pid: u32, name: &str) -> Result<()> {
    let group_alive = || {
        Command::new(kill)
            .args(["-0", "--", &format!("-{pid}")])
            .env("PATH", path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    if !group_alive() {
        return Ok(());
    }
    let status = Command::new(kill)
        .args(["-TERM", "--", &format!("-{pid}")])
        .env("PATH", path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("stop {name} process group"))?;
    if !status.success() && group_alive() {
        bail!("stop {name} process exited with {status}");
    }
    for _ in 0..100 {
        if !group_alive() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("{name} process group did not stop")
}

fn force_stop_process_group(
    kill: &Path,
    path: &std::ffi::OsStr,
    pid: u32,
    name: &str,
) -> Result<()> {
    let status = Command::new(kill)
        .args(["-KILL", "--", &format!("-{pid}")])
        .env("PATH", path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("force-stop {name} process group"))?;
    if !status.success() && process_is_running(pid) {
        bail!("force-stop {name} process exited with {status}");
    }
    Ok(())
}

fn owned_runtime_file(path: PathBuf, expected_name: &str) -> Result<PathBuf> {
    let path = path.canonicalize().context("resolve staged runtime file")?;
    if path.file_name() != Some(std::ffi::OsStr::new(expected_name)) {
        bail!("staged runtime file has an unexpected name");
    }
    let directory = path
        .parent()
        .context("staged runtime file has no directory")?;
    if directory.parent() != Some(Path::new("/run/amn")) {
        bail!("staged runtime file is outside the owned runtime directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{
            MetadataExt,
            PermissionsExt,
        };
        let metadata = fs::metadata(directory)?;
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o777 != 0o700 {
            bail!("staged runtime directory ownership or permissions changed");
        }
    }
    Ok(path)
}

fn openvpn_process_configuration(pid: u32, expected_executable: Option<&Path>) -> Result<PathBuf> {
    if !process_is_running(pid) {
        bail!("recorded OpenVPN process is no longer running");
    }
    let executable =
        fs::canonicalize(format!("/proc/{pid}/exe")).context("resolve OpenVPN executable")?;
    if expected_executable.is_some_and(|expected| executable != expected)
        || executable.file_name() != Some(std::ffi::OsStr::new("openvpn"))
        || !is_trusted_network_executable(&executable)
    {
        bail!("recorded process is not a trusted OpenVPN process");
    }
    let command_line = fs::read(format!("/proc/{pid}/cmdline"))?;
    let arguments = command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    let index = arguments
        .iter()
        .position(|argument| *argument == b"--config")
        .context("OpenVPN process has no configuration argument")?;
    let value = arguments
        .get(index + 1)
        .context("OpenVPN configuration argument is incomplete")?;
    owned_runtime_file(
        PathBuf::from(std::ffi::OsString::from_vec(value.to_vec())),
        "openvpn.conf",
    )
}

struct PreparedIkev2 {
    endpoint: String,
    gateway: String,
    uplink: String,
    identity: String,
    remote_identity: Option<String>,
    certificate: Vec<u8>,
    password: String,
    ike_proposal: Option<String>,
    esp_proposal: Option<String>,
    executable: PathBuf,
    setsid: PathBuf,
    kill: PathBuf,
    ip: PathBuf,
    path: std::ffi::OsString,
    remote_ts: Vec<String>,
    bypass_routes: Vec<String>,
}

fn prepare_ikev2(
    store: &Store,
    profile: &Profile,
    settings: &Settings,
    owned_route: Option<&Ikev2RouteIdentity>,
) -> Result<PreparedIkev2> {
    let profile_text = store.validated_profile_text(profile)?;
    let configuration = crate::core::ikev2::parse_for_endpoint(
        &profile_text,
        owned_route.map(|route| route.endpoint.as_str()),
    )?;
    let executable = resolve_network_program("charon-cmd")?;
    let version = Command::new(&executable)
        .arg("--version")
        .output()
        .context("check charon-cmd")?;
    if !version.status.success() {
        bail!("charon-cmd failed its dependency check");
    }
    let ip = resolve_network_program("ip")?;
    let path = std::env::join_paths(network_program_directories())
        .context("construct IKEv2 dependency PATH")?;
    let (endpoint, gateway, uplink) = if let Some(route) = owned_route {
        (
            route.endpoint.clone(),
            route.gateway.clone(),
            route.uplink.clone(),
        )
    } else {
        let route = Command::new(&ip)
            .args(["route", "get", &configuration.endpoint])
            .env("PATH", &path)
            .output()
            .context("inspect route to IKEv2 endpoint")?;
        if !route.status.success() {
            bail!("cannot determine route to IKEv2 endpoint");
        }
        let route = String::from_utf8(route.stdout).context("IKEv2 endpoint route is not UTF-8")?;
        let fields = route.split_whitespace().collect::<Vec<_>>();
        let uplink = route_field(&fields, "dev")
            .context("IKEv2 endpoint route has no uplink interface")?
            .to_owned();
        let gateway = route_field(&fields, "via").unwrap_or("-").to_owned();
        (configuration.endpoint.clone(), gateway, uplink)
    };
    let routes = settings
        .split_routes
        .iter()
        .map(|route| crate::core::routing::Network::parse(route).map(|route| route.cidr()))
        .collect::<Result<Vec<_>>>()?;
    let (remote_ts, bypass_routes) = match settings.route_mode {
        crate::core::model::RouteMode::All => (vec!["0.0.0.0/0".into(), "::/0".into()], Vec::new()),
        crate::core::model::RouteMode::OnlyListed if routes.is_empty() => {
            bail!("IKEv2 only-listed routing requires at least one split route");
        }
        crate::core::model::RouteMode::OnlyListed => (routes, Vec::new()),
        crate::core::model::RouteMode::ExceptListed => {
            (vec!["0.0.0.0/0".into(), "::/0".into()], routes)
        }
    };
    Ok(PreparedIkev2 {
        endpoint,
        gateway,
        uplink,
        identity: configuration.identity,
        remote_identity: configuration.remote_identity.or(Some(configuration.host)),
        certificate: configuration.certificate,
        password: configuration.password,
        ike_proposal: configuration.ike_proposal,
        esp_proposal: configuration.esp_proposal,
        executable,
        setsid: resolve_network_program("setsid")?,
        kill: resolve_network_program("kill")?,
        ip,
        path,
        remote_ts,
        bypass_routes,
    })
}

fn ikev2_policy_arguments(action: &str, route: &str) -> Vec<Vec<String>> {
    let ipv6 = route.contains(':');
    let any = if ipv6 { "::/0" } else { "0.0.0.0/0" };
    vec![
        vec![
            "xfrm".into(),
            "policy".into(),
            action.into(),
            "dir".into(),
            "out".into(),
            "priority".into(),
            "5".into(),
            "src".into(),
            any.into(),
            "dst".into(),
            route.into(),
            "action".into(),
            "allow".into(),
        ],
        vec![
            "xfrm".into(),
            "policy".into(),
            action.into(),
            "dir".into(),
            "in".into(),
            "priority".into(),
            "5".into(),
            "src".into(),
            route.into(),
            "dst".into(),
            any.into(),
            "action".into(),
            "allow".into(),
        ],
    ]
}

fn run_ikev2_ip(prepared: &PreparedIkev2, arguments: &[String]) -> Result<()> {
    let status = Command::new(&prepared.ip)
        .args(arguments)
        .env("PATH", &prepared.path)
        .status()?;
    if !status.success() {
        bail!("ip {} exited with {status}", arguments.join(" "));
    }
    Ok(())
}

fn install_ikev2_endpoint_route(prepared: &PreparedIkev2) -> Result<()> {
    let existing_route = Command::new(&prepared.ip)
        .args(["route", "show", &format!("{}/32", prepared.endpoint)])
        .env("PATH", &prepared.path)
        .output()?;
    if !existing_route.status.success() || !existing_route.stdout.is_empty() {
        bail!("refusing to replace an existing specific route to the IKEv2 endpoint");
    }
    let existing_rule = Command::new(&prepared.ip)
        .args(["rule", "show", "priority", "186"])
        .env("PATH", &prepared.path)
        .output()?;
    if !existing_rule.status.success() || !existing_rule.stdout.is_empty() {
        bail!("refusing to replace an existing IP rule at priority 186");
    }
    let mut arguments = vec![
        "route".into(),
        "add".into(),
        format!("{}/32", prepared.endpoint),
    ];
    if prepared.gateway != "-" {
        arguments.extend(["via".into(), prepared.gateway.clone()]);
    }
    arguments.extend([
        "dev".into(),
        prepared.uplink.clone(),
        "proto".into(),
        "186".into(),
    ]);
    run_ikev2_ip(prepared, &arguments).context("pin IKEv2 endpoint to the original uplink")?;
    let rule = vec![
        "rule".into(),
        "add".into(),
        "to".into(),
        format!("{}/32", prepared.endpoint),
        "lookup".into(),
        "main".into(),
        "priority".into(),
        "186".into(),
    ];
    if let Err(error) = run_ikev2_ip(prepared, &rule) {
        let error = error.context("prioritize the pinned IKEv2 endpoint route");
        return Err(ikev2_setup_error(
            error,
            remove_ikev2_pinned_route(prepared),
        ));
    }
    Ok(())
}

fn remove_ikev2_pinned_route(prepared: &PreparedIkev2) -> Result<()> {
    let arguments = vec![
        "route".into(),
        "delete".into(),
        format!("{}/32", prepared.endpoint),
        "proto".into(),
        "186".into(),
    ];
    let deletion = run_ikev2_ip(prepared, &arguments);
    let remaining = Command::new(&prepared.ip)
        .args([
            "route",
            "show",
            &format!("{}/32", prepared.endpoint),
            "proto",
            "186",
        ])
        .env("PATH", &prepared.path)
        .output()?;
    if remaining.status.success() && remaining.stdout.is_empty() {
        Ok(())
    } else {
        deletion.context("remove pinned IKEv2 endpoint route")?;
        bail!("pinned IKEv2 endpoint route remained after removal")
    }
}

fn remove_ikev2_endpoint_route(prepared: &PreparedIkev2) -> Result<()> {
    let rule = vec![
        "rule".into(),
        "delete".into(),
        "to".into(),
        format!("{}/32", prepared.endpoint),
        "lookup".into(),
        "main".into(),
        "priority".into(),
        "186".into(),
    ];
    let _ = run_ikev2_ip(prepared, &rule);
    let rule_remaining = Command::new(&prepared.ip)
        .args(["rule", "show", "priority", "186"])
        .env("PATH", &prepared.path)
        .output()?;
    let rule_removed = rule_remaining.status.success()
        && !output_has_endpoint(&rule_remaining.stdout, &prepared.endpoint);
    let route_removed = remove_ikev2_pinned_route(prepared);
    combine_ikev2_cleanup([
        if rule_removed {
            Ok(())
        } else {
            Err(anyhow!("remove pinned IKEv2 endpoint rule"))
        },
        route_removed,
    ])
}

fn remove_ikev2_bypass_policies(prepared: &PreparedIkev2) -> Result<()> {
    let mut failures = Vec::new();
    for route in prepared.bypass_routes.iter().rev() {
        for arguments in ikev2_policy_arguments("delete", route).into_iter().rev() {
            if let Err(error) = run_ikev2_ip(prepared, &arguments) {
                failures.push(format!("{error:#}"));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("{}", failures.join("; "))
    }
}

fn output_has_endpoint(output: &[u8], endpoint: &str) -> bool {
    let endpoint_cidr = format!("{endpoint}/32");
    String::from_utf8_lossy(output)
        .split_whitespace()
        .any(|field| field == endpoint || field == endpoint_cidr)
}

fn remove_ikev2_kernel_artifacts(prepared: &PreparedIkev2) -> Result<()> {
    let interface_exists = Command::new(&prepared.ip)
        .args(["link", "show", "dev", "ipsec0"])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    if interface_exists {
        run_ikev2_ip(
            prepared,
            &[
                "link".into(),
                "delete".into(),
                "dev".into(),
                "ipsec0".into(),
            ],
        )
        .context("remove owned IKEv2 kernel-libipsec interface")?;
    }
    let interface_remains = Command::new(&prepared.ip)
        .args(["link", "show", "dev", "ipsec0"])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    let routes = Command::new(&prepared.ip)
        .args(["route", "show", "table", "220"])
        .env("PATH", &prepared.path)
        .output()?;
    let owned_routes_remain = String::from_utf8_lossy(&routes.stdout)
        .lines()
        .any(|line| line.split_whitespace().any(|field| field == "ipsec0"));
    let states = Command::new(&prepared.ip)
        .args(["xfrm", "state"])
        .env("PATH", &prepared.path)
        .output()?;
    let policies = Command::new(&prepared.ip)
        .args(["xfrm", "policy"])
        .env("PATH", &prepared.path)
        .output()?;
    let endpoint_xfrm_state = output_has_endpoint(&states.stdout, &prepared.endpoint);
    let endpoint_xfrm_policy = output_has_endpoint(&policies.stdout, &prepared.endpoint);
    if interface_remains
        || !routes.status.success()
        || owned_routes_remain
        || !states.status.success()
        || !policies.status.success()
        || endpoint_xfrm_state
        || endpoint_xfrm_policy
    {
        bail!("owned IKEv2 kernel artifacts remained after process termination");
    }
    Ok(())
}

fn cleanup_ikev2_network(prepared: &PreparedIkev2) -> Result<()> {
    let kernel = remove_ikev2_kernel_artifacts(prepared);
    let endpoint = remove_ikev2_endpoint_route(prepared);
    let policies = remove_ikev2_bypass_policies(prepared);
    combine_ikev2_cleanup([kernel, endpoint, policies])
}

fn combine_ikev2_cleanup<const N: usize>(results: [Result<()>; N]) -> Result<()> {
    let failures = results
        .into_iter()
        .filter_map(Result::err)
        .map(|error| format!("{error:#}"))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("IKEv2 cleanup failed: {}", failures.join("; "))
    }
}

fn stop_and_cleanup_ikev2(prepared: &PreparedIkev2, pid: u32) -> Result<()> {
    if let Err(stop_error) = stop_process_group(&prepared.kill, &prepared.path, pid, "IKEv2") {
        force_stop_process_group(&prepared.kill, &prepared.path, pid, "IKEv2")
            .with_context(|| format!("IKEv2 stop failed: {stop_error:#}"))?;
    }
    cleanup_ikev2_network(prepared)
}

fn rollback_applied_ikev2_policies(
    prepared: &PreparedIkev2,
    applied_policies: &[Vec<String>],
) -> Result<()> {
    let mut failures = Vec::new();
    for applied in applied_policies.iter().rev() {
        let mut reverse = applied.clone();
        reverse[2] = "delete".into();
        if let Err(error) = run_ikev2_ip(prepared, &reverse) {
            failures.push(format!("{error:#}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to remove IKEv2 bypass policies: {}",
            failures.join("; ")
        )
    }
}

fn rollback_ikev2_setup(prepared: &PreparedIkev2, directory: Option<&Path>) -> Result<()> {
    let network = cleanup_ikev2_network(prepared);
    let files = match directory {
        Some(directory) => fs::remove_dir_all(directory).context("remove staged IKEv2 files"),
        None => Ok(()),
    };
    combine_ikev2_cleanup([network, files])
}

fn ikev2_setup_error(error: anyhow::Error, rollback: Result<()>) -> anyhow::Error {
    match rollback {
        Ok(()) => error,
        Err(rollback_error) => anyhow!("{error:#}; IKEv2 rollback failed: {rollback_error:#}"),
    }
}

fn start_ikev2(store: &Store, prepared: &PreparedIkev2, logging: bool) -> Result<(u32, PathBuf)> {
    if effective_user_id() != Some(0) {
        bail!("IKEv2 connection requires running amn as root");
    }
    let tunnel_exists = Command::new(&prepared.ip)
        .args(["link", "show", "dev", "ipsec0"])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    if tunnel_exists {
        bail!("refusing to connect because IKEv2 interface already exists: ipsec0");
    }
    let baseline = Command::new(&prepared.ip)
        .args(["xfrm", "state"])
        .env("PATH", &prepared.path)
        .output()
        .context("capture existing IPsec security associations")?;
    if !baseline.status.success() {
        bail!("cannot inspect existing IPsec security associations");
    }
    let mut applied_policies: Vec<Vec<String>> = Vec::new();
    for route in &prepared.bypass_routes {
        for arguments in ikev2_policy_arguments("add", route) {
            if let Err(error) = run_ikev2_ip(prepared, &arguments) {
                let error = error.context("install IKEv2 bypass policy");
                return Err(ikev2_setup_error(
                    error,
                    rollback_applied_ikev2_policies(prepared, &applied_policies),
                ));
            }
            applied_policies.push(arguments);
        }
    }
    if let Err(error) = install_ikev2_endpoint_route(prepared) {
        return Err(ikev2_setup_error(
            error,
            rollback_applied_ikev2_policies(prepared, &applied_policies),
        ));
    }
    let directory = match create_root_runtime_directory() {
        Ok(directory) => directory,
        Err(error) => {
            return Err(ikev2_setup_error(
                error,
                rollback_ikev2_setup(prepared, None),
            ));
        }
    };
    let certificate = directory.join("client.p12");
    if let Err(error) = crate::core::store::write_private(&certificate, &prepared.certificate) {
        return Err(ikev2_setup_error(
            error.context("stage IKEv2 certificate"),
            rollback_ikev2_setup(prepared, Some(&directory)),
        ));
    }
    let mut arguments = vec![
        prepared.executable.as_os_str().to_owned(),
        "--host".into(),
        prepared.endpoint.clone().into(),
        "--identity".into(),
        prepared.identity.clone().into(),
        "--p12".into(),
        certificate.as_os_str().to_owned(),
        "--profile".into(),
        "ikev2-pub".into(),
    ];
    for selector in &prepared.remote_ts {
        arguments.extend(["--remote-ts".into(), selector.into()]);
    }
    if let Some(identity) = &prepared.remote_identity {
        arguments.extend(["--remote-identity".into(), identity.into()]);
    }
    if let Some(proposal) = &prepared.ike_proposal {
        arguments.extend(["--ike-proposal".into(), proposal.into()]);
    }
    if let Some(proposal) = &prepared.esp_proposal {
        arguments.extend(["--esp-proposal".into(), proposal.into()]);
    }
    let mut command = Command::new(&prepared.setsid);
    command
        .args(arguments)
        .env("PATH", &prepared.path)
        .stdin(Stdio::piped());
    if logging {
        let log_path = store
            .root()
            .join("logs")
            .join(format!("connection-{}.log", uuid::Uuid::new_v4().simple()));
        let stdout = match create_private_log(&log_path) {
            Ok(file) => file,
            Err(error) => {
                return Err(ikev2_setup_error(
                    error,
                    rollback_ikev2_setup(prepared, Some(&directory)),
                ));
            }
        };
        let stderr = match stdout.try_clone() {
            Ok(file) => file,
            Err(error) => {
                return Err(ikev2_setup_error(
                    error.into(),
                    rollback_ikev2_setup(prepared, Some(&directory)),
                ));
            }
        };
        command.stdout(stdout).stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Err(ikev2_setup_error(
                error.into(),
                rollback_ikev2_setup(prepared, Some(&directory)),
            ))
            .context("start isolated IKEv2 process");
        }
    };
    let startup = (|| -> Result<()> {
        if let Some(mut input) = child.stdin.take() {
            input.write_all(prepared.password.as_bytes())?;
            input.write_all(b"\n")?;
        }
        for _ in 0..300 {
            if let Some(status) = child.try_wait()? {
                bail!("IKEv2 process exited during startup with {status}");
            }
            let state = Command::new(&prepared.ip)
                .args(["xfrm", "state"])
                .env("PATH", &prepared.path)
                .output()?;
            let kernel_ready = state.status.success()
                && state.stdout != baseline.stdout
                && String::from_utf8_lossy(&state.stdout)
                    .split_whitespace()
                    .any(|field| field == prepared.endpoint);
            if kernel_ready {
                let policies = Command::new(&prepared.ip)
                    .args(["xfrm", "policy"])
                    .env("PATH", &prepared.path)
                    .output()?;
                if policies.status.success() && !policies.stdout.is_empty() {
                    return Ok(());
                }
            }
            let tunnel = Command::new(&prepared.ip)
                .args(["-brief", "address", "show", "dev", "ipsec0"])
                .env("PATH", &prepared.path)
                .output()?;
            let routes = Command::new(&prepared.ip)
                .args(["route", "show", "table", "220", "dev", "ipsec0"])
                .env("PATH", &prepared.path)
                .output()?;
            let has_virtual_ipv4 = String::from_utf8_lossy(&tunnel.stdout)
                .split_whitespace()
                .any(|field| field.contains('.') && field.contains('/'));
            if tunnel.status.success()
                && routes.status.success()
                && has_virtual_ipv4
                && !routes.stdout.is_empty()
            {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!("IKEv2 did not establish a new IPsec security association and policy")
    })();
    if let Err(error) = startup {
        let cleanup = stop_and_cleanup_ikev2(prepared, child.id());
        let directory_cleanup = fs::remove_dir_all(&directory)
            .context("remove staged IKEv2 certificate after startup failure");
        return match combine_ikev2_cleanup([cleanup, directory_cleanup]) {
            Ok(()) => Err(error).context("IKEv2 startup rolled back"),
            Err(cleanup_error) => {
                Err(error).context(format!(
                    "IKEv2 startup failed and rollback failed: {cleanup_error:#}"
                ))
            }
        };
    }
    Ok((child.id(), directory))
}

fn ikev2_process_certificate(pid: u32, expected_executable: Option<&Path>) -> Result<PathBuf> {
    if !process_is_running(pid) {
        bail!("recorded IKEv2 process is no longer running");
    }
    let executable =
        fs::canonicalize(format!("/proc/{pid}/exe")).context("resolve IKEv2 executable")?;
    if expected_executable.is_some_and(|expected| executable != expected)
        || executable.file_name() != Some(std::ffi::OsStr::new("charon-cmd"))
        || !is_trusted_network_executable(&executable)
    {
        bail!("recorded process is not a trusted IKEv2 process");
    }
    let command_line = fs::read(format!("/proc/{pid}/cmdline"))?;
    let arguments = command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    let index = arguments
        .iter()
        .position(|argument| *argument == b"--p12")
        .context("IKEv2 process has no certificate argument")?;
    let value = arguments
        .get(index + 1)
        .context("IKEv2 certificate argument is incomplete")?;
    owned_runtime_file(
        PathBuf::from(std::ffi::OsString::from_vec(value.to_vec())),
        "client.p12",
    )
}

struct PreparedXray {
    configuration: String,
    endpoint: String,
    endpoint_port: u16,
    gateway: String,
    uplink: String,
    executable: PathBuf,
    tun2socks: PathBuf,
    setsid: PathBuf,
    kill: PathBuf,
    ip: PathBuf,
    path: std::ffi::OsString,
    route_mode: crate::core::model::RouteMode,
    split_routes: Vec<crate::core::routing::Network>,
}

fn prepare_xray(store: &Store, profile: &Profile, settings: &Settings) -> Result<PreparedXray> {
    let text = store.validated_profile_text(profile)?;
    let raw = match profile.protocol {
        Protocol::Xray => crate::core::xray::RawConfiguration::parse(&text)?,
        Protocol::Shadowsocks => crate::core::shadowsocks::parse(&text)?,
        _ => bail!("protocol does not use the XRay transport backend"),
    };
    let endpoint = raw.endpoint_ipv4()?;
    let endpoint_port = raw.endpoint_port();
    let configuration = raw.render_for_endpoint(endpoint)?;
    let executable = resolve_network_program("amnezia-xray-runner")?;
    let runner_status = Command::new(&executable)
        .arg("--check")
        .status()
        .context("check bundled XRay runner")?;
    if !runner_status.success() {
        bail!("bundled XRay runner failed its dependency check");
    }
    let tun2socks = resolve_network_program("tun2socks")?;
    let setsid = resolve_network_program("setsid")?;
    let kill = resolve_network_program("kill")?;
    let ip = resolve_network_program("ip")?;
    let path = std::env::join_paths(network_program_directories())
        .context("construct XRay dependency PATH")?;
    let route = Command::new(&ip)
        .args(["route", "get", &endpoint.to_string()])
        .env("PATH", &path)
        .output()
        .context("inspect route to XRay endpoint")?;
    if !route.status.success() {
        bail!("cannot determine route to XRay endpoint");
    }
    let route = String::from_utf8(route.stdout).context("XRay endpoint route is not UTF-8")?;
    let fields = route.split_whitespace().collect::<Vec<_>>();
    let uplink = route_field(&fields, "dev")
        .context("XRay endpoint route has no uplink interface")?
        .to_owned();
    let gateway = route_field(&fields, "via").unwrap_or("-").to_owned();
    let split_routes = settings
        .split_routes
        .iter()
        .map(|route| crate::core::routing::Network::parse(route))
        .collect::<Result<Vec<_>>>()?;
    if settings.route_mode != crate::core::model::RouteMode::All
        && split_routes
            .iter()
            .any(crate::core::routing::Network::is_ipv6)
    {
        bail!("XRay split-tunnel routes currently require IPv4 networks");
    }
    Ok(PreparedXray {
        configuration,
        endpoint: endpoint.to_string(),
        endpoint_port,
        gateway,
        uplink,
        executable,
        tun2socks,
        setsid,
        kill,
        ip,
        path,
        route_mode: settings.route_mode.clone(),
        split_routes,
    })
}

fn route_field<'a>(fields: &'a [&str], name: &str) -> Option<&'a str> {
    fields
        .windows(2)
        .find_map(|pair| (pair.first().copied() == Some(name)).then(|| pair[1]))
}

fn xray_ip_command(prepared: &PreparedXray, arguments: &[String]) -> Result<()> {
    let status = Command::new(&prepared.ip)
        .args(arguments)
        .env("PATH", &prepared.path)
        .status()
        .with_context(|| format!("run ip {}", arguments.join(" ")))?;
    if !status.success() {
        bail!("ip {} exited with {status}", arguments.join(" "));
    }
    Ok(())
}

fn apply_xray_mutation(
    prepared: &PreparedXray,
    forward: Vec<String>,
    reverse: Vec<String>,
    rollback: &mut Vec<Vec<String>>,
) -> Result<()> {
    xray_ip_command(prepared, &forward)?;
    rollback.push(reverse);
    Ok(())
}

fn endpoint_route_arguments(prepared: &PreparedXray, action: &str) -> Vec<String> {
    let mut arguments = vec![
        "route".into(),
        action.into(),
        format!("{}/32", prepared.endpoint),
    ];
    if prepared.gateway != "-" {
        arguments.extend(["via".into(), prepared.gateway.clone()]);
    }
    arguments.extend([
        "dev".into(),
        prepared.uplink.clone(),
        "proto".into(),
        "66".into(),
    ]);
    arguments
}

fn start_xray_worker(
    store: &Store,
    prepared: &PreparedXray,
    interface: &str,
    logging: bool,
) -> Result<u32> {
    if effective_user_id() != Some(0) {
        bail!("XRay interface changes require running amn as root");
    }
    let directory = create_root_runtime_directory()?;
    let configuration = directory.join("xray.json");
    if let Err(error) =
        crate::core::store::write_private(&configuration, prepared.configuration.as_bytes())
    {
        let _ = fs::remove_dir_all(&directory);
        return Err(error).context("stage normalized XRay configuration");
    }
    let mut command = Command::new(&prepared.setsid);
    command
        .args([
            prepared.executable.as_os_str(),
            configuration.as_os_str(),
            prepared.tun2socks.as_os_str(),
            std::ffi::OsStr::new(interface),
            std::ffi::OsStr::new(&prepared.endpoint),
            std::ffi::OsStr::new(&prepared.gateway),
            std::ffi::OsStr::new(&prepared.uplink),
        ])
        .env("PATH", &prepared.path)
        .stdin(Stdio::null());
    if logging {
        let log_path = store
            .root()
            .join("logs")
            .join(format!("connection-{}.log", uuid::Uuid::new_v4().simple()));
        let stdout = create_private_log(&log_path)?;
        let stderr = match stdout.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_dir_all(&directory);
                return Err(error.into());
            }
        };
        command.stdout(stdout).stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let mut child = command.spawn().context("start isolated XRay worker")?;
    for _ in 0..50 {
        if let Some(status) = child.try_wait()? {
            let _ = fs::remove_dir_all(&directory);
            bail!("XRay worker exited during startup with {status}");
        }
        let exists = Command::new(&prepared.ip)
            .args(["link", "show", "dev", interface])
            .env("PATH", &prepared.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        if exists {
            fs::remove_dir_all(&directory).context("remove staged XRay configuration")?;
            return Ok(child.id());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = stop_xray_worker(prepared, child.id());
    let _ = fs::remove_dir_all(&directory);
    bail!("XRay worker did not create its TUN interface")
}

fn stop_xray_worker(prepared: &PreparedXray, pid: u32) -> Result<()> {
    stop_process_group(&prepared.kill, &prepared.path, pid, "XRay worker")
}

fn traffic_route_pairs(
    prepared: &PreparedXray,
    interface: &str,
) -> Vec<(Vec<String>, Vec<String>)> {
    let mut pairs = Vec::new();
    let tunnel_route = |action: &str, prefix: &str| {
        vec![
            "route".into(),
            action.into(),
            prefix.into(),
            "dev".into(),
            interface.into(),
            "proto".into(),
            "66".into(),
            "metric".into(),
            "5".into(),
        ]
    };
    let bypass_route = |action: &str, prefix: &str| {
        let mut arguments = vec!["route".into(), action.into(), prefix.into()];
        if prepared.gateway != "-" {
            arguments.extend(["via".into(), prepared.gateway.clone()]);
        }
        arguments.extend([
            "dev".into(),
            prepared.uplink.clone(),
            "proto".into(),
            "66".into(),
            "metric".into(),
            "5".into(),
        ]);
        arguments
    };
    match prepared.route_mode {
        crate::core::model::RouteMode::All => {
            for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
                pairs.push((tunnel_route("add", prefix), tunnel_route("delete", prefix)));
            }
        }
        crate::core::model::RouteMode::OnlyListed => {
            for route in &prepared.split_routes {
                let prefix = route.cidr();
                pairs.push((
                    tunnel_route("add", &prefix),
                    tunnel_route("delete", &prefix),
                ));
            }
        }
        crate::core::model::RouteMode::ExceptListed => {
            for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
                pairs.push((tunnel_route("add", prefix), tunnel_route("delete", prefix)));
            }
            for route in &prepared.split_routes {
                let prefix = route.cidr();
                pairs.push((
                    bypass_route("add", &prefix),
                    bypass_route("delete", &prefix),
                ));
            }
        }
    }
    if prepared.route_mode != crate::core::model::RouteMode::OnlyListed {
        pairs.push((
            vec![
                "-6".into(),
                "route".into(),
                "add".into(),
                "unreachable".into(),
                "::/0".into(),
                "proto".into(),
                "66".into(),
                "metric".into(),
                "42760".into(),
            ],
            vec![
                "-6".into(),
                "route".into(),
                "delete".into(),
                "unreachable".into(),
                "::/0".into(),
                "proto".into(),
                "66".into(),
                "metric".into(),
                "42760".into(),
            ],
        ));
    }
    pairs
}

fn configure_xray_interface(
    prepared: &PreparedXray,
    interface: &str,
    rollback: &mut Vec<Vec<String>>,
) -> Result<()> {
    apply_xray_mutation(
        prepared,
        vec![
            "address".into(),
            "add".into(),
            "10.33.0.2/24".into(),
            "dev".into(),
            interface.into(),
        ],
        vec![
            "address".into(),
            "delete".into(),
            "10.33.0.2/24".into(),
            "dev".into(),
            interface.into(),
        ],
        rollback,
    )?;
    apply_xray_mutation(
        prepared,
        vec![
            "link".into(),
            "set".into(),
            "dev".into(),
            interface.into(),
            "up".into(),
        ],
        vec![
            "link".into(),
            "set".into(),
            "dev".into(),
            interface.into(),
            "down".into(),
        ],
        rollback,
    )?;
    apply_xray_mutation(
        prepared,
        endpoint_route_arguments(prepared, "add"),
        endpoint_route_arguments(prepared, "delete"),
        rollback,
    )?;
    for (forward, reverse) in traffic_route_pairs(prepared, interface) {
        apply_xray_mutation(prepared, forward, reverse, rollback)?;
    }
    Ok(())
}

fn rollback_xray_connect(
    prepared: &PreparedXray,
    pid: u32,
    interface: &str,
    rollback: &mut Vec<Vec<String>>,
) -> Result<()> {
    let mut failures = Vec::new();
    while let Some(arguments) = rollback.pop() {
        if let Err(error) = xray_ip_command(prepared, &arguments) {
            failures.push(format!("{error:#}"));
        }
    }
    if let Err(error) = stop_xray_worker(prepared, pid) {
        failures.push(format!("{error:#}"));
    }
    let delete = vec![
        "link".into(),
        "delete".into(),
        "dev".into(),
        interface.into(),
    ];
    let _ = xray_ip_command(prepared, &delete);
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("{}", failures.join("; "))
    }
}

fn connect_xray(
    store: &Store,
    state: &mut State,
    profile: &Profile,
    id: String,
    dry_run: bool,
) -> Result<String> {
    if dry_run {
        return Ok("amnezia-xray-runner <validated-config> <tun2socks> amnxray0 <endpoint> <gateway> <uplink>\nrollback: ip route/address/link delete; terminate XRay worker process group".into());
    }
    let prepared = prepare_xray(store, profile, &state.settings)?;
    let endpoint = format!("{}:{}", prepared.endpoint, prepared.endpoint_port)
        .parse()
        .context("construct XRay endpoint socket address")?;
    TcpStream::connect_timeout(&endpoint, std::time::Duration::from_secs(5))
        .context("XRay endpoint is not accepting TCP connections")?;
    let interface = "amnxray0";
    let existing = Command::new(&prepared.ip)
        .args(["link", "show", "dev", interface])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    if existing {
        bail!("refusing to connect because interface already exists: {interface}");
    }
    let pid = start_xray_worker(store, &prepared, interface, state.settings.logging)?;
    let mut rollback = Vec::new();
    let mutation = configure_xray_interface(&prepared, interface, &mut rollback);
    if let Err(error) = mutation {
        return match rollback_xray_connect(&prepared, pid, interface, &mut rollback) {
            Ok(()) => Err(error).context("XRay connection failed; rollback completed"),
            Err(rollback_error) => {
                Err(error).context(format!(
                    "XRay connection and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    let Some(start_ticks) = process_start_ticks(pid) else {
        rollback_xray_connect(&prepared, pid, interface, &mut rollback)
            .context("XRay process identity could not be read and rollback failed")?;
        bail!("XRay process identity could not be read; connection rolled back");
    };
    let mut updated = state.clone();
    updated.connection = Some(Connection {
        profile_id: id,
        pid: Some(pid),
        process_start_ticks: Some(start_ticks),
        interface: Some(interface.into()),
        ikev2_route: None,
    });
    if let Err(error) = store.save(&updated) {
        return match rollback_xray_connect(&prepared, pid, interface, &mut rollback) {
            Ok(()) => Err(error).context("XRay connection rolled back after state save failed"),
            Err(rollback_error) => {
                Err(error).context(format!(
                    "XRay state save and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = updated;
    Ok("connected".into())
}

struct XrayProcessInfo {
    interface: String,
    endpoint: String,
    gateway: String,
    uplink: String,
}

fn xray_process_info(pid: u32) -> Result<XrayProcessInfo> {
    if !process_is_running(pid) {
        bail!("recorded XRay worker is no longer running");
    }
    let executable =
        fs::canonicalize(format!("/proc/{pid}/exe")).context("resolve XRay worker executable")?;
    if executable.file_name() != Some(std::ffi::OsStr::new("amnezia-xray-runner"))
        || !is_trusted_network_executable(&executable)
    {
        bail!("recorded process is not a trusted XRay worker");
    }
    let command_line =
        fs::read(format!("/proc/{pid}/cmdline")).context("read XRay worker command line")?;
    let arguments = command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .collect::<Vec<_>>();
    let values = arguments
        .get(1..7)
        .context("XRay worker command line is incomplete")?;
    Ok(XrayProcessInfo {
        interface: String::from_utf8(values[2].to_vec()).context("XRay interface is not UTF-8")?,
        endpoint: String::from_utf8(values[3].to_vec()).context("XRay endpoint is not UTF-8")?,
        gateway: String::from_utf8(values[4].to_vec()).context("XRay gateway is not UTF-8")?,
        uplink: String::from_utf8(values[5].to_vec()).context("XRay uplink is not UTF-8")?,
    })
}

fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    fields.get(19)?.parse().ok()
}

fn verify_connection_process(connection: &Connection) -> Result<u32> {
    let pid = connection.pid.context("connection has no process ID")?;
    let expected = connection
        .process_start_ticks
        .context("connection has no verifiable process start identity")?;
    if process_start_ticks(pid) != Some(expected) {
        bail!("recorded connection process identity no longer matches");
    }
    Ok(pid)
}

fn process_is_running(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, suffix)| suffix.chars().next())
        .is_some_and(|state| state != 'Z')
}

fn reverse_ip_action(mut arguments: Vec<String>) -> Vec<String> {
    if let Some(action) = arguments
        .iter_mut()
        .find(|value| value.as_str() == "add" || value.as_str() == "delete")
    {
        *action = if action == "add" {
            "delete".into()
        } else {
            "add".into()
        };
    }
    arguments
}

fn restore_xray_disconnect(
    store: &Store,
    state: &mut State,
    profile: &Profile,
    original: &Connection,
    prepared: &PreparedXray,
    process_alive: bool,
    mut route_rollback: Vec<Vec<String>>,
) -> Result<()> {
    let interface = original
        .interface
        .as_deref()
        .context("XRay connection has no interface")?;
    let mut restored = original.clone();
    let pid;
    let mut disconnect_again = Vec::new();
    if process_alive {
        pid = original.pid.context("XRay connection has no worker PID")?;
        while let Some(arguments) = route_rollback.pop() {
            if let Err(error) = xray_ip_command(prepared, &arguments) {
                let cleanup =
                    rollback_xray_connect(prepared, pid, interface, &mut disconnect_again);
                return match cleanup {
                    Ok(()) => {
                        Err(error).context(
                            "restore XRay route failed; disconnected network state retained",
                        )
                    }
                    Err(cleanup_error) => {
                        Err(error).context(format!(
                            "restore XRay route and cleanup failed: {cleanup_error:#}"
                        ))
                    }
                };
            }
            disconnect_again.push(reverse_ip_action(arguments));
        }
    } else {
        let delete = vec![
            "link".into(),
            "delete".into(),
            "dev".into(),
            interface.into(),
        ];
        let _ = xray_ip_command(prepared, &delete);
        pid = start_xray_worker(store, prepared, interface, state.settings.logging)?;
        if let Err(error) = configure_xray_interface(prepared, interface, &mut disconnect_again) {
            let _ = rollback_xray_connect(prepared, pid, interface, &mut disconnect_again);
            return Err(error).context("restore XRay network after failed disconnect");
        }
        restored.pid = Some(pid);
    }
    let Some(start_ticks) = process_start_ticks(pid) else {
        let _ = rollback_xray_connect(prepared, pid, interface, &mut disconnect_again);
        bail!("restored XRay worker process identity could not be read");
    };
    restored.process_start_ticks = Some(start_ticks);
    let mut recovered = state.clone();
    recovered.connection = Some(restored);
    if let Err(error) = store.save(&recovered) {
        let rollback = rollback_xray_connect(prepared, pid, interface, &mut disconnect_again);
        return match rollback {
            Ok(()) => {
                Err(error).context(
                    "restore XRay connection state failed; disconnected network state retained",
                )
            }
            Err(rollback_error) => {
                Err(error).context(format!(
                    "restore XRay connection state and cleanup failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = recovered;
    let _ = profile;
    Ok(())
}

fn disconnect_xray(
    store: &Store,
    state: &mut State,
    profile: &Profile,
    connection: &Connection,
    dry_run: bool,
) -> Result<String> {
    let pid = verify_connection_process(connection).context("verify XRay worker identity")?;
    let info = xray_process_info(pid)?;
    if connection.interface.as_deref() != Some(&info.interface) {
        bail!("XRay worker interface does not match saved connection");
    }
    if dry_run {
        return Ok(format!(
            "ip route delete 0.0.0.0/1 dev {} proto 66; ip route delete 128.0.0.0/1 dev {} proto 66; terminate XRay worker {}\nrollback: restart validated XRay worker and restore address/routes",
            info.interface, info.interface, pid
        ));
    }
    let mut prepared = prepare_xray(store, profile, &state.settings)?;
    prepared.endpoint = info.endpoint;
    prepared.gateway = info.gateway;
    prepared.uplink = info.uplink;

    let mut disconnected = state.clone();
    disconnected.connection = None;
    store
        .save(&disconnected)
        .context("persist pending XRay disconnect")?;

    let mut route_rollback = Vec::new();
    let operation = (|| -> Result<()> {
        for (forward, reverse) in traffic_route_pairs(&prepared, &info.interface)
            .into_iter()
            .rev()
        {
            apply_xray_mutation(&prepared, reverse, forward, &mut route_rollback)?;
        }
        apply_xray_mutation(
            &prepared,
            endpoint_route_arguments(&prepared, "delete"),
            endpoint_route_arguments(&prepared, "add"),
            &mut route_rollback,
        )?;
        stop_xray_worker(&prepared, pid)?;
        let exists = Command::new(&prepared.ip)
            .args(["link", "show", "dev", &info.interface])
            .env("PATH", &prepared.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        if exists {
            xray_ip_command(
                &prepared,
                &[
                    "link".into(),
                    "delete".into(),
                    "dev".into(),
                    info.interface.clone(),
                ],
            )?;
        }
        Ok(())
    })();
    if let Err(error) = operation {
        let process_alive = process_is_running(pid);
        return match restore_xray_disconnect(
            store,
            state,
            profile,
            connection,
            &prepared,
            process_alive,
            route_rollback,
        ) {
            Ok(()) => Err(error).context("XRay disconnect failed; rollback completed"),
            Err(rollback_error) => {
                Err(error).context(format!(
                    "XRay disconnect and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = disconnected;
    Ok("disconnected".into())
}

fn connect_openvpn(
    store: &Store,
    state: &mut State,
    profile: &Profile,
    id: String,
    dry_run: bool,
) -> Result<String> {
    if dry_run {
        return Ok("openvpn --config <validated-config>\nrollback: terminate the owned OpenVPN process group and remove its tunnel interface".into());
    }
    let prepared = prepare_openvpn(store, profile, &state.settings)?;
    let (pid, runtime_directory) = start_openvpn(store, &prepared, state.settings.logging)?;
    let Some(start_ticks) = process_start_ticks(pid) else {
        let rollback = stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN");
        let _ = fs::remove_dir_all(&runtime_directory);
        rollback.context("OpenVPN process identity could not be read and rollback failed")?;
        bail!("OpenVPN process identity could not be read; connection rolled back");
    };
    let mut updated = state.clone();
    updated.connection = Some(Connection {
        profile_id: id,
        pid: Some(pid),
        process_start_ticks: Some(start_ticks),
        interface: Some(prepared.interface.clone()),
        ikev2_route: None,
    });
    if let Err(error) = store.save(&updated) {
        let rollback = stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN");
        let _ = fs::remove_dir_all(&runtime_directory);
        return match rollback {
            Ok(()) => Err(error).context("OpenVPN connection rolled back after state save failed"),
            Err(rollback_error) => {
                Err(error).context(format!(
                    "OpenVPN state save and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = updated;
    Ok("connected".into())
}

fn restore_openvpn_connection(
    store: &Store,
    state: &mut State,
    original: &Connection,
    prepared: &PreparedOpenVpn,
) -> Result<()> {
    let (pid, directory) = start_openvpn(store, prepared, state.settings.logging)?;
    let Some(start_ticks) = process_start_ticks(pid) else {
        let _ = stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN");
        let _ = fs::remove_dir_all(directory);
        bail!("restored OpenVPN process identity could not be read");
    };
    let mut connection = original.clone();
    connection.pid = Some(pid);
    connection.process_start_ticks = Some(start_ticks);
    connection.interface = Some(prepared.interface.clone());
    let mut recovered = state.clone();
    recovered.connection = Some(connection);
    if let Err(error) = store.save(&recovered) {
        let _ = stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN");
        let _ = fs::remove_dir_all(directory);
        return Err(error).context("persist restored OpenVPN connection");
    }
    *state = recovered;
    Ok(())
}

fn disconnect_openvpn(
    store: &Store,
    state: &mut State,
    profile: &Profile,
    connection: &Connection,
    dry_run: bool,
) -> Result<String> {
    let pid = verify_connection_process(connection).context("verify OpenVPN process identity")?;
    let prepared = prepare_openvpn(store, profile, &state.settings)?;
    let configuration = openvpn_process_configuration(pid, Some(&prepared.executable))?;
    if dry_run {
        return Ok(format!(
            "terminate owned OpenVPN process group {pid}\nrollback: restart the validated OpenVPN profile"
        ));
    }
    let mut disconnected = state.clone();
    disconnected.connection = None;
    store
        .save(&disconnected)
        .context("persist pending OpenVPN disconnect")?;
    if let Err(error) = stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN") {
        if let Err(persist_error) = store.save(state) {
            let cleanup = force_stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN");
            return match cleanup {
                Ok(()) => Err(error).context(format!("OpenVPN disconnect failed and connection state could not be restored: {persist_error:#}; process force-stopped")),
                Err(cleanup_error) => Err(error).context(format!("OpenVPN disconnect, state restoration, and force-stop failed: {persist_error:#}; {cleanup_error:#}")),
            };
        }
        return Err(error).context("OpenVPN disconnect failed; connection state restored");
    }
    let runtime_directory = configuration.parent().map(Path::to_path_buf);
    let cleanup = (|| -> Result<()> {
        for _ in 0..100 {
            let exists = Command::new(&prepared.ip)
                .args(["link", "show", "dev", &prepared.interface])
                .env("PATH", &prepared.path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success();
            if !exists {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let remains = Command::new(&prepared.ip)
            .args(["link", "show", "dev", &prepared.interface])
            .env("PATH", &prepared.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        if remains {
            let status = Command::new(&prepared.ip)
                .args(["link", "delete", "dev", &prepared.interface])
                .env("PATH", &prepared.path)
                .status()?;
            if !status.success() {
                bail!("OpenVPN tunnel interface remained after process termination");
            }
        }
        if let Some(directory) = runtime_directory {
            fs::remove_dir_all(directory).context("remove staged OpenVPN configuration")?;
        }
        Ok(())
    })();
    if let Err(error) = cleanup {
        return match restore_openvpn_connection(store, state, connection, &prepared) {
            Ok(()) => Err(error).context("OpenVPN disconnect cleanup failed; connection restored"),
            Err(rollback_error) => {
                Err(error).context(format!(
                    "OpenVPN disconnect cleanup and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = disconnected;
    Ok("disconnected".into())
}

fn connect_ikev2(
    store: &Store,
    state: &mut State,
    profile: &Profile,
    id: String,
    dry_run: bool,
) -> Result<String> {
    if dry_run {
        return Ok("charon-cmd --host <server> --identity <identity> --p12 <validated-certificate> --profile ikev2-pub\nrollback: terminate the owned IKEv2 process group".into());
    }
    let prepared = prepare_ikev2(store, profile, &state.settings, None)?;
    let (pid, runtime_directory) = start_ikev2(store, &prepared, state.settings.logging)?;
    let Some(start_ticks) = process_start_ticks(pid) else {
        let rollback = stop_and_cleanup_ikev2(&prepared, pid).and_then(|_| {
            fs::remove_dir_all(&runtime_directory).context("remove staged IKEv2 certificate")
        });
        rollback.context("IKEv2 process identity could not be read and rollback failed")?;
        bail!("IKEv2 process identity could not be read; connection rolled back");
    };
    let mut updated = state.clone();
    updated.connection = Some(Connection {
        profile_id: id,
        pid: Some(pid),
        process_start_ticks: Some(start_ticks),
        interface: Some("ipsec0".into()),
        ikev2_route: Some(Ikev2RouteIdentity {
            endpoint: prepared.endpoint.clone(),
            gateway: prepared.gateway.clone(),
            uplink: prepared.uplink.clone(),
        }),
    });
    if let Err(error) = store.save(&updated) {
        let rollback = stop_and_cleanup_ikev2(&prepared, pid).and_then(|_| {
            fs::remove_dir_all(&runtime_directory).context("remove staged IKEv2 certificate")
        });
        return match rollback {
            Ok(()) => Err(error).context("IKEv2 connection rolled back after state save failed"),
            Err(rollback_error) => {
                Err(error).context(format!(
                    "IKEv2 state save and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = updated;
    Ok("connected".into())
}

fn restore_ikev2_connection(
    store: &Store,
    state: &mut State,
    original: &Connection,
    prepared: &PreparedIkev2,
) -> Result<()> {
    let (pid, directory) = start_ikev2(store, prepared, state.settings.logging)?;
    let Some(start_ticks) = process_start_ticks(pid) else {
        stop_and_cleanup_ikev2(prepared, pid)
            .context("clean restored IKEv2 connection with unreadable process identity")?;
        fs::remove_dir_all(directory).context("remove restored IKEv2 certificate")?;
        bail!("restored IKEv2 process identity could not be read");
    };
    let mut connection = original.clone();
    connection.pid = Some(pid);
    connection.process_start_ticks = Some(start_ticks);
    let mut recovered = state.clone();
    recovered.connection = Some(connection);
    if let Err(error) = store.save(&recovered) {
        stop_and_cleanup_ikev2(prepared, pid)
            .context("clean restored IKEv2 connection after persistence failure")?;
        fs::remove_dir_all(directory).context("remove restored IKEv2 certificate")?;
        return Err(error).context("persist restored IKEv2 connection");
    }
    *state = recovered;
    Ok(())
}

fn disconnect_ikev2(
    store: &Store,
    state: &mut State,
    profile: &Profile,
    connection: &Connection,
    dry_run: bool,
) -> Result<String> {
    let pid = verify_connection_process(connection).context("verify IKEv2 process identity")?;
    let owned_route = connection
        .ikev2_route
        .as_ref()
        .context("IKEv2 connection has no persisted endpoint route identity")?;
    let prepared = prepare_ikev2(store, profile, &state.settings, Some(owned_route))?;
    let certificate = ikev2_process_certificate(pid, Some(&prepared.executable))?;
    if dry_run {
        return Ok(format!(
            "terminate owned IKEv2 process group {pid}\nrollback: restart the validated IKEv2 profile"
        ));
    }
    let mut disconnected = state.clone();
    disconnected.connection = None;
    store
        .save(&disconnected)
        .context("persist pending IKEv2 disconnect")?;
    let cleanup = stop_and_cleanup_ikev2(&prepared, pid).and_then(|_| {
        if let Some(directory) = certificate.parent() {
            fs::remove_dir_all(directory).context("remove staged IKEv2 certificate")?;
        }
        Ok(())
    });
    if let Err(error) = cleanup {
        if process_start_ticks(pid) == connection.process_start_ticks {
            store
                .save(state)
                .context("restore connected IKEv2 state after cleanup failure")?;
            return Err(error).context("IKEv2 disconnect cleanup failed; connection retained");
        }
        let _ = cleanup_ikev2_network(&prepared);
        return match restore_ikev2_connection(store, state, connection, &prepared) {
            Ok(()) => Err(error).context("IKEv2 disconnect cleanup failed; connection restored"),
            Err(rollback_error) => {
                Err(error).context(format!(
                    "IKEv2 disconnect cleanup and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = disconnected;
    Ok("disconnected".into())
}

pub fn connect(
    store: &Store,
    state: &mut State,
    profile_id: Option<&str>,
    dry_run: bool,
) -> Result<String> {
    refresh_connection(state);
    if state.connection.is_some() {
        bail!("VPN already connected");
    }
    let id = profile_id
        .map(str::to_owned)
        .or_else(|| state.default_profile.clone())
        .context("no profile selected")?;
    let profile = state
        .profiles
        .get(&id)
        .with_context(|| format!("unknown profile: {id}"))?
        .clone();
    if !profile.enabled {
        bail!("profile is disabled");
    }

    if matches!(profile.protocol, Protocol::Xray | Protocol::Shadowsocks) {
        return connect_xray(store, state, &profile, id, dry_run);
    }
    if profile.protocol == Protocol::OpenVpn {
        return connect_openvpn(store, state, &profile, id, dry_run);
    }
    if profile.protocol == Protocol::Ikev2 {
        return connect_ikev2(store, state, &profile, id, dry_run);
    }
    let plan = quick_connection_plan(&profile)?;
    if dry_run {
        return Ok(plan.display());
    }

    let prepared = prepare_network_plan(store, &profile, &plan, true)?;
    if prepared.interface_existed {
        bail!(
            "refusing to connect because interface already exists: {}",
            prepared.interface
        );
    }
    let mut command = network_command(&prepared.program, &prepared.args, &prepared);
    command.stdin(Stdio::null());
    if state.settings.logging {
        let log_path = store
            .root()
            .join("logs")
            .join(format!("connection-{}.log", uuid::Uuid::new_v4().simple()));
        let stdout = create_private_log(&log_path)?;
        let stderr = stdout.try_clone()?;
        command.stdout(stdout).stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let status = match command
        .status()
        .with_context(|| format!("run {}", plan.program))
    {
        Ok(status) => status,
        Err(error) => return fail_with_rollback(&plan, &prepared, error),
    };
    if !status.success() {
        return fail_with_rollback(
            &plan,
            &prepared,
            anyhow!("{} exited with {status}", plan.program),
        );
    }
    let connection = Connection {
        profile_id: profile.id.clone(),
        pid: None,
        process_start_ticks: None,
        interface: plan.interface.clone(),
        ikev2_route: None,
    };
    let mut updated = state.clone();
    updated.connection = Some(connection);
    if let Err(save_error) = store.save(&updated) {
        return match rollback(&plan, &prepared) {
            Ok(()) => Err(save_error).context("connection rolled back after state save failed"),
            Err(rollback_error) => {
                Err(save_error).context(format!(
                    "state save failed and tunnel rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = updated;
    Ok("connected".into())
}

pub fn disconnect(store: &Store, state: &mut State, dry_run: bool) -> Result<String> {
    let connection = state.connection.clone().context("VPN is not connected")?;
    let profile = state
        .profiles
        .get(&connection.profile_id)
        .context("connected profile is missing")?
        .clone();
    if matches!(profile.protocol, Protocol::Xray | Protocol::Shadowsocks) {
        return disconnect_xray(store, state, &profile, &connection, dry_run);
    }
    if profile.protocol == Protocol::OpenVpn {
        return disconnect_openvpn(store, state, &profile, &connection, dry_run);
    }
    if profile.protocol == Protocol::Ikev2 {
        return disconnect_ikev2(store, state, &profile, &connection, dry_run);
    }
    let process_is_valid = connection
        .pid
        .is_none_or(|pid| process_belongs_to_profile(pid, &profile));
    if !process_is_valid {
        let mut updated = state.clone();
        updated.connection = None;
        store.save(&updated)?;
        *state = updated;
        bail!("recorded VPN process is no longer running");
    }
    let plan = disconnect_plan(&profile, &connection)?;
    if dry_run {
        return Ok(plan.display());
    }
    let prepared = prepare_network_plan(store, &profile, &plan, true)?;
    if !prepared.interface_existed {
        bail!(
            "refusing to disconnect because interface does not exist: {}",
            prepared.interface
        );
    }
    let status = match network_command(&prepared.program, &prepared.args, &prepared)
        .status()
        .with_context(|| format!("run {}", plan.program))
    {
        Ok(status) => status,
        Err(error) => return fail_with_rollback(&plan, &prepared, error),
    };
    if !status.success() {
        return fail_with_rollback(
            &plan,
            &prepared,
            anyhow!("{} exited with {status}", plan.program),
        );
    }
    let mut updated = state.clone();
    updated.connection = None;
    if let Err(save_error) = store.save(&updated) {
        return match rollback(&plan, &prepared) {
            Ok(()) => Err(save_error).context("disconnect rolled back after state save failed"),
            Err(rollback_error) => {
                Err(save_error).context(format!(
                    "state save failed and disconnect rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = updated;
    Ok("disconnected".into())
}

fn disconnect_plan(profile: &Profile, connection: &Connection) -> Result<CommandPlan> {
    let spec = quick_spec(&profile.protocol)?;
    Ok(CommandPlan {
        program: spec.quick_program.into(),
        args: vec!["down".into(), profile.source.clone()],
        rollback_program: spec.quick_program.into(),
        rollback_args: vec!["up".into(), profile.source.clone()],
        interface: connection.interface.clone(),
    })
}

pub fn refresh_connection(state: &mut State) {
    if let Some(connection) = state.connection.as_mut()
        && connection.process_start_ticks.is_none()
        && let Some(pid) = connection.pid
    {
        connection.process_start_ticks = process_start_ticks(pid);
    }
    let stale = state.connection.as_ref().is_some_and(|connection| {
        let Some(profile) = state.profiles.get(&connection.profile_id) else {
            return true;
        };
        if let Some(pid) = connection.pid {
            if connection.process_start_ticks != process_start_ticks(pid) {
                return true;
            }
            if profile.protocol == Protocol::Ikev2 {
                return ikev2_process_certificate(pid, None).is_err();
            }
            if profile.protocol == Protocol::OpenVpn {
                return openvpn_process_configuration(pid, None).is_err();
            }
            if matches!(profile.protocol, Protocol::Xray | Protocol::Shadowsocks) {
                return match xray_process_info(pid) {
                    Ok(worker) => connection.interface.as_deref() != Some(&worker.interface),
                    Err(_) => true,
                };
            }
            return !process_belongs_to_profile(pid, profile);
        }
        let Some(interface) = connection.interface.as_deref() else {
            return true;
        };
        let Ok(spec) = quick_spec(&profile.protocol) else {
            return true;
        };
        match resolve_program(spec.probe_program).and_then(|executable| {
            Command::new(executable)
                .args(["show", interface])
                .status()
                .map_err(Into::into)
        }) {
            Ok(status) => !status.success(),
            Err(_) => true,
        }
    });
    if stale {
        state.connection = None;
    }
}

fn process_belongs_to_profile(pid: u32, profile: &Profile) -> bool {
    let Ok(command_line) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
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
    program_directories()
        .into_iter()
        .map(|directory| directory.join(program))
        .find(|candidate| is_executable(candidate))
        .with_context(|| format!("required executable program not found: {program}; install bundle helper or add it to PATH"))
}

fn resolve_network_program(program: &str) -> Result<PathBuf> {
    let candidates = if Path::new(program).is_absolute() {
        vec![PathBuf::from(program)]
    } else {
        network_program_directories()
            .into_iter()
            .map(|directory| directory.join(program))
            .collect()
    };
    candidates.into_iter().filter_map(|candidate| fs::canonicalize(candidate).ok()).find(|candidate| is_trusted_network_executable(candidate)).with_context(|| {
        format!("required trusted network program not found: {program}; install it in the root-owned bundle or a system program directory")
    })
}

fn network_program_directories() -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        directories.push(directory.join("libexec").join("amn"));
        directories.push(directory.join("..").join("libexec").join("amn"));
    }
    directories.extend(
        [
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ]
        .map(PathBuf::from),
    );
    directories
        .into_iter()
        .filter_map(|directory| fs::canonicalize(directory).ok())
        .filter(|directory| is_trusted_network_path(directory))
        .collect()
}

fn is_trusted_network_executable(path: &Path) -> bool {
    is_executable(path) && is_trusted_network_path(path)
}

fn is_trusted_network_path(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{
            MetadataExt,
            PermissionsExt,
        };
        path.ancestors().all(|ancestor| {
            fs::metadata(ancestor).is_ok_and(|metadata| {
                metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0
            })
        })
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn program_directories() -> Vec<PathBuf> {
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
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(protocol: Protocol) -> Profile {
        Profile {
            id: "p".into(),
            name: "test".into(),
            protocol,
            source: "/vpn/test.conf".into(),
            enabled: true,
        }
    }

    #[test]
    fn endpoint_output_matches_host_and_host_cidr_forms() {
        assert!(output_has_endpoint(
            b"186: from all to 192.0.2.10 lookup main",
            "192.0.2.10"
        ));
        assert!(output_has_endpoint(
            b"dst 192.0.2.10/32 tmpl src 10.0.0.2",
            "192.0.2.10"
        ));
        assert!(!output_has_endpoint(
            b"186: from all to 192.0.2.100 lookup main",
            "192.0.2.10"
        ));
    }

    #[test]
    fn network_plans_always_include_opposite_rollback() {
        let connect = quick_connection_plan(&profile(Protocol::WireGuard)).unwrap();
        assert_eq!(connect.args.first().map(String::as_str), Some("up"));
        assert_eq!(
            connect.rollback_args.first().map(String::as_str),
            Some("down")
        );

        let connection = Connection {
            profile_id: "p".into(),
            pid: None,
            process_start_ticks: None,
            interface: Some("test".into()),
            ikev2_route: None,
        };
        let disconnect = disconnect_plan(&profile(Protocol::WireGuard), &connection).unwrap();
        assert_eq!(disconnect.args.first().map(String::as_str), Some("down"));
        assert_eq!(
            disconnect.rollback_args.first().map(String::as_str),
            Some("up")
        );
    }

    #[test]
    fn configuration_dependencies_are_detected() {
        let configuration = "[Interface]\nDNS = 1.1.1.1 # resolver\n[Peer]\nAllowedIPs = 10.0.0.0/8, 0:0:0:0:0:0:0:0/0 # default\n";
        assert!(configuration_has_key(configuration, "dns"));
        assert!(configuration_has_default_route(configuration));
        assert!(!configuration_has_default_route(
            "AllowedIPs = 10.0.0.0/8 # ::/0"
        ));
    }

    #[test]
    fn rollback_only_restores_changed_interface_ownership_state() {
        assert_eq!(rollback_strategy(false, false), RollbackStrategy::None);
        assert_eq!(rollback_strategy(false, true), RollbackStrategy::Opposite);
        assert_eq!(rollback_strategy(true, false), RollbackStrategy::Opposite);
        assert_eq!(
            rollback_strategy(true, true),
            RollbackStrategy::NormalizeThenOpposite
        );

        let expected = vec!["peer-a".to_owned(), "peer-b".to_owned()];
        assert!(peer_sets_match(&expected, ["peer-b", "peer-a"].into_iter()));
        assert!(!peer_sets_match(&expected, ["peer-a"].into_iter()));
        assert!(!peer_sets_match(
            &expected,
            ["peer-a", "peer-b", "peer-c"].into_iter()
        ));
    }

    #[test]
    fn xray_route_modes_generate_distinct_reversible_routes() {
        let prepared = |route_mode, split_routes| {
            PreparedXray {
                configuration: String::new(),
                endpoint: "192.0.2.1".into(),
                endpoint_port: 443,
                gateway: "192.0.2.254".into(),
                uplink: "eth0".into(),
                executable: "/bundle/xray".into(),
                tun2socks: "/bundle/tun2socks".into(),
                setsid: "/usr/bin/setsid".into(),
                kill: "/usr/bin/kill".into(),
                ip: "/usr/bin/ip".into(),
                path: "/usr/bin".into(),
                route_mode,
                split_routes,
            }
        };
        let only = prepared(
            crate::core::model::RouteMode::OnlyListed,
            vec![crate::core::routing::Network::parse("10.4.3.2/8").unwrap()],
        );
        let only_pairs = traffic_route_pairs(&only, "amnxray0");
        assert_eq!(only_pairs.len(), 1);
        assert!(only_pairs[0].0.contains(&"10.0.0.0/8".into()));
        assert!(!only_pairs[0].0.contains(&"0.0.0.0/1".into()));

        let except = prepared(
            crate::core::model::RouteMode::ExceptListed,
            vec![crate::core::routing::Network::parse("10.0.0.0/8").unwrap()],
        );
        let except_pairs = traffic_route_pairs(&except, "amnxray0");
        assert!(
            except_pairs
                .iter()
                .any(|(forward, _)| forward.contains(&"0.0.0.0/1".into()))
        );
        assert!(except_pairs.iter().any(|(forward, _)| {
            forward.contains(&"10.0.0.0/8".into()) && forward.contains(&"eth0".into())
        }));
        assert!(
            except_pairs
                .iter()
                .all(|(_, reverse)| reverse.iter().any(|argument| argument == "delete"))
        );
    }

    #[test]
    fn process_identity_uses_kernel_start_ticks() {
        let pid = std::process::id();
        let ticks = process_start_ticks(pid).expect("current process has start ticks");
        let connection = Connection {
            profile_id: "p".into(),
            pid: Some(pid),
            process_start_ticks: Some(ticks),
            interface: None,
            ikev2_route: None,
        };
        assert_eq!(verify_connection_process(&connection).unwrap(), pid);
        let mut mismatch = connection;
        mismatch.process_start_ticks = Some(ticks.saturating_add(1));
        assert!(verify_connection_process(&mismatch).is_err());
    }

    #[test]
    fn root_network_command_uses_validated_dependency_environment() {
        let prepared = PreparedPlan {
            program: "/tools/wg-quick".into(),
            rollback_program: "/tools/wg-quick".into(),
            args: Vec::new(),
            rollback_args: Vec::new(),
            path: "/bundle:/usr/bin".into(),
            interface_probe: "/tools/wg".into(),
            interface: "amn0".into(),
            interface_existed: false,
            expected_peer_keys: vec!["peer".into()],
            runtime_directory: None,
            quick_base_created: false,
            backend_environment: Some((
                "WG_QUICK_USERSPACE_IMPLEMENTATION".into(),
                "/tools/wireguard-go".into(),
            )),
        };
        let command = network_command(
            &prepared.program,
            &["up".into(), "/vpn/amn0.conf".into()],
            &prepared,
        );
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let environment = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            environment.get("PATH").and_then(Option::as_deref),
            Some("/bundle:/usr/bin")
        );
        assert_eq!(
            environment
                .get("WG_QUICK_USERSPACE_IMPLEMENTATION")
                .and_then(Option::as_deref),
            Some("/tools/wireguard-go")
        );
        assert_eq!(arguments.first().map(String::as_str), Some("up"));
        assert_eq!(arguments.last().map(String::as_str), Some("/vpn/amn0.conf"));
    }
}
