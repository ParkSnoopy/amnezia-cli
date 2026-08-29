use crate::core::model::{Connection, Profile, Protocol, Settings, State};
use crate::core::store::Store;
use anyhow::{Context, Result, anyhow, bail};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPlan {
    pub program: String,
    pub args: Vec<String>,
    pub rollback_program: String,
    pub rollback_args: Vec<String>,
    pub interface: Option<String>,
}

impl CommandPlan {
    pub fn display(&self) -> String {
        format!("{}\nrollback: {}", format_command(&self.program, &self.args), format_command(&self.rollback_program, &self.rollback_args))
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
            rollback_program: "wg-quick".into(),
            rollback_args: vec!["down".into(), profile.source.clone()],
            interface: Some(interface_name(&profile.source)),
        },
        Protocol::AmneziaWg => CommandPlan {
            program: "awg-quick".into(),
            args: vec!["up".into(), source],
            rollback_program: "awg-quick".into(),
            rollback_args: vec!["down".into(), profile.source.clone()],
            interface: Some(interface_name(&profile.source)),
        },
        Protocol::Xray => bail!("XRay connection requires bundled XRay and tun2socks backend integration"),
        Protocol::Shadowsocks => bail!("Shadowsocks connection requires bundled tun2socks backend integration"),
        Protocol::Ikev2 => bail!("IKEv2 connection requires privileged platform backend integration"),
        Protocol::Amnezia => bail!("Amnezia full-access bundle must be exported to a native protocol before connection"),
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
    backend_environment: Option<(String, PathBuf)>,
}

impl Drop for PreparedPlan {
    fn drop(&mut self) {
        if let Some(directory) = &self.runtime_directory {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

fn prepare_network_plan(store: &Store, profile: &Profile, plan: &CommandPlan, stage_profile: bool) -> Result<PreparedPlan> {
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
    let (kernel_backend, interface_probe) = match profile.protocol {
        Protocol::WireGuard => {
            let probe = resolve_network_program("wg")?;
            (Some(("wireguard", "WG_QUICK_USERSPACE_IMPLEMENTATION", "wireguard-go")), probe)
        }
        Protocol::AmneziaWg => {
            let probe = resolve_network_program("awg")?;
            (Some(("amneziawg", "WG_QUICK_USERSPACE_IMPLEMENTATION", "amneziawg-go")), probe)
        }
        _ => bail!("protocol does not use a supported network interface backend"),
    };
    if configuration_has_key(&configuration, "DNS") {
        resolve_network_program("resolvconf")?;
    }
    if configuration_has_default_route(&configuration) {
        resolve_network_program("sysctl")?;
        let nft_available = resolve_network_program("nft").is_ok();
        let iptables_available = resolve_network_program("iptables").is_ok();
        if iptables_available {
            for dependency in ["ip6tables", "iptables-save", "ip6tables-save", "iptables-restore", "ip6tables-restore"] {
                resolve_network_program(dependency)?;
            }
        }
        if !nft_available && !iptables_available {
            bail!("default-route profile requires nft or iptables firewall tools");
        }
    }
    let path = std::env::join_paths(network_program_directories()).context("construct dependency PATH")?;

    let backend_environment = kernel_backend
        .map(|(module, fallback_variable, default_fallback)| {
            require_kernel_backend(module, fallback_variable, default_fallback, &path)
        })
        .transpose()?
        .flatten();
    let interface = plan.interface.clone().context("network plan has no interface")?;
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
    let (args, rollback_args, runtime_directory) = if stage_profile {
        if effective_user_id() != Some(0) {
            bail!("VPN interface changes require running amn as root");
        }
        let directory = create_root_runtime_directory()?;
        let file_name = Path::new(&profile.source).file_name().context("profile source has no filename")?;
        let staged = directory.join(file_name);
        if let Err(error) = crate::core::store::write_private(&staged, configuration.as_bytes()) {
            let _ = fs::remove_dir_all(&directory);
            return Err(error).context("stage validated VPN profile");
        }
        let staged = staged.to_string_lossy().into_owned();
        (
            replace_profile_argument(&plan.args, &profile.source, &staged),
            replace_profile_argument(&plan.rollback_args, &profile.source, &staged),
            Some(directory),
        )
    } else {
        (plan.args.clone(), plan.rollback_args.clone(), None)
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
        backend_environment,
    })
}

pub fn check_profile_dependencies(store: &Store, profile: &Profile, settings: &Settings) -> Result<()> {
    if profile.protocol == Protocol::Xray {
        prepare_xray(store, profile, settings)?;
        return Ok(());
    }
    let plan = connection_plan(profile, settings)?;
    prepare_network_plan(store, profile, &plan, false)?;
    Ok(())
}

fn configuration_has_key(configuration: &str, expected: &str) -> bool {
    configuration.lines().filter_map(|line| line.split_once('=')).any(|(key, value)| {
        key.trim().eq_ignore_ascii_case(expected) && !configuration_value(value).is_empty()
    })
}

fn configuration_values(configuration: &str, expected: &str) -> Vec<String> {
    configuration.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        let value = configuration_value(value);
        (key.trim().eq_ignore_ascii_case(expected) && !value.is_empty()).then(|| value.to_owned())
    }).collect()
}

fn configuration_has_default_route(configuration: &str) -> bool {
    configuration.lines().filter_map(|line| line.split_once('=')).any(|(key, value)| {
        key.trim().eq_ignore_ascii_case("AllowedIPs")
            && configuration_value(value).split(',').any(is_default_route)
    })
}

fn configuration_value(value: &str) -> &str {
    value.split('#').next().unwrap_or_default().trim()
}

fn is_default_route(route: &str) -> bool {
    let Some((address, prefix)) = route.trim().split_once('/') else { return false };
    prefix.trim() == "0"
        && address.trim().parse::<std::net::IpAddr>().is_ok_and(|address| address.is_unspecified())
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
    let interface_exists_now = interface_exists(&prepared.interface_probe, &prepared.interface, &prepared.path)?;
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
        bail!("refusing rollback because interface ownership is ambiguous: {}", prepared.interface);
    }
    if strategy == RollbackStrategy::NormalizeThenOpposite {
        let status = network_command(&prepared.program, &prepared.args, prepared)
            .status()
            .with_context(|| format!("normalize failed {} before rollback", plan.program))?;
        if !status.success() {
            bail!("rollback normalization {} exited with {status}", plan.program);
        }
    }
    let status = network_command(&prepared.rollback_program, &prepared.rollback_args, prepared)
        .status()
        .with_context(|| format!("run rollback {}", plan.rollback_program))?;
    if !status.success() {
        bail!("rollback {} exited with {status}", plan.rollback_program);
    }
    Ok(())
}

fn rollback_strategy(interface_existed_before: bool, interface_exists_now: bool) -> RollbackStrategy {
    match (interface_existed_before, interface_exists_now) {
        (false, false) => RollbackStrategy::None,
        (true, true) => RollbackStrategy::NormalizeThenOpposite,
        _ => RollbackStrategy::Opposite,
    }
}

fn network_command(program: &Path, arguments: &[String], prepared: &PreparedPlan) -> Command {
    const BACKEND_VARIABLES: [&str; 2] = ["WG_QUICK_USERSPACE_IMPLEMENTATION", "AWG_QUICK_USERSPACE_IMPLEMENTATION"];
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

fn interface_matches_profile(probe: &Path, interface: &str, expected_peers: &[String], path: &std::ffi::OsStr) -> Result<bool> {
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
    let expected = expected.iter().map(|peer| peer.trim()).collect::<std::collections::BTreeSet<_>>();
    let actual = actual.map(str::trim).filter(|peer| !peer.is_empty()).collect::<std::collections::BTreeSet<_>>();
    expected == actual
}

fn replace_profile_argument(arguments: &[String], source: &str, staged: &str) -> Vec<String> {
    arguments.iter().map(|argument| if argument == source { staged.to_owned() } else { argument.clone() }).collect()
}

fn effective_user_id() -> Option<u32> {
    fs::read_to_string("/proc/self/status").ok()?.lines().find_map(|line| {
        line.strip_prefix("Uid:")?.split_whitespace().nth(1)?.parse().ok()
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

fn create_root_runtime_directory() -> Result<PathBuf> {
    let base = Path::new("/run/amn");
    match fs::create_dir(base) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(base, fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create root VPN runtime directory"),
    }
    let canonical = fs::canonicalize(base).context("inspect root VPN runtime directory")?;
    if canonical != base {
        bail!("root VPN runtime directory resolves outside /run/amn");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::metadata(base)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o777 != 0o700 {
            bail!("root VPN runtime directory must be root-owned with mode 0700");
        }
    }
    let directory = base.join(uuid::Uuid::new_v4().simple().to_string());
    create_private_directory(&directory)?;
    Ok(directory)
}

fn fail_with_rollback<T>(plan: &CommandPlan, prepared: &PreparedPlan, failure: anyhow::Error) -> Result<T> {
    match rollback(plan, prepared) {
        Ok(()) => Err(failure).context("network action failed; rollback completed"),
        Err(rollback_error) => Err(failure).context(format!("network action failed and rollback failed: {rollback_error:#}")),
    }
}

struct PreparedXray {
    configuration: String,
    endpoint: String,
    gateway: String,
    uplink: String,
    executable: PathBuf,
    tun2socks: PathBuf,
    setsid: PathBuf,
    kill: PathBuf,
    ip: PathBuf,
    path: std::ffi::OsString,
}

fn prepare_xray(store: &Store, profile: &Profile, settings: &Settings) -> Result<PreparedXray> {
    if settings.route_mode != crate::core::model::RouteMode::All {
        bail!("raw XRay currently requires all-traffic routing mode");
    }
    let raw = crate::core::xray::RawConfiguration::parse(&store.validated_profile_text(profile)?)?;
    let endpoint = raw.endpoint_ipv4()?;
    let configuration = raw.render_for_endpoint(endpoint)?;
    let executable = resolve_network_program("amnezia-xray-runner")?;
    let runner_status = Command::new(&executable).arg("--check").status().context("check bundled XRay runner")?;
    if !runner_status.success() {
        bail!("bundled XRay runner failed its dependency check");
    }
    let tun2socks = resolve_network_program("tun2socks")?;
    let setsid = resolve_network_program("setsid")?;
    let kill = resolve_network_program("kill")?;
    let ip = resolve_network_program("ip")?;
    let path = std::env::join_paths(network_program_directories()).context("construct XRay dependency PATH")?;
    let route = Command::new(&ip).args(["route", "get", &endpoint.to_string()]).env("PATH", &path).output()
        .context("inspect route to XRay endpoint")?;
    if !route.status.success() {
        bail!("cannot determine route to XRay endpoint");
    }
    let route = String::from_utf8(route.stdout).context("XRay endpoint route is not UTF-8")?;
    let fields = route.split_whitespace().collect::<Vec<_>>();
    let uplink = route_field(&fields, "dev").context("XRay endpoint route has no uplink interface")?.to_owned();
    let gateway = route_field(&fields, "via").unwrap_or("-").to_owned();
    Ok(PreparedXray {
        configuration,
        endpoint: endpoint.to_string(),
        gateway,
        uplink,
        executable,
        tun2socks,
        setsid,
        kill,
        ip,
        path,
    })
}

fn route_field<'a>(fields: &'a [&str], name: &str) -> Option<&'a str> {
    fields.windows(2).find_map(|pair| (pair.first().copied() == Some(name)).then(|| pair[1]))
}

fn xray_ip_command(prepared: &PreparedXray, arguments: &[String]) -> Result<()> {
    let status = Command::new(&prepared.ip).args(arguments).env("PATH", &prepared.path).status()
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
    let mut arguments = vec!["route".into(), action.into(), format!("{}/32", prepared.endpoint)];
    if prepared.gateway != "-" {
        arguments.extend(["via".into(), prepared.gateway.clone()]);
    }
    arguments.extend(["dev".into(), prepared.uplink.clone(), "proto".into(), "66".into()]);
    arguments
}

fn start_xray_worker(store: &Store, prepared: &PreparedXray, interface: &str, logging: bool) -> Result<u32> {
    if effective_user_id() != Some(0) {
        bail!("XRay interface changes require running amn as root");
    }
    let directory = create_root_runtime_directory()?;
    let configuration = directory.join("xray.json");
    if let Err(error) = crate::core::store::write_private(&configuration, prepared.configuration.as_bytes()) {
        let _ = fs::remove_dir_all(&directory);
        return Err(error).context("stage normalized XRay configuration");
    }
    let mut command = Command::new(&prepared.setsid);
    command.args([
        prepared.executable.as_os_str(),
        configuration.as_os_str(),
        prepared.tun2socks.as_os_str(),
        std::ffi::OsStr::new(interface),
        std::ffi::OsStr::new(&prepared.endpoint),
        std::ffi::OsStr::new(&prepared.gateway),
        std::ffi::OsStr::new(&prepared.uplink),
    ]).env("PATH", &prepared.path).stdin(Stdio::null());
    if logging {
        let log_path = store.root().join("logs").join(format!("connection-{}.log", uuid::Uuid::new_v4().simple()));
        let stdout = create_private_log(&log_path)?;
        command.stdout(stdout.try_clone()?).stderr(stdout);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let mut child = command.spawn().context("start isolated XRay worker")?;
    for _ in 0..50 {
        if let Some(status) = child.try_wait()? {
            let _ = fs::remove_dir_all(&directory);
            bail!("XRay worker exited during startup with {status}");
        }
        let exists = Command::new(&prepared.ip).args(["link", "show", "dev", interface]).env("PATH", &prepared.path)
            .stdout(Stdio::null()).stderr(Stdio::null()).status()?.success();
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
    let status = Command::new(&prepared.kill).args(["-TERM", "--", &format!("-{pid}")]).env("PATH", &prepared.path).status()
        .context("stop XRay worker process group")?;
    if !status.success() {
        bail!("stop XRay worker exited with {status}");
    }
    for _ in 0..30 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("XRay worker did not stop")
}

fn configure_xray_interface(prepared: &PreparedXray, interface: &str, rollback: &mut Vec<Vec<String>>) -> Result<()> {
    apply_xray_mutation(prepared,
        vec!["address".into(), "add".into(), "10.33.0.2/24".into(), "dev".into(), interface.into()],
        vec!["address".into(), "delete".into(), "10.33.0.2/24".into(), "dev".into(), interface.into()], rollback)?;
    apply_xray_mutation(prepared,
        vec!["link".into(), "set".into(), "dev".into(), interface.into(), "up".into()],
        vec!["link".into(), "set".into(), "dev".into(), interface.into(), "down".into()], rollback)?;
    apply_xray_mutation(prepared, endpoint_route_arguments(prepared, "add"), endpoint_route_arguments(prepared, "delete"), rollback)?;
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        apply_xray_mutation(prepared,
            vec!["route".into(), "add".into(), prefix.into(), "dev".into(), interface.into(), "proto".into(), "66".into()],
            vec!["route".into(), "delete".into(), prefix.into(), "dev".into(), interface.into(), "proto".into(), "66".into()], rollback)?;
    }
    apply_xray_mutation(prepared,
        vec!["-6".into(), "route".into(), "add".into(), "unreachable".into(), "::/0".into(), "proto".into(), "66".into(), "metric".into(), "42760".into()],
        vec!["-6".into(), "route".into(), "delete".into(), "unreachable".into(), "::/0".into(), "proto".into(), "66".into(), "metric".into(), "42760".into()], rollback)?;
    Ok(())
}

fn rollback_xray_connect(prepared: &PreparedXray, pid: u32, interface: &str, rollback: &mut Vec<Vec<String>>) -> Result<()> {
    let mut failures = Vec::new();
    while let Some(arguments) = rollback.pop() {
        if let Err(error) = xray_ip_command(prepared, &arguments) {
            failures.push(format!("{error:#}"));
        }
    }
    if let Err(error) = stop_xray_worker(prepared, pid) {
        failures.push(format!("{error:#}"));
    }
    let delete = vec!["link".into(), "delete".into(), "dev".into(), interface.into()];
    let _ = xray_ip_command(prepared, &delete);
    if failures.is_empty() { Ok(()) } else { bail!("{}", failures.join("; ")) }
}

fn connect_xray(store: &Store, state: &mut State, profile: &Profile, id: String, dry_run: bool) -> Result<String> {
    if dry_run {
        return Ok("amnezia-xray-runner <validated-config> <tun2socks> amnxray0 <endpoint> <gateway> <uplink>\nrollback: ip route/address/link delete; terminate XRay worker process group".into());
    }
    let prepared = prepare_xray(store, profile, &state.settings)?;
    let interface = "amnxray0";
    let existing = Command::new(&prepared.ip).args(["link", "show", "dev", interface]).env("PATH", &prepared.path)
        .stdout(Stdio::null()).stderr(Stdio::null()).status()?.success();
    if existing {
        bail!("refusing to connect because interface already exists: {interface}");
    }
    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
        let output = Command::new(&prepared.ip).args(["route", "show", prefix]).env("PATH", &prepared.path).output()?;
        if !output.status.success() || !output.stdout.is_empty() {
            bail!("refusing to replace existing route: {prefix}");
        }
    }
    let pid = start_xray_worker(store, &prepared, interface, state.settings.logging)?;
    let mut rollback = Vec::new();
    let mutation = configure_xray_interface(&prepared, interface, &mut rollback);
    if let Err(error) = mutation {
        return match rollback_xray_connect(&prepared, pid, interface, &mut rollback) {
            Ok(()) => Err(error).context("XRay connection failed; rollback completed"),
            Err(rollback_error) => Err(error).context(format!("XRay connection and rollback failed: {rollback_error:#}")),
        };
    }
    let mut updated = state.clone();
    updated.connection = Some(Connection {
        profile_id: id,
        pid: Some(pid),
        interface: Some(interface.into()),
        started_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    });
    if let Err(error) = store.save(&updated) {
        return match rollback_xray_connect(&prepared, pid, interface, &mut rollback) {
            Ok(()) => Err(error).context("XRay connection rolled back after state save failed"),
            Err(rollback_error) => Err(error).context(format!("XRay state save and rollback failed: {rollback_error:#}")),
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
    let executable = fs::canonicalize(format!("/proc/{pid}/exe")).context("resolve XRay worker executable")?;
    if executable.file_name() != Some(std::ffi::OsStr::new("amnezia-xray-runner")) || !is_trusted_network_executable(&executable) {
        bail!("recorded process is not a trusted XRay worker");
    }
    let command_line = fs::read(format!("/proc/{pid}/cmdline")).context("read XRay worker command line")?;
    let arguments = command_line.split(|byte| *byte == 0).filter(|argument| !argument.is_empty()).collect::<Vec<_>>();
    let values = arguments.get(1..7).context("XRay worker command line is incomplete")?;
    Ok(XrayProcessInfo {
        interface: String::from_utf8(values[2].to_vec()).context("XRay interface is not UTF-8")?,
        endpoint: String::from_utf8(values[3].to_vec()).context("XRay endpoint is not UTF-8")?,
        gateway: String::from_utf8(values[4].to_vec()).context("XRay gateway is not UTF-8")?,
        uplink: String::from_utf8(values[5].to_vec()).context("XRay uplink is not UTF-8")?,
    })
}

fn process_is_running(pid: u32) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else { return false };
    stat.rsplit_once(") ").and_then(|(_, suffix)| suffix.chars().next()).is_some_and(|state| state != 'Z')
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
    let mut restored = original.clone();
    if process_alive {
        while let Some(arguments) = route_rollback.pop() {
            xray_ip_command(prepared, &arguments)?;
        }
    } else {
        let delete = vec!["link".into(), "delete".into(), "dev".into(), original.interface.clone().context("XRay connection has no interface")?];
        let _ = xray_ip_command(prepared, &delete);
        let interface = original.interface.as_deref().context("XRay connection has no interface")?;
        let pid = start_xray_worker(store, prepared, interface, state.settings.logging)?;
        let mut rollback = Vec::new();
        if let Err(error) = configure_xray_interface(prepared, interface, &mut rollback) {
            let _ = rollback_xray_connect(prepared, pid, interface, &mut rollback);
            return Err(error).context("restore XRay network after failed disconnect");
        }
        restored.pid = Some(pid);
    }
    let mut recovered = state.clone();
    recovered.connection = Some(restored);
    store.save(&recovered).context("restore XRay connection state")?;
    *state = recovered;
    let _ = profile;
    Ok(())
}

fn disconnect_xray(store: &Store, state: &mut State, profile: &Profile, connection: &Connection, dry_run: bool) -> Result<String> {
    let pid = connection.pid.context("XRay connection has no worker PID")?;
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
    store.save(&disconnected).context("persist pending XRay disconnect")?;

    let mut route_rollback = Vec::new();
    let operation = (|| -> Result<()> {
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            apply_xray_mutation(&prepared,
                vec!["route".into(), "delete".into(), prefix.into(), "dev".into(), info.interface.clone(), "proto".into(), "66".into()],
                vec!["route".into(), "add".into(), prefix.into(), "dev".into(), info.interface.clone(), "proto".into(), "66".into()], &mut route_rollback)?;
        }
        apply_xray_mutation(&prepared,
            vec!["-6".into(), "route".into(), "delete".into(), "unreachable".into(), "::/0".into(), "proto".into(), "66".into(), "metric".into(), "42760".into()],
            vec!["-6".into(), "route".into(), "add".into(), "unreachable".into(), "::/0".into(), "proto".into(), "66".into(), "metric".into(), "42760".into()], &mut route_rollback)?;
        apply_xray_mutation(&prepared, endpoint_route_arguments(&prepared, "delete"), endpoint_route_arguments(&prepared, "add"), &mut route_rollback)?;
        stop_xray_worker(&prepared, pid)?;
        let exists = Command::new(&prepared.ip).args(["link", "show", "dev", &info.interface]).env("PATH", &prepared.path)
            .stdout(Stdio::null()).stderr(Stdio::null()).status()?.success();
        if exists {
            xray_ip_command(&prepared, &["link".into(), "delete".into(), "dev".into(), info.interface.clone()])?;
        }
        Ok(())
    })();
    if let Err(error) = operation {
        let process_alive = process_is_running(pid);
        return match restore_xray_disconnect(store, state, profile, connection, &prepared, process_alive, route_rollback) {
            Ok(()) => Err(error).context("XRay disconnect failed; rollback completed"),
            Err(rollback_error) => Err(error).context(format!("XRay disconnect and rollback failed: {rollback_error:#}")),
        };
    }
    *state = disconnected;
    Ok("disconnected".into())
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
    if profile.protocol == Protocol::Xray {
        return connect_xray(store, state, &profile, id, dry_run);
    }
    let plan = connection_plan(&profile, &state.settings)?;
    if dry_run {
        return Ok(plan.display());
    }

    let prepared = prepare_network_plan(store, &profile, &plan, true)?;
    if prepared.interface_existed {
        bail!("refusing to connect because interface already exists: {}", prepared.interface);
    }
    let mut command = network_command(&prepared.program, &prepared.args, &prepared);
    command.stdin(Stdio::null());
    if state.settings.logging {
        let log_path = store.root().join("logs").join(format!("connection-{}.log", uuid::Uuid::new_v4().simple()));
        let stdout = create_private_log(&log_path)?;
        let stderr = stdout.try_clone()?;
        command.stdout(stdout).stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let status = match command.status().with_context(|| format!("run {}", plan.program)) {
        Ok(status) => status,
        Err(error) => return fail_with_rollback(&plan, &prepared, error),
    };
    if !status.success() {
        return fail_with_rollback(&plan, &prepared, anyhow!("{} exited with {status}", plan.program));
    }
    let connection = Connection {
        profile_id: id,
        pid: None,
        interface: plan.interface.clone(),
        started_unix_seconds: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    };
    let mut updated = state.clone();
    updated.connection = Some(connection);
    if let Err(save_error) = store.save(&updated) {
        return match rollback(&plan, &prepared) {
            Ok(()) => Err(save_error).context("connection rolled back after state save failed"),
            Err(rollback_error) => Err(save_error).context(format!("state save failed and tunnel rollback failed: {rollback_error:#}")),
        };
    }
    *state = updated;
    Ok("connected".into())
}

pub fn disconnect(store: &Store, state: &mut State, dry_run: bool) -> Result<String> {
    let connection = state.connection.clone().context("VPN is not connected")?;
    let profile = state.profiles.get(&connection.profile_id).context("connected profile is missing")?.clone();
    if profile.protocol == Protocol::Xray {
        return disconnect_xray(store, state, &profile, &connection, dry_run);
    }
    let process_is_valid = connection.pid.is_none_or(|pid| process_belongs_to_profile(pid, &profile));
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
        bail!("refusing to disconnect because interface does not exist: {}", prepared.interface);
    }
    let status = match network_command(&prepared.program, &prepared.args, &prepared)
        .status()
        .with_context(|| format!("run {}", plan.program))
    {
        Ok(status) => status,
        Err(error) => return fail_with_rollback(&plan, &prepared, error),
    };
    if !status.success() {
        return fail_with_rollback(&plan, &prepared, anyhow!("{} exited with {status}", plan.program));
    }
    let mut updated = state.clone();
    updated.connection = None;
    if let Err(save_error) = store.save(&updated) {
        return match rollback(&plan, &prepared) {
            Ok(()) => Err(save_error).context("disconnect rolled back after state save failed"),
            Err(rollback_error) => Err(save_error).context(format!("state save failed and disconnect rollback failed: {rollback_error:#}")),
        };
    }
    *state = updated;
    Ok("disconnected".into())
}

fn disconnect_plan(profile: &Profile, connection: &Connection) -> Result<CommandPlan> {
    match profile.protocol {
        Protocol::WireGuard => Ok(CommandPlan {
            program: "wg-quick".into(),
            args: vec!["down".into(), profile.source.clone()],
            rollback_program: "wg-quick".into(),
            rollback_args: vec!["up".into(), profile.source.clone()],
            interface: connection.interface.clone(),
        }),
        Protocol::AmneziaWg => Ok(CommandPlan {
            program: "awg-quick".into(),
            args: vec!["down".into(), profile.source.clone()],
            rollback_program: "awg-quick".into(),
            rollback_args: vec!["up".into(), profile.source.clone()],
            interface: connection.interface.clone(),
        }),
        _ => bail!("connected protocol has no supported rollback-safe disconnect backend"),
    }
}

pub fn refresh_connection(state: &mut State) {
    let stale = state.connection.as_ref().is_some_and(|connection| {
        let Some(profile) = state.profiles.get(&connection.profile_id) else { return true };
        if let Some(pid) = connection.pid {
            if profile.protocol == Protocol::Xray {
                return match xray_process_info(pid) {
                    Ok(worker) => connection.interface.as_deref() != Some(&worker.interface),
                    Err(_) => true,
                };
            }
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
        network_program_directories().into_iter().map(|directory| directory.join(program)).collect()
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
    directories.extend(["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"].map(PathBuf::from));
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
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    let Ok(metadata) = fs::metadata(path) else { return false };
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

    #[test]
    fn network_plans_always_include_opposite_rollback() {
        let connect = connection_plan(&profile(Protocol::WireGuard), &Settings::default()).unwrap();
        assert_eq!(connect.args.first().map(String::as_str), Some("up"));
        assert_eq!(connect.rollback_args.first().map(String::as_str), Some("down"));

        let connection = Connection {
            profile_id: "p".into(),
            pid: None,
            interface: Some("test".into()),
            started_unix_seconds: 0,
        };
        let disconnect = disconnect_plan(&profile(Protocol::WireGuard), &connection).unwrap();
        assert_eq!(disconnect.args.first().map(String::as_str), Some("down"));
        assert_eq!(disconnect.rollback_args.first().map(String::as_str), Some("up"));
    }

    #[test]
    fn configuration_dependencies_are_detected() {
        let configuration = "[Interface]\nDNS = 1.1.1.1 # resolver\n[Peer]\nAllowedIPs = 10.0.0.0/8, 0:0:0:0:0:0:0:0/0 # default\n";
        assert!(configuration_has_key(configuration, "dns"));
        assert!(configuration_has_default_route(configuration));
        assert!(!configuration_has_default_route("AllowedIPs = 10.0.0.0/8 # ::/0"));
    }

    #[test]
    fn rollback_only_restores_changed_interface_ownership_state() {
        assert_eq!(rollback_strategy(false, false), RollbackStrategy::None);
        assert_eq!(rollback_strategy(false, true), RollbackStrategy::Opposite);
        assert_eq!(rollback_strategy(true, false), RollbackStrategy::Opposite);
        assert_eq!(rollback_strategy(true, true), RollbackStrategy::NormalizeThenOpposite);

        let expected = vec!["peer-a".to_owned(), "peer-b".to_owned()];
        assert!(peer_sets_match(&expected, ["peer-b", "peer-a"].into_iter()));
        assert!(!peer_sets_match(&expected, ["peer-a"].into_iter()));
        assert!(!peer_sets_match(&expected, ["peer-a", "peer-b", "peer-c"].into_iter()));
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
            backend_environment: Some(("WG_QUICK_USERSPACE_IMPLEMENTATION".into(), "/tools/wireguard-go".into())),
        };
        let command = network_command(&prepared.program, &["up".into(), "/vpn/amn0.conf".into()], &prepared);
        let arguments = command.get_args().map(|argument| argument.to_string_lossy().into_owned()).collect::<Vec<_>>();
        let environment = command.get_envs().map(|(key, value)| {
            (key.to_string_lossy().into_owned(), value.map(|value| value.to_string_lossy().into_owned()))
        }).collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(environment.get("PATH").and_then(Option::as_deref), Some("/bundle:/usr/bin"));
        assert_eq!(environment.get("WG_QUICK_USERSPACE_IMPLEMENTATION").and_then(Option::as_deref), Some("/tools/wireguard-go"));
        assert_eq!(arguments.first().map(String::as_str), Some("up"));
        assert_eq!(arguments.last().map(String::as_str), Some("/vpn/amn0.conf"));
    }
}
