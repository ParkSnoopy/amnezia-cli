#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPlan {
    mutation: ReversibleMutation,
    pub interface: Option<String>,
}

pub(crate) struct QuickSpec {
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

fn quick_program(protocol: &Protocol) -> Result<QuickProgram> {
    match protocol {
        Protocol::WireGuard => Ok(QuickProgram::WireGuard),
        Protocol::AmneziaWg => Ok(QuickProgram::AmneziaWg),
        _ => bail!("protocol does not use a quick-script backend"),
    }
}

type QuickCommand = (&'static str, Vec<String>);

impl CommandPlan {
    fn commands(&self) -> (QuickCommand, QuickCommand) {
        let (apply, reverse) = self.mutation.quick_pair();
        (apply.command(), reverse.command())
    }

    fn program(&self) -> &'static str {
        self.mutation.quick_pair().0.program().executable()
    }

    fn rollback_program(&self) -> &'static str {
        self.mutation.quick_pair().1.program().executable()
    }

    pub fn display(&self) -> String {
        let ((program, args), (rollback_program, rollback_args)) = self.commands();
        format!(
            "{}\nrollback: {}",
            format_command(program, &args),
            format_command(rollback_program, &rollback_args)
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
            CommandPlan {
                mutation: ReversibleMutation::quick(
                    quick_program(&profile.protocol)?,
                    QuickDirection::Up,
                    source,
                ),
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
    ip: PathBuf,
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
    settings: &Settings,
    stage_profile: bool,
) -> Result<PreparedPlan> {
    let configuration = effective_quick_configuration(
        &store.validated_profile_text(profile)?,
        settings,
    )?;
    let recipe = super::prepare_protocol(
        &profile.protocol,
        &configuration,
        settings,
    )?;
    let super::ProtocolRecipe::Quick(recipe_program) = recipe else {
        bail!("quick connection received a non-quick protocol recipe");
    };
    if recipe_program != quick_program(&profile.protocol)? {
        bail!("quick protocol adapter returned the wrong executable family");
    }
    let ((program_name, plan_args), (rollback_name, plan_rollback_args)) = plan.commands();
    let program = resolve_network_program(program_name)?;
    let rollback_program = resolve_network_program(rollback_name)?;

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
    let ip = resolve_network_program("ip")?;
    let kernel_backend = Some((
        spec.kernel_module,
        spec.backend_variable,
        spec.userspace_backend,
    ));
    if configuration_has_key(&configuration, "DNS") {
        validate_quick_dns(&configuration)?;
        resolve_network_program("amn-dns")?;
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
    if plan_args.first().is_some_and(|action| action == "down")
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
            replace_profile_argument(&plan_args, &profile.source, &staged),
            replace_profile_argument(&plan_rollback_args, &profile.source, &staged),
            Some(directory),
            quick_base_created,
        )
    } else {
        (plan_args, plan_rollback_args, None, false)
    };

    Ok(PreparedPlan {
        program,
        rollback_program,
        args,
        rollback_args,
        path,
        interface_probe,
        ip,
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
    if profile.protocol == Protocol::OpenVpn {
        prepare_openvpn(store, profile, settings)?;
        return Ok(());
    }
    if profile.protocol == Protocol::Xray {
        prepare_xray(store, profile, settings)?;
        return Ok(());
    }
    let plan = quick_connection_plan(profile)?;
    prepare_network_plan(store, profile, &plan, settings, false)?;
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

fn quick_interface_values(configuration: &str, expected: &str) -> Vec<String> {
    let mut in_interface = false;
    configuration
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_interface = trimmed.eq_ignore_ascii_case("[Interface]");
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let value = configuration_value(value);
            (in_interface && key.trim().eq_ignore_ascii_case(expected) && !value.is_empty())
                .then(|| value.to_owned())
        })
        .collect()
}

fn quick_dns_values(configuration: &str) -> Vec<String> {
    quick_interface_values(configuration, "DNS")
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn validate_quick_dns(configuration: &str) -> Result<()> {
    let values = quick_dns_values(configuration);
    if !values
        .iter()
        .any(|value| value.parse::<std::net::IpAddr>().is_ok())
    {
        bail!("WireGuard-family DNS requires at least one IP address");
    }
    for value in values
        .iter()
        .filter(|value| value.parse::<std::net::IpAddr>().is_err())
    {
        if value.len() > 253
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        {
            bail!("WireGuard-family DNS contains an invalid search domain");
        }
    }
    Ok(())
}

fn effective_quick_configuration(configuration: &str, settings: &Settings) -> Result<String> {
    let profile_values = quick_dns_values(configuration);
    let mut servers = profile_values
        .iter()
        .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
        .cloned()
        .collect::<Vec<_>>();
    let search_domains = profile_values
        .iter()
        .filter(|value| value.parse::<std::net::IpAddr>().is_err())
        .cloned()
        .collect::<Vec<_>>();
    if servers.is_empty() {
        servers = settings
            .dns_servers
            .iter()
            .map(|value| {
                value
                    .parse::<std::net::IpAddr>()
                    .map(|_| value.clone())
                    .with_context(|| format!("invalid configured DNS server: {value}"))
            })
            .collect::<Result<Vec<_>>>()?;
    }
    if servers.is_empty() {
        bail!("connection DNS settings contain no IP address");
    }
    servers.extend(search_domains);
    let replacement = format!("DNS = {}", servers.join(", "));

    let mut output = Vec::new();
    let mut in_interface = false;
    let mut wrote_dns = false;
    for line in configuration.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_interface && !wrote_dns {
                output.push(replacement.clone());
                wrote_dns = true;
            }
            in_interface = trimmed.eq_ignore_ascii_case("[Interface]");
        }
        let is_dns = in_interface
            && line
                .split_once('=')
                .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("DNS"));
        if is_dns {
            if !wrote_dns {
                output.push(replacement.clone());
                wrote_dns = true;
            }
        } else {
            output.push(line.to_owned());
        }
    }
    if in_interface && !wrote_dns {
        output.push(replacement);
        wrote_dns = true;
    }
    if !wrote_dns {
        bail!("WireGuard-family profile has no Interface section");
    }
    Ok(format!("{}\n", output.join("\n")))
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

fn rollback(
    plan: &CommandPlan,
    prepared: &PreparedPlan,
    identity: Option<&Connection>,
) -> Result<()> {
    let interface_exists_now = interface_exists(
        &prepared.interface_probe,
        &prepared.interface,
        &prepared.path,
    )?;
    let strategy = rollback_strategy(prepared.interface_existed, interface_exists_now);
    if strategy == RollbackStrategy::None {
        return Ok(());
    }
    if interface_exists_now {
        let identity = identity.context(
            "refusing WireGuard-family rollback without exact interface ownership identity",
        )?;
        verify_openvpn_interface_identity(&prepared.interface, identity)
            .context("refusing WireGuard-family rollback after interface ownership changed")?;
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
        bail!(
            "refusing destructive rollback normalization without a fresh exact interface identity: {}",
            prepared.interface
        );
    }
    if interface_exists_now {
        let identity = identity.context(
            "refusing final WireGuard-family rollback without exact ownership identity",
        )?;
        verify_openvpn_interface_identity(&prepared.interface, identity)
            .context("WireGuard-family interface ownership changed immediately before rollback")?;
    }
    let status = network_command(
        &prepared.rollback_program,
        &prepared.rollback_args,
        prepared,
    )
    .status()
    .with_context(|| format!("run rollback {}", plan.rollback_program()))?;
    if !status.success() {
        bail!("rollback {} exited with {status}", plan.rollback_program());
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
    store: &Store,
    state: &mut State,
    profile_id: &str,
    plan: &CommandPlan,
    prepared: &PreparedPlan,
    failure: anyhow::Error,
) -> Result<T> {
    let exists = Command::new(&prepared.ip)
        .args(["link", "show", "dev", &prepared.interface])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    let mut recovery = None;
    if exists {
        let owner = uuid::Uuid::new_v4().to_string();
        let marked = Command::new(&prepared.ip)
            .args([
                "link",
                "set",
                "dev",
                &prepared.interface,
                "alias",
                &owner,
            ])
            .env("PATH", &prepared.path)
            .status()
            .is_ok_and(|status| status.success());
        if marked
            && let Ok(index) = interface_index(&prepared.interface)
        {
            recovery = Some(Connection {
                profile_id: profile_id.to_owned(),
                recovery_required: true,
                pid: None,
                process_start_ticks: None,
                interface: Some(prepared.interface.clone()),
                interface_index: Some(index),
                interface_owner: Some(owner),
                runtime_directory: None,
                xray_route: None,
            });
        } else {
            let mut fallback = state.clone();
            fallback.connection = Some(Connection {
                profile_id: profile_id.to_owned(),
                recovery_required: true,
                pid: None,
                process_start_ticks: None,
                interface: Some(prepared.interface.clone()),
                interface_index: None,
                interface_owner: None,
                runtime_directory: None,
                xray_route: None,
            });
            *state = fallback.clone();
            let _ = store.save(&fallback);
            return Err(failure).context(
                "network action failed; rollback was refused because exact interface ownership could not be established",
            );
        }
    }
    if !exists {
        return Err(failure).context("network action failed; no interface remained to roll back");
    }
    if let Some(identity) = recovery.as_ref() {
        verify_openvpn_interface_identity(&prepared.interface, identity)
            .context("refusing failed-connect rollback without exact interface ownership")?;
    }
    match rollback(plan, prepared, recovery.as_ref()) {
        Ok(()) => Err(failure).context("network action failed; rollback completed"),
        Err(rollback_error) => {
            if let Some(connection) = recovery {
                let mut retained = state.clone();
                retained.connection = Some(connection);
                *state = retained.clone();
                if store.save(&retained).is_ok() {
                    return Err(failure).context(format!(
                        "network action and rollback failed; exact recovery ownership was retained: {rollback_error:#}"
                    ));
                }
            }
            Err(failure).context(format!(
                "network action and rollback failed and recovery ownership could not be persisted: {rollback_error:#}"
            ))
        }
    }
}

