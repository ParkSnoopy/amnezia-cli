struct PreparedXray {
    configuration: String,
    endpoint: String,
    endpoint_port: u16,
    requires_tcp_endpoint: bool,
    gateway: String,
    uplink: String,
    executable: PathBuf,
    tun2socks: PathBuf,
    setsid: PathBuf,
    kill: PathBuf,
    ip: PathBuf,
    dns_helper: PathBuf,
    path: std::ffi::OsString,
    route_mode: crate::core::model::RouteMode,
    split_routes: Vec<crate::core::routing::Network>,
    dns_servers: Vec<std::net::IpAddr>,
}

fn prepare_xray(store: &Store, profile: &Profile, settings: &Settings) -> Result<PreparedXray> {
    let text = store.validated_profile_text(profile)?;
    if profile.protocol != Protocol::Xray {
        bail!("protocol does not use the XRay transport backend");
    }
    let super::ProtocolRecipe::Xray(configuration) =
        super::prepare_protocol(&profile.protocol, &text, settings)?
    else {
        bail!("XRay preparation returned the wrong protocol recipe");
    };
    let endpoint = configuration.endpoint_ipv4()?;
    let endpoint_port = configuration.endpoint_port();
    let requires_tcp_endpoint = configuration.requires_tcp_endpoint();
    let configuration = configuration.render_for_endpoint(endpoint)?;
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
    let dns_helper = resolve_network_program("amn-dns")?;
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
    let dns_servers = settings
        .dns_servers
        .iter()
        .map(|server| server.parse().with_context(|| format!("invalid DNS server: {server}")))
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
        requires_tcp_endpoint,
        gateway,
        uplink,
        executable,
        tun2socks,
        setsid,
        kill,
        ip,
        dns_helper,
        path,
        route_mode: settings.route_mode.clone(),
        split_routes,
        dns_servers,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XrayRouteDisposition {
    Missing,
    SatisfiedExternally,
    Collision,
}

fn xray_route_destination(arguments: &[String]) -> Result<(&str, Option<&str>)> {
    let action_index = arguments
        .iter()
        .position(|argument| argument == "add" || argument == "delete")
        .context("XRay route has no mutation action")?;
    let route_type = arguments
        .get(action_index + 1)
        .filter(|value| value.as_str() == "unreachable")
        .map(String::as_str);
    let destination = arguments
        .get(action_index + 1 + usize::from(route_type.is_some()))
        .context("XRay route has no destination")?;
    Ok((destination, route_type))
}

fn xray_route_path_matches(arguments: &[String], line: &str) -> Result<bool> {
    let (destination, route_type) = xray_route_destination(arguments)?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let destination_matches = match route_type {
        Some(kind) => {
            fields.first().copied() == Some(kind)
                && fields
                    .get(1)
                    .is_some_and(|value| xray_route_destination_matches(destination, value))
        }
        None => fields
            .first()
            .is_some_and(|value| xray_route_destination_matches(destination, value)),
    };
    Ok(destination_matches
        && ["via", "dev"].into_iter().all(|field| {
            route_field(&fields, field)
                == arguments
                    .iter()
                    .position(|argument| argument == field)
                    .and_then(|index| arguments.get(index + 1))
                    .map(String::as_str)
        }))
}

fn classify_xray_route(arguments: &[String], output: &str) -> Result<XrayRouteDisposition> {
    let lines = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Ok(XrayRouteDisposition::Missing);
    }
    for line in lines {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if !xray_route_path_matches(arguments, line)?
            || route_field(&fields, "proto") == Some("66")
        {
            return Ok(XrayRouteDisposition::Collision);
        }
    }
    Ok(XrayRouteDisposition::SatisfiedExternally)
}

fn exact_xray_route_query(arguments: &[String]) -> Result<Vec<String>> {
    let ipv6 = arguments.first().is_some_and(|argument| argument == "-6");
    let (destination, _) = xray_route_destination(arguments)?;
    let mut query = vec!["-N".to_owned()];
    if ipv6 {
        query.push("-6".to_owned());
    }
    query.extend([
        "route".to_owned(),
        "show".to_owned(),
        "exact".to_owned(),
        destination.to_owned(),
    ]);
    Ok(query)
}

fn inspect_xray_route(
    prepared: &PreparedXray,
    arguments: &[String],
) -> Result<XrayRouteDisposition> {
    let query = exact_xray_route_query(arguments)?;
    let output = Command::new(&prepared.ip)
        .args(&query)
        .env("PATH", &prepared.path)
        .output()
        .context("inspect existing route before XRay mutation")?;
    if !output.status.success() {
        bail!("inspect existing XRay route exited with {}", output.status);
    }
    let output = String::from_utf8(output.stdout).context("existing route output is not UTF-8")?;
    classify_xray_route(arguments, &output)
}

fn is_xray_bypass_route(prepared: &PreparedXray, arguments: &[String]) -> Result<bool> {
    if prepared.route_mode != crate::core::model::RouteMode::ExceptListed {
        return Ok(false);
    }
    let (destination, route_type) = xray_route_destination(arguments)?;
    Ok(route_type.is_none()
        && arguments
            .iter()
            .position(|argument| argument == "dev")
            .and_then(|index| arguments.get(index + 1))
            .is_some_and(|device| device == &prepared.uplink)
        && prepared
            .split_routes
            .iter()
            .any(|route| route.cidr() == destination))
}

fn preflight_xray_routes(prepared: &PreparedXray, interface: &str) -> Result<()> {
    for (route, _) in traffic_route_pairs(prepared, interface) {
        if !is_xray_bypass_route(prepared, &route)? {
            continue;
        }
        if inspect_xray_route(prepared, &route)? == XrayRouteDisposition::Collision {
            let (destination, _) = xray_route_destination(&route)?;
            bail!(
                "XRay route already exists with an incompatible path or ownership: {destination}"
            );
        }
    }
    Ok(())
}

fn verify_xray_bypass_routes(
    prepared: &PreparedXray,
    interface: &str,
    rollback: &[XrayRollback],
) -> Result<()> {
    for (route, reverse) in traffic_route_pairs(prepared, interface) {
        if !is_xray_bypass_route(prepared, &route)? {
            continue;
        }
        let owned = xray_rollback_owns_route(rollback, &reverse);
        let satisfied = if owned {
            xray_route_exists(prepared, &reverse)?
        } else {
            inspect_xray_route(prepared, &route)? == XrayRouteDisposition::SatisfiedExternally
        };
        if !satisfied {
            let (destination, _) = xray_route_destination(&route)?;
            bail!("XRay bypass route changed during connection setup: {destination}");
        }
    }
    Ok(())
}

#[derive(Clone)]
enum XrayRollback {
    Ip(Vec<String>),
    DnsRevert { interface: String },
    DnsSet { interface: String },
}

fn xray_rollback_owns_route(rollback: &[XrayRollback], route: &[String]) -> bool {
    rollback
        .iter()
        .any(|action| matches!(action, XrayRollback::Ip(arguments) if arguments == route))
}

fn xray_dns_set(prepared: &PreparedXray, interface: &str) -> Result<()> {
    let servers = prepared
        .dns_servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let status = Command::new(&prepared.dns_helper)
        .arg("set")
        .arg(interface)
        .args(&servers)
        .env("PATH", &prepared.path)
        .status()
        .context("configure XRay DNS servers")?;
    if !status.success() {
        bail!("bundled DNS helper exited with {status}");
    }
    Ok(())
}

fn xray_dns_revert(prepared: &PreparedXray, interface: &str) -> Result<()> {
    let status = Command::new(&prepared.dns_helper)
        .args(["unset", interface])
        .env("PATH", &prepared.path)
        .status()
        .context("revert XRay DNS")?;
    if !status.success() {
        bail!("bundled DNS helper rollback exited with {status}");
    }
    Ok(())
}

fn run_xray_rollback(prepared: &PreparedXray, rollback: &XrayRollback) -> Result<()> {
    match rollback {
        XrayRollback::Ip(arguments) => xray_ip_command(prepared, arguments),
        XrayRollback::DnsRevert { interface } => xray_dns_revert(prepared, interface),
        XrayRollback::DnsSet { interface } => xray_dns_set(prepared, interface),
    }
}

fn opposite_xray_rollback(rollback: XrayRollback) -> XrayRollback {
    match rollback {
        XrayRollback::Ip(arguments) => XrayRollback::Ip(reverse_ip_action(arguments)),
        XrayRollback::DnsRevert { interface } => XrayRollback::DnsSet { interface },
        XrayRollback::DnsSet { interface } => XrayRollback::DnsRevert { interface },
    }
}

fn apply_xray_mutation(
    prepared: &PreparedXray,
    forward: Vec<String>,
    reverse: Vec<String>,
    rollback: &mut Vec<XrayRollback>,
) -> Result<()> {
    xray_ip_command(prepared, &forward)?;
    rollback.push(XrayRollback::Ip(reverse));
    Ok(())
}

fn apply_xray_route_mutation(
    prepared: &PreparedXray,
    forward: Vec<String>,
    reverse: Vec<String>,
    rollback: &mut Vec<XrayRollback>,
) -> Result<()> {
    if !is_xray_bypass_route(prepared, &forward)? {
        return apply_xray_mutation(prepared, forward, reverse, rollback);
    }
    match inspect_xray_route(prepared, &forward)? {
        XrayRouteDisposition::Missing => {
            apply_xray_mutation(prepared, forward, reverse, rollback)
        }
        XrayRouteDisposition::SatisfiedExternally => Ok(()),
        XrayRouteDisposition::Collision => {
            let (destination, _) = xray_route_destination(&forward)?;
            bail!(
                "XRay route already exists with an incompatible path or ownership: {destination}"
            )
        }
    }
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

fn xray_route_line_matches(arguments: &[String], line: &str) -> Result<bool> {
    let action_index = arguments
        .iter()
        .position(|argument| argument == "add" || argument == "delete")
        .context("XRay route query has no mutation action")?;
    let route_type = arguments
        .get(action_index + 1)
        .filter(|value| value.as_str() == "unreachable")
        .map(String::as_str);
    let destination_index = action_index + 1 + usize::from(route_type.is_some());
    let destination = arguments
        .get(destination_index)
        .context("XRay route query has no destination")?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let destination_matches = match route_type {
        Some(kind) => {
            fields.first().copied() == Some(kind)
                && fields
                    .get(1)
                    .is_some_and(|value| xray_route_destination_matches(destination, value))
        }
        None => fields
            .first()
            .is_some_and(|value| xray_route_destination_matches(destination, value)),
    };
    Ok(destination_matches
        && ["via", "dev", "proto", "metric"].into_iter().all(|field| {
            route_field(&fields, field)
                == arguments
                    .iter()
                    .position(|argument| argument == field)
                    .and_then(|index| arguments.get(index + 1))
                    .map(String::as_str)
        }))
}

fn xray_route_destination_matches(expected: &str, rendered: &str) -> bool {
    expected == rendered
        || rendered == "default" && matches!(expected, "0.0.0.0/0" | "::/0")
        || expected
            .strip_suffix("/32")
            .is_some_and(|address| address == rendered)
        || expected
            .strip_suffix("/128")
            .is_some_and(|address| address == rendered)
}

fn xray_route_exists(prepared: &PreparedXray, arguments: &[String]) -> Result<bool> {
    let query = exact_xray_route_query(arguments)?;
    let output = Command::new(&prepared.ip)
        .args(&query)
        .env("PATH", &prepared.path)
        .output()
        .context("inspect XRay route")?;
    if !output.status.success() {
        bail!("inspect XRay route exited with {}", output.status);
    }
    let output = String::from_utf8(output.stdout).context("XRay route output is not UTF-8")?;
    for line in output.lines() {
        if xray_route_line_matches(arguments, line)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn endpoint_route_exists(prepared: &PreparedXray) -> Result<bool> {
    let destination = format!("{}/32", prepared.endpoint);
    let output = Command::new(&prepared.ip)
        .args(["route", "show", &destination, "proto", "66"])
        .env("PATH", &prepared.path)
        .output()
        .context("inspect owned XRay endpoint route")?;
    if !output.status.success() {
        bail!("inspect owned XRay endpoint route exited with {}", output.status);
    }
    let output = String::from_utf8(output.stdout)
        .context("XRay endpoint route output is not UTF-8")?;
    Ok(output.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        matches!(fields.first().copied(), Some(value) if value == destination || value == prepared.endpoint)
            && route_field(&fields, "dev") == Some(prepared.uplink.as_str())
            && (prepared.gateway == "-"
                && route_field(&fields, "via").is_none()
                || prepared.gateway != "-"
                    && route_field(&fields, "via") == Some(prepared.gateway.as_str()))
    }))
}

fn retain_unstarted_xray_runtime(
    store: &Store,
    state: &mut State,
    profile_id: &str,
    interface: &str,
    directory: &Path,
) -> Result<()> {
    let mut retained = state.clone();
    retained.connection = Some(Connection {
        profile_id: profile_id.to_owned(),
        recovery_required: true,
        pid: None,
        process_start_ticks: None,
        interface: Some(interface.to_owned()),
        interface_index: None,
        interface_owner: None,
        runtime_directory: Some(directory.to_string_lossy().into_owned()),
        xray_route: None,
    });
    *state = retained.clone();
    store
        .save(&retained)
        .context("persist unstarted XRay runtime cleanup ownership")
}

fn is_runtime_only_xray_recovery(connection: &Connection) -> bool {
    connection.recovery_required
        && connection.pid.is_none()
        && connection.process_start_ticks.is_none()
        && connection.interface_index.is_none()
        && connection.interface_owner.is_none()
        && connection.xray_route.is_none()
        && connection.runtime_directory.is_some()
}

fn fail_unstarted_xray<T>(
    store: &Store,
    state: &mut State,
    profile_id: &str,
    interface: &str,
    directory: &Path,
    failure: anyhow::Error,
) -> Result<T> {
    if let Err(remove_error) = fs::remove_dir_all(directory) {
        retain_unstarted_xray_runtime(store, state, profile_id, interface, directory)?;
        return Err(failure).context(format!(
            "unstarted XRay runtime cleanup failed and was retained for recovery: {remove_error:#}"
        ));
    }
    Err(failure)
}

fn start_xray_worker(
    store: &Store,
    state: &mut State,
    profile_id: &str,
    prepared: &PreparedXray,
    interface: &str,
    logging: bool,
) -> Result<(u32, PathBuf)> {
    if effective_user_id() != Some(0) {
        bail!("XRay interface changes require running amn as root");
    }
    let directory = create_root_runtime_directory()?;
    let configuration = directory.join("xray.json");
    let startup_error = directory.join("startup-error");
    if let Err(error) =
        crate::core::store::write_private(&configuration, prepared.configuration.as_bytes())
    {
        return fail_unstarted_xray(
            store,
            state,
            profile_id,
            interface,
            &directory,
            error.context("stage normalized XRay configuration"),
        );
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
            startup_error.as_os_str(),
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
                return fail_unstarted_xray(
                    store,
                    state,
                    profile_id,
                    interface,
                    &directory,
                    error,
                );
            }
        };
        let stderr = match stdout.try_clone() {
            Ok(file) => file,
            Err(error) => {
                return fail_unstarted_xray(
                    store,
                    state,
                    profile_id,
                    interface,
                    &directory,
                    error.into(),
                );
            }
        };
        command.stdout(stdout).stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let child = match command.spawn().context("start isolated XRay worker") {
        Ok(child) => child,
        Err(error) => {
            return fail_unstarted_xray(
                store,
                state,
                profile_id,
                interface,
                &directory,
                error,
            );
        }
    };
    Ok((child.id(), directory))
}

fn wait_xray_interface(
    prepared: &PreparedXray,
    pid: u32,
    interface: &str,
    runtime_directory: &Path,
) -> Result<()> {
    for _ in 0..50 {
        if !process_is_running(pid) {
            let message = match fs::read_to_string(runtime_directory.join("startup-error"))
                .ok()
                .as_deref()
            {
                Some("configuration") => {
                    "bundled XRay engine rejected the normalized configuration"
                }
                Some("xray-start") => "bundled XRay engine could not start",
                Some("tun2socks-start") => "bundled tun2socks could not start",
                Some("tun2socks-exit") => {
                    "bundled tun2socks exited before creating its TUN interface"
                }
                _ => "XRay worker exited before creating its TUN interface",
            };
            bail!("{message}");
        }
        let exists = Command::new(&prepared.ip)
            .args(["link", "show", "dev", interface])
            .env("PATH", &prepared.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("inspect XRay startup interface")?
            .success();
        if exists {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("XRay worker did not create its TUN interface")
}

fn stop_xray_worker(prepared: &PreparedXray, pid: u32) -> Result<()> {
    if stop_process_group(&prepared.kill, &prepared.path, pid, "XRay worker").is_ok() {
        return Ok(());
    }
    force_stop_process_group(&prepared.kill, &prepared.path, pid, "XRay worker")
        .context("force-stop XRay worker process group")
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
    rollback: &mut Vec<XrayRollback>,
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
    apply_xray_route_mutation(
        prepared,
        endpoint_route_arguments(prepared, "add"),
        endpoint_route_arguments(prepared, "delete"),
        rollback,
    )?;
    for (forward, reverse) in traffic_route_pairs(prepared, interface) {
        apply_xray_route_mutation(prepared, forward, reverse, rollback)?;
    }
    rollback.push(XrayRollback::DnsRevert {
        interface: interface.into(),
    });
    xray_dns_set(prepared, interface)?;
    Ok(())
}

fn cleanup_xray_routes(
    prepared: &PreparedXray,
    interface: &str,
    identity: &Connection,
) -> Result<()> {
    for (_, reverse) in traffic_route_pairs(prepared, interface).into_iter().rev() {
        if xray_route_exists(prepared, &reverse)? {
            verify_openvpn_interface_identity(interface, identity)
                .context("refusing XRay route rollback after interface ownership changed")?;
            xray_ip_command(prepared, &reverse).context("remove owned XRay traffic route")?;
        }
    }
    if endpoint_route_exists(prepared)? {
        verify_openvpn_interface_identity(interface, identity)
            .context("refusing XRay endpoint-route rollback after interface ownership changed")?;
        xray_ip_command(prepared, &endpoint_route_arguments(prepared, "delete"))
            .context("remove owned XRay endpoint route")?;
    }
    Ok(())
}

fn partial_xray_recovery(
    state: &State,
    profile_id: &str,
    prepared: &PreparedXray,
    pid: u32,
    interface: &str,
) -> State {
    let mut recovery = state.clone();
    recovery.connection = Some(Connection {
        profile_id: profile_id.to_owned(),
        recovery_required: true,
        pid: Some(pid),
        process_start_ticks: process_start_ticks(pid),
        interface: Some(interface.to_owned()),
        interface_index: None,
        interface_owner: None,
        runtime_directory: None,
        xray_route: Some(XrayRouteIdentity {
            endpoint: prepared.endpoint.clone(),
            gateway: prepared.gateway.clone(),
            uplink: prepared.uplink.clone(),
        }),
    });
    recovery
}

fn rollback_or_retain_xray(
    store: &Store,
    state: &mut State,
    profile_id: &str,
    prepared: &PreparedXray,
    pid: u32,
    interface: &str,
    rollback: &mut Vec<XrayRollback>,
) -> Result<()> {
    match rollback_xray_connect(prepared, pid, interface, rollback, None) {
        Ok(()) => Ok(()),
        Err(rollback_error) => {
            let interface_disappeared = rollback.is_empty()
                && Command::new(&prepared.ip)
                    .args(["link", "show", "dev", interface])
                    .env("PATH", &prepared.path)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|status| !status.success())
                && !Path::new("/sys/class/net").join(interface).exists();
            if interface_disappeared && stop_xray_worker(prepared, pid).is_ok() {
                return Ok(());
            }
            *state = partial_xray_recovery(state, profile_id, prepared, pid, interface);
            store.save(state).context(format!(
                "persist partial XRay recovery facts after rollback failed; recovery remains available in memory: {rollback_error:#}"
            ))?;
            Err(anyhow!(
                "XRay rollback failed; known recovery facts were retained without claiming interface ownership: {rollback_error:#}"
            ))
        }
    }
}

fn retain_xray_runtime(store: &Store, state: &mut State, directory: &Path) -> Result<()> {
    let mut retained = state.clone();
    let connection = retained
        .connection
        .as_mut()
        .context("XRay recovery state is missing while retaining runtime files")?;
    connection.runtime_directory = Some(directory.to_string_lossy().into_owned());
    *state = retained.clone();
    store
        .save(&retained)
        .context("persist XRay runtime cleanup ownership")?;
    Ok(())
}

fn rollback_xray_connect(
    prepared: &PreparedXray,
    pid: u32,
    interface: &str,
    rollback: &mut Vec<XrayRollback>,
    identity: Option<&Connection>,
) -> Result<()> {
    let initial_interface_exists = Command::new(&prepared.ip)
        .args(["link", "show", "dev", interface])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(true);
    if initial_interface_exists {
        let identity = identity.context(
            "refusing XRay rollback actions without exact interface ownership identity",
        )?;
        verify_openvpn_interface_identity(interface, identity)
            .context("refusing XRay rollback actions after interface ownership changed")?;
    } else if identity.is_none() {
        return stop_xray_worker(prepared, pid)
            .context("stop pre-identity XRay worker during rollback");
    }
    let identity = identity.context("XRay rollback has no exact ownership identity")?;
    let mut failures = Vec::new();
    while let Some(action) = rollback.pop() {
        if let Err(error) = verify_openvpn_interface_identity(interface, identity) {
            failures.push(format!("{error:#}"));
            break;
        }
        let rollback_result = match &action {
            XrayRollback::Ip(arguments)
                if *arguments == endpoint_route_arguments(prepared, "delete") =>
            {
                if endpoint_route_exists(prepared)? {
                    run_xray_rollback(prepared, &action)
                } else {
                    Ok(())
                }
            }
            _ => run_xray_rollback(prepared, &action),
        };
        if let Err(error) = rollback_result {
            failures.push(format!("{error:#}"));
        }
    }
    if let Err(error) = cleanup_xray_routes(prepared, interface, identity) {
        failures.push(format!("{error:#}"));
    }
    if let Err(error) = stop_xray_worker(prepared, pid) {
        failures.push(format!("{error:#}"));
    }
    let interface_exists = Command::new(&prepared.ip)
        .args(["link", "show", "dev", interface])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(true);
    if interface_exists {
        verify_openvpn_interface_identity(interface, identity)
            .context("refusing XRay rollback without exact interface ownership")?;
        let delete = vec![
            "link".into(),
            "delete".into(),
            "dev".into(),
            interface.into(),
        ];
        if let Err(error) = xray_ip_command(prepared, &delete) {
            failures.push(format!("{error:#}"));
        }
    }
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
    if prepared.requires_tcp_endpoint {
        let endpoint = format!("{}:{}", prepared.endpoint, prepared.endpoint_port)
            .parse()
            .context("construct XRay endpoint socket address")?;
        TcpStream::connect_timeout(&endpoint, std::time::Duration::from_secs(2))
            .context("XRay endpoint is not accepting TCP connections")?;
    }
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
    preflight_xray_routes(&prepared, interface)?;
    let logging = state.settings.logging;
    let (pid, runtime_directory) =
        start_xray_worker(store, state, &id, &prepared, interface, logging)?;
    let mut rollback = Vec::new();
    if let Err(start_error) =
        wait_xray_interface(&prepared, pid, interface, &runtime_directory)
    {
        return match rollback_or_retain_xray(
            store,
            state,
            &id,
            &prepared,
            pid,
            interface,
            &mut rollback,
        ) {
            Ok(()) => {
                if let Err(remove_error) = fs::remove_dir_all(&runtime_directory) {
                    retain_unstarted_xray_runtime(
                        store,
                        state,
                        &id,
                        interface,
                        &runtime_directory,
                    )?;
                    return Err(start_error).context(format!(
                        "XRay startup rolled back but staged configuration cleanup failed: {remove_error:#}"
                    ));
                }
                Err(start_error).context("XRay startup rolled back")
            }
            Err(rollback_error) => {
                retain_xray_runtime(store, state, &runtime_directory)?;
                Err(start_error).context(format!(
                    "XRay startup failed and rollback required recovery: {rollback_error:#}"
                ))
            }
        };
    }
    if let Err(remove_error) = fs::remove_dir_all(&runtime_directory) {
        return match rollback_or_retain_xray(
            store,
            state,
            &id,
            &prepared,
            pid,
            interface,
            &mut rollback,
        ) {
            Ok(()) => Err(remove_error).context("remove staged XRay configuration"),
            Err(rollback_error) => {
                retain_xray_runtime(store, state, &runtime_directory)?;
                Err(remove_error).context(format!(
                    "staged XRay configuration removal and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    let Some(start_ticks) = process_start_ticks(pid) else {
        rollback_or_retain_xray(
            store,
            state,
            &id,
            &prepared,
            pid,
            interface,
            &mut rollback,
        )
        .context("XRay process identity could not be read and rollback failed")?;
        bail!("XRay process identity could not be read; connection rolled back");
    };
    let interface_index = match interface_index(interface) {
        Ok(index) => index,
        Err(error) => {
            rollback_or_retain_xray(
                store,
                state,
                &id,
                &prepared,
                pid,
                interface,
                &mut rollback,
            )
            .context("XRay interface identity failed and rollback failed")?;
            return Err(error).context("read XRay interface identity; connection rolled back");
        }
    };
    let interface_owner = uuid::Uuid::new_v4().to_string();
    if let Err(error) = xray_ip_command(
        &prepared,
        &[
            "link".into(),
            "set".into(),
            "dev".into(),
            interface.into(),
            "alias".into(),
            interface_owner.clone(),
        ],
    ) {
        rollback_or_retain_xray(
            store,
            state,
            &id,
            &prepared,
            pid,
            interface,
            &mut rollback,
        )
        .context("XRay ownership marking failed and rollback failed")?;
        return Err(error).context("mark XRay interface ownership; connection rolled back");
    }
    let mut updated = state.clone();
    updated.connection = Some(Connection {
        profile_id: id,
        recovery_required: false,
        pid: Some(pid),
        process_start_ticks: Some(start_ticks),
        interface: Some(interface.into()),
        interface_index: Some(interface_index),
        interface_owner: Some(interface_owner),
        runtime_directory: None,
        xray_route: Some(XrayRouteIdentity {
            endpoint: prepared.endpoint.clone(),
            gateway: prepared.gateway.clone(),
            uplink: prepared.uplink.clone(),
        }),
    });
    let configure_result = configure_xray_interface(&prepared, interface, &mut rollback)
        .and_then(|()| verify_xray_bypass_routes(&prepared, interface, &rollback));
    if let Err(error) = configure_result {
        return match rollback_xray_connect(
            &prepared,
            pid,
            interface,
            &mut rollback,
            updated.connection.as_ref(),
        ) {
            Ok(()) => Err(error).context("XRay connection failed; rollback completed"),
            Err(rollback_error) => {
                if let Some(connection) = updated.connection.as_mut() {
                    connection.recovery_required = true;
                }
                *state = updated.clone();
                match store.save(&updated) {
                    Ok(()) => {
                        *state = updated;
                        Err(error).context(format!(
                            "XRay connection and rollback failed; recovery ownership was retained: {rollback_error:#}"
                        ))
                    }
                    Err(recovery_error) => Err(error).context(format!(
                        "XRay connection, rollback, and recovery ownership persistence failed: {rollback_error:#}; {recovery_error:#}"
                    )),
                }
            }
        };
    }
    if let Err(error) = store.save(&updated) {
        return match rollback_xray_connect(
            &prepared,
            pid,
            interface,
            &mut rollback,
            updated.connection.as_ref(),
        ) {
            Ok(()) => Err(error).context("XRay connection rolled back after state save failed"),
            Err(rollback_error) => {
                if let Some(connection) = updated.connection.as_mut() {
                    connection.recovery_required = true;
                }
                *state = updated.clone();
                match store.save(&updated) {
                    Ok(()) => {
                        *state = updated;
                        Err(error).context(format!(
                            "XRay state save and rollback failed; recovery ownership was retained: {rollback_error:#}"
                        ))
                    }
                    Err(recovery_error) => Err(error).context(format!(
                        "XRay state save, rollback, and recovery ownership persistence failed: {rollback_error:#}; {recovery_error:#}"
                    )),
                }
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
    process_stat_identity(&stat).map(|(_, _, ticks)| ticks)
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
    process_stat_identity(&stat).is_some_and(|(state, _, _)| state != 'Z')
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
    mut route_rollback: Vec<XrayRollback>,
) -> Result<()> {
    let interface = original
        .interface
        .as_deref()
        .context("XRay connection has no interface")?;
    let mut restored = original.clone();
    let pid;
    let mut disconnect_again = Vec::new();
    if process_alive {
        verify_openvpn_interface_identity(interface, original)
            .context("refusing XRay disconnect rollback after interface ownership changed")?;
        pid = original.pid.context("XRay connection has no worker PID")?;
        while let Some(action) = route_rollback.pop() {
            verify_openvpn_interface_identity(interface, original).context(
                "refusing XRay disconnect rollback action after interface ownership changed",
            )?;
            let pre_recorded = matches!(action, XrayRollback::DnsSet { .. });
            if pre_recorded {
                disconnect_again.push(opposite_xray_rollback(action.clone()));
            }
            if let Err(error) = run_xray_rollback(prepared, &action) {
                let cleanup = rollback_xray_connect(
                    prepared,
                    pid,
                    interface,
                    &mut disconnect_again,
                    Some(original),
                );
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
            if !pre_recorded {
                disconnect_again.push(opposite_xray_rollback(action));
            }
        }
    } else {
        let owner = original
            .interface_owner
            .as_deref()
            .context("XRay connection has no interface ownership alias")?;
        verify_openvpn_interface_identity(interface, original)
            .context("refusing XRay recovery cleanup without exact interface ownership")?;
        let delete = vec![
            "link".into(),
            "delete".into(),
            "dev".into(),
            interface.into(),
        ];
        if let Err(error) = xray_ip_command(prepared, &delete) {
            if let Some(connection) = state.connection.as_mut() {
                connection.recovery_required = true;
            }
            store
                .save(state)
                .context("retain XRay ownership metadata after orphan interface cleanup failure")?;
            return Err(error).context(
                "remove orphan XRay interface before recovery; ownership metadata retained",
            );
        }
        let logging = state.settings.logging;
        let (started_pid, runtime_directory) = start_xray_worker(
            store,
            state,
            &original.profile_id,
            prepared,
            interface,
            logging,
        )?;
        pid = started_pid;
        if let Err(start_error) =
            wait_xray_interface(prepared, pid, interface, &runtime_directory)
        {
            let rollback = rollback_or_retain_xray(
                store,
                state,
                &original.profile_id,
                prepared,
                pid,
                interface,
                &mut disconnect_again,
            );
            match &rollback {
                Ok(()) => {
                    if let Err(remove_error) = fs::remove_dir_all(&runtime_directory) {
                        retain_unstarted_xray_runtime(
                            store,
                            state,
                            &original.profile_id,
                            interface,
                            &runtime_directory,
                        )?;
                        return Err(start_error).context(format!(
                            "restore XRay startup rolled back but runtime cleanup failed: {remove_error:#}"
                        ));
                    }
                }
                Err(_) => retain_xray_runtime(store, state, &runtime_directory)?,
            }
            return Err(start_error).context(format!(
                "restore XRay worker startup failed: {rollback:?}"
            ));
        }
        if let Err(remove_error) = fs::remove_dir_all(&runtime_directory) {
            let rollback = rollback_or_retain_xray(
                store,
                state,
                &original.profile_id,
                prepared,
                pid,
                interface,
                &mut disconnect_again,
            );
            match &rollback {
                Ok(()) => retain_unstarted_xray_runtime(
                    store,
                    state,
                    &original.profile_id,
                    interface,
                    &runtime_directory,
                )?,
                Err(_) => retain_xray_runtime(store, state, &runtime_directory)?,
            }
            return Err(remove_error).context(format!(
                "remove restored XRay staged configuration failed: {rollback:?}"
            ));
        }
        if let Err(error) = xray_ip_command(
            prepared,
            &[
                "link".into(),
                "set".into(),
                "dev".into(),
                interface.into(),
                "alias".into(),
                owner.into(),
            ],
        ) {
            rollback_or_retain_xray(
                store,
                state,
                &original.profile_id,
                prepared,
                pid,
                interface,
                &mut disconnect_again,
            )
            .context("restore XRay interface ownership alias and retain recovery state")?;
            return Err(error).context("restore XRay interface ownership alias");
        }
        restored.interface_index = match interface_index(interface) {
            Ok(index) => Some(index),
            Err(error) => {
                rollback_or_retain_xray(
                    store,
                    state,
                    &original.profile_id,
                    prepared,
                    pid,
                    interface,
                    &mut disconnect_again,
                )
                .context("restore XRay interface identity and retain recovery state")?;
                return Err(error).context("restore XRay interface identity");
            }
        };
        restored.interface_owner = Some(owner.into());
        restored.pid = Some(pid);
        if let Err(error) = configure_xray_interface(prepared, interface, &mut disconnect_again) {
            let cleanup = rollback_xray_connect(
                prepared,
                pid,
                interface,
                &mut disconnect_again,
                Some(&restored),
            );
            return match cleanup {
                Ok(()) => Err(error).context("restore XRay network after failed disconnect"),
                Err(cleanup_error) => Err(error).context(format!(
                    "restore XRay network failed and exact cleanup failed: {cleanup_error:#}"
                )),
            };
        }
    }
    let Some(start_ticks) = process_start_ticks(pid) else {
        if let Err(rollback_error) = rollback_xray_connect(
            prepared,
            pid,
            interface,
            &mut disconnect_again,
            Some(&restored),
        ) {
            restored.recovery_required = true;
            restored.pid = Some(pid);
            restored.process_start_ticks = None;
            let mut retained = state.clone();
            retained.connection = Some(restored);
            *state = retained.clone();
            store
                .save(&retained)
                .context("persist restored XRay worker recovery ownership")?;
            return Err(rollback_error)
                .context("restored XRay worker identity failed and rollback required recovery");
        }
        bail!("restored XRay worker process identity could not be read");
    };
    restored.process_start_ticks = Some(start_ticks);
    let mut recovered = state.clone();
    recovered.connection = Some(restored);
    if let Err(error) = store.save(&recovered) {
        let rollback = rollback_xray_connect(
            prepared,
            pid,
            interface,
            &mut disconnect_again,
            recovered.connection.as_ref(),
        );
        return match rollback {
            Ok(()) => {
                Err(error).context(
                    "restore XRay connection state failed; disconnected network state retained",
                )
            }
            Err(rollback_error) => {
                if let Some(connection) = recovered.connection.as_mut() {
                    connection.recovery_required = true;
                }
                *state = recovered;
                Err(error).context(format!(
                    "restore XRay connection state and cleanup failed; recovery ownership remains in memory: {rollback_error:#}"
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
    if is_runtime_only_xray_recovery(connection) {
        if dry_run {
            return Ok("remove retained XRay runtime files".into());
        }
        let retained = state.clone();
        let mut disconnected = retained.clone();
        disconnected.connection = None;
        store
            .save(&disconnected)
            .context("persist pending XRay runtime cleanup")?;
        if let Err(cleanup_error) =
            remove_openvpn_runtime(connection.runtime_directory.as_deref())
        {
            *state = retained;
            if let Err(persist_error) = store.save(state) {
                return Err(cleanup_error).context(format!(
                    "remove retained XRay runtime files and restore recovery state failed: {persist_error:#}"
                ));
            }
            return Err(cleanup_error).context("remove retained XRay runtime files");
        }
        *state = disconnected;
        return Ok("disconnected".into());
    }
    let live = connection
        .pid
        .and_then(|pid| {
            (verify_connection_process(connection).ok() == Some(pid))
                .then(|| xray_process_info(pid).ok())
                .flatten()
                .map(|info| (pid, info))
        });
    let (pid, info, process_alive) = if let Some((pid, info)) = live {
        (pid, info, true)
    } else {
        let route = connection
            .xray_route
            .as_ref()
            .context("stale XRay connection has no persisted route identity")?;
        let interface = connection
            .interface
            .clone()
            .context("XRay connection has no interface")?;
        (
            connection.pid.unwrap_or(0),
            XrayProcessInfo {
                interface,
                endpoint: route.endpoint.clone(),
                gateway: route.gateway.clone(),
                uplink: route.uplink.clone(),
            },
            false,
        )
    };
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
    prepared.configuration = crate::core::xray::Configuration::parse(
        &store.validated_profile_text(profile)?,
    )?
    .render_for_endpoint(
        prepared
            .endpoint
            .parse()
            .context("saved XRay endpoint is not IPv4")?,
    )?;
    let interface_exists = Command::new(&prepared.ip)
        .args(["link", "show", "dev", &info.interface])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    if interface_exists {
        verify_openvpn_interface_identity(&info.interface, connection)
            .context("refusing XRay cleanup without exact interface ownership")?;
    }

    let mut disconnected = state.clone();
    disconnected.connection = None;
    store
        .save(&disconnected)
        .context("persist pending XRay disconnect")?;

    if !process_alive && !interface_exists {
        let stale_cleanup = (|| -> Result<()> {
            for (_, reverse) in traffic_route_pairs(&prepared, &info.interface)
                .into_iter()
                .rev()
                .filter(|(_, reverse)| !reverse.iter().any(|argument| argument == &info.interface))
            {
                if xray_route_exists(&prepared, &reverse)? {
                    xray_ip_command(&prepared, &reverse)
                        .context("remove interface-independent stale XRay route")?;
                }
            }
            if endpoint_route_exists(&prepared)? {
                let interface_reappeared = Command::new(&prepared.ip)
                    .args(["link", "show", "dev", &info.interface])
                    .env("PATH", &prepared.path)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()?
                    .success();
                if interface_reappeared {
                    bail!("refusing stale XRay endpoint-route cleanup after an interface reappeared");
                }
                xray_ip_command(
                    &prepared,
                    &endpoint_route_arguments(&prepared, "delete"),
                )
                .context("remove stale XRay endpoint route")?;
            }
            remove_openvpn_runtime(connection.runtime_directory.as_deref())
                .context("remove stale XRay runtime files")?;
            Ok(())
        })();
        if let Err(error) = stale_cleanup {
            if let Some(connection) = state.connection.as_mut() {
                connection.recovery_required = true;
            }
            if let Err(persist_error) = store.save(state) {
                return Err(error).context(format!(
                    "clean stale XRay routes and persist recovery metadata failed; recovery remains in memory: {persist_error:#}"
                ));
            }
            return Err(error).context("clean stale XRay routes");
        }
        *state = disconnected;
        return Ok("disconnected".into());
    }

    let mut route_rollback = Vec::new();
    let operation = (|| -> Result<()> {
        xray_dns_revert(&prepared, &info.interface)?;
        route_rollback.push(XrayRollback::DnsSet {
            interface: info.interface.clone(),
        });
        for (forward, reverse) in traffic_route_pairs(&prepared, &info.interface)
            .into_iter()
            .rev()
        {
            if xray_route_exists(&prepared, &reverse)? {
                apply_xray_mutation(&prepared, reverse, forward, &mut route_rollback)?;
            }
        }
        if endpoint_route_exists(&prepared)? {
            verify_openvpn_interface_identity(&info.interface, connection)
                .context("refusing XRay endpoint-route disconnect after ownership changed")?;
            apply_xray_mutation(
                &prepared,
                endpoint_route_arguments(&prepared, "delete"),
                endpoint_route_arguments(&prepared, "add"),
                &mut route_rollback,
            )?;
        }
        if process_alive {
            stop_xray_worker(&prepared, pid)?;
        }
        let exists = Command::new(&prepared.ip)
            .args(["link", "show", "dev", &info.interface])
            .env("PATH", &prepared.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        if exists {
            verify_openvpn_interface_identity(&info.interface, connection)
                .context("refusing final XRay interface deletion without exact ownership")?;
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
        remove_openvpn_runtime(connection.runtime_directory.as_deref())
            .context("remove XRay runtime files")?;
        Ok(())
    })();
    if let Err(error) = operation {
        let process_alive = process_alive && process_is_running(pid);
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
                let recovery_in_memory = state
                    .connection
                    .as_ref()
                    .is_some_and(|connection| connection.recovery_required);
                if !recovery_in_memory
                    && let Ok(persisted) = store.load_without_migration()
                {
                    *state = persisted;
                }
                Err(error).context(format!(
                    "XRay disconnect and rollback failed: {rollback_error:#}"
                ))
            }
        };
    }
    *state = disconnected;
    Ok("disconnected".into())
}

