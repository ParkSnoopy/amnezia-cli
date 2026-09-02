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
    let text = store.validated_profile_text(profile)?;
    let super::ProtocolRecipe::OpenVpn(configuration) =
        super::prepare_protocol(&profile.protocol, &text, settings)?
    else {
        bail!("OpenVPN preparation returned the wrong protocol recipe");
    };
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
    state: &mut State,
    profile_id: &str,
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
        let interface_exists = Command::new(&prepared.ip)
            .args(["link", "show", "dev", &prepared.interface])
            .env("PATH", &prepared.path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        let recovery_result = (|| -> Result<Option<Connection>> {
            if !interface_exists {
                return Ok(None);
            }
            let owner = uuid::Uuid::new_v4().to_string();
            let status = Command::new(&prepared.ip)
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
                .context("mark failed OpenVPN startup ownership")?;
            if !status.success() {
                bail!("mark failed OpenVPN startup ownership exited with {status}");
            }
            Ok(Some(Connection {
                profile_id: profile_id.to_owned(),
                recovery_required: true,
                disconnecting: false,
                pid: Some(child.id()),
                process_start_ticks: process_start_ticks(child.id()),
                interface: Some(prepared.interface.clone()),
                interface_index: Some(interface_index(&prepared.interface)?),
                interface_owner: Some(owner),
                runtime_directory: Some(directory.to_string_lossy().into_owned()),
                quick_root_owned: false,
                xray_route: None,
                xray_owned_routes: Vec::new(),
            }))
        })();
        let identity_error = recovery_result.as_ref().err().map(|error| format!("{error:#}"));
        let mut recovery = recovery_result.unwrap_or(None);
        let fallback_recovery = Connection {
            profile_id: profile_id.to_owned(),
            recovery_required: true,
            disconnecting: false,
            pid: Some(child.id()),
            process_start_ticks: process_start_ticks(child.id()),
            interface: Some(prepared.interface.clone()),
            interface_index: None,
            interface_owner: None,
            runtime_directory: Some(directory.to_string_lossy().into_owned()),
            quick_root_owned: false,
            xray_route: None,
            xray_owned_routes: Vec::new(),
        };
        let stopped = stop_process_group(&prepared.kill, &prepared.path, child.id(), "OpenVPN")
            .or_else(|_| {
                force_stop_process_group(&prepared.kill, &prepared.path, child.id(), "OpenVPN")
            });
        if let Err(stop_error) = stopped {
            let connection = recovery.take().unwrap_or_else(|| fallback_recovery.clone());
            let mut retained = state.clone();
            retained.connection = Some(connection);
            *state = retained.clone();
            store
                .save(&retained)
                .context("persist failed OpenVPN startup ownership")?;
            *state = retained;
            return Err(error).context(format!(
                "OpenVPN startup and process rollback failed: {stop_error:#}"
            ));
        }
        if let Some(identity_error) = identity_error {
            let remains = Command::new(&prepared.ip)
                .args(["link", "show", "dev", &prepared.interface])
                .env("PATH", &prepared.path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if remains {
                let mut retained = state.clone();
                retained.connection = Some(fallback_recovery);
                *state = retained.clone();
                store
                    .save(&retained)
                    .context("persist unidentified failed OpenVPN startup recovery state")?;
                *state = retained;
                return Err(error).context(format!(
                    "OpenVPN startup was stopped, but its remaining interface ownership could not be established: {identity_error}"
                ));
            }
        }
        if let Some(connection) = recovery {
            if let Err(cleanup_error) = cleanup_owned_openvpn_artifacts(prepared, &connection) {
                let mut retained = state.clone();
                retained.connection = Some(connection);
                *state = retained.clone();
                store
                    .save(&retained)
                    .context("persist incomplete OpenVPN startup cleanup ownership")?;
                *state = retained;
                return Err(error).context(format!(
                    "OpenVPN startup rollback cleanup failed; recovery ownership was retained: {cleanup_error:#}"
                ));
            }
        } else {
            if let Err(remove_error) = fs::remove_dir_all(&directory) {
                let mut retained = state.clone();
                retained.connection = Some(fallback_recovery);
                *state = retained.clone();
                store
                    .save(&retained)
                    .context("persist failed OpenVPN runtime cleanup ownership")?;
                return Err(error).context(format!(
                    "OpenVPN startup rollback left runtime files for recovery: {remove_error:#}"
                ));
            }
        }
        return Err(error).context("OpenVPN startup rolled back");
    }
    Ok((child.id(), directory))
}

fn stop_process_group(kill: &Path, path: &std::ffi::OsStr, pid: u32, name: &str) -> Result<()> {
    let group_alive = || {
        process_group_has_live_members(pid).unwrap_or_else(|| {
            Command::new(kill)
                .args(["-0", "--", &format!("-{pid}")])
                .env("PATH", path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        })
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
    if !status.success() && process_group_has_live_members(pid).unwrap_or(true) {
        bail!("force-stop {name} process exited with {status}");
    }
    for _ in 0..20 {
        if !process_group_has_live_members(pid).unwrap_or(true) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("{name} process group remained live after force-stop")
}

fn process_stat_identity(stat: &str) -> Option<(char, u32, u64)> {
    let fields = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    Some((
        fields.first()?.chars().next()?,
        fields.get(2)?.parse().ok()?,
        fields.get(19)?.parse().ok()?,
    ))
}

fn process_stat_is_live_group_member(stat: &str, group: u32) -> bool {
    process_stat_identity(stat)
        .is_some_and(|(state, process_group, _)| process_group == group && state != 'Z')
}

fn process_group_has_live_members(group: u32) -> Option<bool> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.filter_map(|entry| entry.ok()) {
        let Some(pid) = entry.file_name().to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        if process_stat_is_live_group_member(&stat, group) {
            return Some(true);
        }
    }
    Some(false)
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

