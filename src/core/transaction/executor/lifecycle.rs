fn stop_openvpn_for_rollback(prepared: &PreparedOpenVpn, pid: u32) -> Result<()> {
    if stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN").is_ok() {
        return Ok(());
    }
    force_stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN")
        .context("force-stop OpenVPN rollback process group")
}

fn cleanup_failed_openvpn_start(
    store: &Store,
    state: &mut State,
    prepared: &PreparedOpenVpn,
    mut recovery: Connection,
) -> Result<()> {
    let pid = recovery.pid.context("failed OpenVPN startup has no PID")?;
    let runtime_directory = recovery
        .runtime_directory
        .as_deref()
        .map(Path::new)
        .context("failed OpenVPN startup has no runtime directory")?;
    if let Err(stop_error) = stop_openvpn_for_rollback(prepared, pid) {
        recovery.recovery_required = true;
        let mut retained = state.clone();
        retained.connection = Some(recovery);
        *state = retained.clone();
        store
            .save(&retained)
            .context("persist failed OpenVPN startup ownership")?;
        return Err(stop_error).context("stop failed OpenVPN startup");
    }
    let interface_exists = Command::new(&prepared.ip)
        .args(["link", "show", "dev", &prepared.interface])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(true);
    if interface_exists {
        if recovery.interface_index.is_some() && recovery.interface_owner.is_some() {
            if let Err(cleanup_error) = cleanup_owned_openvpn_artifacts(prepared, &recovery) {
                recovery.recovery_required = true;
                let mut retained = state.clone();
                retained.connection = Some(recovery);
                *state = retained.clone();
                store
                    .save(&retained)
                    .context("persist incomplete OpenVPN startup cleanup ownership")?;
                return Err(cleanup_error).context("clean failed OpenVPN startup artifacts");
            }
            return Ok(());
        }
        recovery.recovery_required = true;
        let mut retained = state.clone();
        retained.connection = Some(recovery);
        *state = retained.clone();
        store
            .save(&retained)
            .context("persist partial OpenVPN startup ownership")?;
        bail!("failed OpenVPN startup interface remained without exact ownership identity");
    }
    fs::remove_dir_all(runtime_directory).context("remove rolled-back OpenVPN runtime directory")
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
    let logging = state.settings.logging;
    let (pid, runtime_directory) =
        start_openvpn(store, state, &id, &prepared, logging)?;
    let mut connection = Connection {
        profile_id: id,
        recovery_required: true,
        pid: Some(pid),
        process_start_ticks: process_start_ticks(pid),
        interface: Some(prepared.interface.clone()),
        interface_index: None,
        interface_owner: None,
        runtime_directory: Some(runtime_directory.to_string_lossy().into_owned()),
        xray_route: None,
    };
    let interface_owner = uuid::Uuid::new_v4().to_string();
    let owner_result = Command::new(&prepared.ip)
        .args([
            "link",
            "set",
            "dev",
            &prepared.interface,
            "alias",
            &interface_owner,
        ])
        .env("PATH", &prepared.path)
        .status();
    if !matches!(&owner_result, Ok(status) if status.success()) {
        let owner_error = match owner_result {
            Ok(status) => anyhow!("OpenVPN ownership marking exited with {status}"),
            Err(error) => error.into(),
        };
        cleanup_failed_openvpn_start(store, state, &prepared, connection)
            .context("OpenVPN ownership marking failed and rollback required recovery")?;
        return Err(owner_error).context("mark OpenVPN interface ownership; connection rolled back");
    }
    connection.interface_owner = Some(interface_owner);
    connection.interface_index = match interface_index(&prepared.interface) {
        Ok(index) => Some(index),
        Err(error) => {
            cleanup_failed_openvpn_start(store, state, &prepared, connection)
                .context("OpenVPN interface identity failed and rollback required recovery")?;
            return Err(error).context("read OpenVPN interface identity; connection rolled back");
        }
    };
    let Some(start_ticks) = connection.process_start_ticks else {
        cleanup_failed_openvpn_start(store, state, &prepared, connection)
            .context("OpenVPN process identity failed and rollback required recovery")?;
        bail!("OpenVPN process identity could not be read; connection rolled back");
    };
    connection.process_start_ticks = Some(start_ticks);
    connection.recovery_required = false;
    let mut updated = state.clone();
    updated.connection = Some(connection);
    if let Err(error) = store.save(&updated) {
        if let Err(rollback_error) = stop_openvpn_for_rollback(&prepared, pid) {
            if let Some(connection) = updated.connection.as_mut() {
                connection.recovery_required = true;
            }
            *state = updated.clone();
            return match store.save(&updated) {
                Ok(()) => {
                    *state = updated;
                    Err(error).context(format!(
                        "OpenVPN state save and process rollback failed; recovery ownership was retained: {rollback_error:#}"
                    ))
                }
                Err(recovery_error) => Err(error).context(format!(
                    "OpenVPN state save, process rollback, and recovery ownership persistence failed: {rollback_error:#}; {recovery_error:#}"
                )),
            };
        }
        let ownership = updated
            .connection
            .as_ref()
            .context("OpenVPN rollback ownership metadata is missing")?;
        if let Err(cleanup_error) = cleanup_owned_openvpn_artifacts(&prepared, ownership) {
            if let Some(connection) = updated.connection.as_mut() {
                connection.recovery_required = true;
            }
            *state = updated.clone();
            return match store.save(&updated) {
                Ok(()) => {
                    *state = updated;
                    Err(error).context(format!(
                        "OpenVPN state save failed and external rollback was incomplete; recovery ownership was retained: {cleanup_error:#}"
                    ))
                }
                Err(recovery_error) => Err(error).context(format!(
                    "OpenVPN state save failed, external rollback was incomplete, and recovery ownership could not be persisted: {cleanup_error:#}; {recovery_error:#}"
                )),
            };
        }
        return Err(error).context("OpenVPN connection rolled back after state save failed");
    }
    *state = updated;
    Ok("connected".into())
}

fn disconnect_openvpn(
    store: &Store,
    state: &mut State,
    profile: &Profile,
    connection: &Connection,
    dry_run: bool,
) -> Result<String> {
    let prepared = prepare_openvpn(store, profile, &state.settings)?;
    let pid = match verify_connection_process(connection) {
        Ok(pid) => pid,
        Err(_identity_error) => {
            let interface_exists = Command::new(&prepared.ip)
                .args(["link", "show", "dev", &prepared.interface])
                .env("PATH", &prepared.path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success();
            if interface_exists {
                verify_openvpn_interface_identity(&prepared.interface, connection)
                    .context("OpenVPN process is stale and interface ownership changed")?;
            }
            if dry_run {
                return Ok(if interface_exists {
                    "delete the indexed stale OpenVPN interface and private runtime directory\nrollback: restore the ownership record".into()
                } else {
                    "remove the stale OpenVPN private runtime directory and clear its ownership record\nrollback: restore the ownership record".into()
                });
            }
            let mut disconnected = state.clone();
            disconnected.connection = None;
            store
                .save(&disconnected)
                .context("persist pending stale OpenVPN cleanup")?;
            if let Err(error) = cleanup_owned_openvpn_artifacts(&prepared, connection) {
                if let Some(connection) = state.connection.as_mut() {
                    connection.recovery_required = true;
                }
                if let Err(persist_error) = store.save(state) {
                    return Err(error).context(format!(
                        "stale OpenVPN cleanup failed and ownership metadata could not be persisted; recovery remains in memory: {persist_error:#}"
                    ));
                }
                return Err(error).context("clean stale OpenVPN resources");
            }
            *state = disconnected;
            return Ok("disconnected".into());
        }
    };
    let configuration = openvpn_process_configuration(pid, Some(&prepared.executable))?;
    let expected_interface_index = connection
        .interface_index
        .context("OpenVPN connection has no saved interface ownership index")?;
    let expected_interface_owner = connection
        .interface_owner
        .clone()
        .context("OpenVPN connection has no saved interface ownership alias")?;
    let runtime_directory = configuration.parent().map(Path::to_path_buf);
    let runtime_directory_text = match runtime_directory.as_deref() {
        Some(directory) => Some(
            directory
                .to_str()
                .context("OpenVPN runtime directory is not valid UTF-8")?,
        ),
        None => None,
    };
    if let (Some(saved), Some(actual)) = (
        connection.runtime_directory.as_deref(),
        runtime_directory.as_deref(),
    ) && Path::new(saved) != actual
    {
        bail!("saved OpenVPN runtime directory does not match the owned process configuration");
    }
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
        if let Some(connection) = state.connection.as_mut() {
            connection.recovery_required = true;
        }
        if let Err(persist_error) = store.save(state) {
            let cleanup = force_stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN")
                .and_then(|()| cleanup_owned_openvpn_artifacts(&prepared, connection));
            return match cleanup {
                Ok(()) => {
                    *state = disconnected;
                    Err(error).context(format!(
                        "OpenVPN disconnect failed and connection state could not be restored: {persist_error:#}; owned artifacts were removed"
                    ))
                }
                Err(cleanup_error) => Err(error).context(format!(
                    "OpenVPN disconnect, state restoration, and final cleanup failed; recovery remains in memory: {persist_error:#}; {cleanup_error:#}"
                )),
            };
        }
        return Err(error).context("OpenVPN disconnect failed; connection state restored");
    }
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
            if interface_index(&prepared.interface)? != expected_interface_index
                || interface_owner(&prepared.interface)? != expected_interface_owner
            {
                bail!("OpenVPN tunnel interface ownership changed during disconnect");
            }
            let status = Command::new(&prepared.ip)
                .args(["link", "delete", "dev", &prepared.interface])
                .env("PATH", &prepared.path)
                .status()?;
            if !status.success() {
                bail!("OpenVPN tunnel interface remained after process termination");
            }
        }
        remove_openvpn_runtime(runtime_directory_text)?;
        Ok(())
    })();
    if let Err(error) = cleanup {
        let mut orphaned = disconnected.clone();
        let mut orphan_connection = connection.clone();
        orphan_connection.pid = None;
        orphan_connection.process_start_ticks = None;
        orphan_connection.recovery_required = true;
        orphan_connection.interface_index = Some(expected_interface_index);
        orphan_connection.interface_owner = Some(expected_interface_owner);
        orphan_connection.runtime_directory = runtime_directory_text.map(str::to_owned);
        orphaned.connection = Some(orphan_connection.clone());
        *state = orphaned.clone();
        if let Err(persist_error) = store.save(&orphaned) {
            return match cleanup_owned_openvpn_artifacts(&prepared, &orphan_connection) {
                Ok(()) => {
                    *state = disconnected;
                    Err(error).context(format!(
                        "OpenVPN disconnect cleanup failed and orphan ownership metadata could not be persisted: {persist_error:#}; remaining owned artifacts were removed"
                    ))
                }
                Err(cleanup_error) => Err(error).context(format!(
                    "OpenVPN disconnect cleanup failed, orphan ownership metadata could not be persisted, and final cleanup failed; recovery remains in memory: {persist_error:#}; {cleanup_error:#}"
                )),
            };
        }
        *state = orphaned;
        return Err(error).context(
            "OpenVPN disconnect cleanup failed; orphan ownership metadata was retained for retry",
        );
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
    refresh_connection(store, state)?;
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
        .context("selected profile no longer exists")?
        .clone();
    if !profile.enabled {
        bail!("profile is disabled");
    }
    if dry_run {
        check_profile_dependencies(store, &profile, &state.settings)?;
    }

    if profile.protocol == Protocol::OpenVpn {
        return connect_openvpn(store, state, &profile, id, dry_run);
    }
    if profile.protocol == Protocol::Xray {
        return connect_xray(store, state, &profile, id, dry_run);
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
        .with_context(|| format!("run {}", plan.program()))
    {
        Ok(status) => status,
        Err(error) => return fail_with_rollback(store, state, &profile.id, &plan, &prepared, error),
    };
    if !status.success() {
        return fail_with_rollback(
            store,
            state,
            &profile.id,
            &plan,
            &prepared,
            anyhow!("{} exited with {status}", plan.program()),
        );
    }
    let interface_index = match interface_index(&prepared.interface) {
        Ok(index) => index,
        Err(error) => return fail_with_rollback(store, state, &profile.id, &plan, &prepared, error),
    };
    let interface_owner = uuid::Uuid::new_v4().to_string();
    let ownership = Command::new(&prepared.ip)
        .args([
            "link",
            "set",
            "dev",
            &prepared.interface,
            "alias",
            &interface_owner,
        ])
        .env("PATH", &prepared.path)
        .status();
    match ownership {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return fail_with_rollback(
                store,
                state,
                &profile.id,
                &plan,
                &prepared,
                anyhow!("mark WireGuard-family interface ownership exited with {status}"),
            );
        }
        Err(error) => {
            return fail_with_rollback(
                store,
                state,
                &profile.id,
                &plan,
                &prepared,
                error.into(),
            );
        }
    }
    let connection = Connection {
        profile_id: profile.id.clone(),
        recovery_required: false,
        pid: None,
        process_start_ticks: None,
        interface: plan.interface.clone(),
        interface_index: Some(interface_index),
        interface_owner: Some(interface_owner),
        runtime_directory: None,
        xray_route: None,
    };
    let mut updated = state.clone();
    updated.connection = Some(connection);
    if let Err(save_error) = store.save(&updated) {
        let identity = updated
            .connection
            .as_ref()
            .context("WireGuard-family rollback ownership metadata is missing")?;
        verify_openvpn_interface_identity(&prepared.interface, identity)
            .context("refusing failed-connect rollback without exact interface ownership")?;
        return match rollback(&plan, &prepared, updated.connection.as_ref()) {
            Ok(()) => Err(save_error).context("connection rolled back after state save failed"),
            Err(rollback_error) => {
                if let Some(connection) = updated.connection.as_mut() {
                    connection.recovery_required = true;
                }
                *state = updated.clone();
                match store.save(&updated) {
                    Ok(()) => Err(save_error).context(format!(
                            "state save and tunnel rollback failed; recovery ownership was retained: {rollback_error:#}"
                        )),
                    Err(recovery_error) => Err(save_error).context(format!(
                        "state save, tunnel rollback, and recovery ownership persistence failed; recovery remains in memory: {rollback_error:#}; {recovery_error:#}"
                    )),
                }
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
    if dry_run {
        check_profile_dependencies(store, &profile, &state.settings)?;
    }
    if profile.protocol == Protocol::Xray {
        return disconnect_xray(store, state, &profile, &connection, dry_run);
    }
    if profile.protocol == Protocol::OpenVpn {
        return disconnect_openvpn(store, state, &profile, &connection, dry_run);
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
        let mut disconnected = state.clone();
        disconnected.connection = None;
        store
            .save(&disconnected)
            .context("clear stale WireGuard-family connection")?;
        *state = disconnected;
        return Ok("disconnected".into());
    }
    verify_openvpn_interface_identity(&prepared.interface, &connection)
        .context("refusing to disconnect WireGuard-family interface without exact ownership")?;
    let mut disconnected = state.clone();
    disconnected.connection = None;
    store
        .save(&disconnected)
        .context("persist pending WireGuard-family disconnect")?;
    verify_openvpn_interface_identity(&prepared.interface, &connection)
        .context("WireGuard-family interface ownership changed before disconnect")?;
    let operation = network_command(&prepared.program, &prepared.args, &prepared)
        .status()
        .with_context(|| format!("run {}", plan.program()))
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(anyhow!("{} exited with {status}", plan.program()))
            }
        });
    if let Err(error) = operation {
        if let Err(rollback_error) = rollback(&plan, &prepared, Some(&connection)) {
            if let Some(connection) = state.connection.as_mut() {
                connection.recovery_required = true;
            }
            if let Err(persist_error) = store.save(state) {
                return Err(error).context(format!(
                    "WireGuard-family disconnect, rollback, and recovery-state persistence failed; recovery remains in memory and no unowned interface deletion was attempted: {rollback_error:#}; {persist_error:#}"
                ));
            }
            return Err(error).context(format!(
                "WireGuard-family disconnect and rollback failed; ownership metadata was retained: {rollback_error:#}"
            ));
        }
        if let Err(identity_error) = restore_quick_interface_identity(&prepared, state) {
            if let Some(connection) = state.connection.as_mut() {
                connection.recovery_required = true;
            }
            return match store.save(state) {
                Ok(()) => Err(error).context(format!(
                    "disconnect rollback restored an interface whose exact ownership could not be re-established; recovery metadata was retained: {identity_error:#}"
                )),
                Err(persist_error) => Err(error).context(format!(
                    "disconnect rollback restored an interface whose exact ownership could not be re-established and recovery metadata could not be persisted; recovery remains in memory: {identity_error:#}; {persist_error:#}"
                )),
            };
        }
        if let Err(persist_error) = store.save(state) {
            let mut recovery = disconnected.clone();
            let mut recovery_connection = connection.clone();
            recovery_connection.recovery_required = true;
            recovery.connection = Some(recovery_connection);
            let Some(identity) = recovery.connection.as_ref() else {
                *state = disconnected.clone();
                return Err(error).context(format!(
                    "disconnect rollback restored no ownership identity and connected state restoration failed: {persist_error:#}"
                ));
            };
            if let Err(identity_error) =
                verify_openvpn_interface_identity(&prepared.interface, identity)
            {
                *state = recovery.clone();
                let _ = store.save(&recovery);
                return Err(error).context(format!(
                    "refusing disconnected cleanup after ownership changed: {identity_error:#}; connected state restoration failed: {persist_error:#}"
                ));
            }
            *state = disconnected.clone();
            let cleanup = network_command(&prepared.program, &prepared.args, &prepared)
                .status()
                .context("restore disconnected network state after persistence failure");
            return match cleanup {
                Ok(status) if status.success() => Err(error).context(format!(
                    "disconnect rolled back, but connected state restoration failed: {persist_error:#}; network returned to persisted disconnected state"
                )),
                cleanup_result => {
                    *state = recovery.clone();
                    if store.save(&recovery).is_ok() {
                        return Err(error).context(format!(
                            "disconnect rolled back and disconnected cleanup failed, but ownership metadata was retained: {persist_error:#}; cleanup: {cleanup_result:?}"
                        ));
                    }
                    match cleanup_result {
                        Ok(status) => Err(error).context(format!(
                            "disconnect rolled back, connected state restoration failed, cleanup exited with {status}, and ownership persistence retry failed; recovery remains in memory: {persist_error:#}"
                        )),
                        Err(cleanup_error) => Err(error).context(format!(
                            "disconnect rolled back, connected state restoration failed, cleanup failed, and ownership persistence retry failed; recovery remains in memory: {persist_error:#}; {cleanup_error:#}"
                        )),
                    }
                }
            };
        }
        return Err(error).context("WireGuard-family disconnect failed; connection restored");
    }
    *state = disconnected;
    Ok("disconnected".into())
}

fn disconnect_plan(profile: &Profile, connection: &Connection) -> Result<CommandPlan> {
    Ok(CommandPlan {
        mutation: ReversibleMutation::quick(
            quick_program(&profile.protocol)?,
            QuickDirection::Down,
            profile.source.clone(),
        ),
        interface: connection.interface.clone(),
    })
}

fn restore_quick_interface_identity(
    prepared: &PreparedPlan,
    state: &mut State,
) -> Result<()> {
    let owner = state
        .connection
        .as_ref()
        .and_then(|connection| connection.interface_owner.as_deref())
        .context("WireGuard-family connection has no ownership alias")?
        .to_owned();
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
        .context("restore WireGuard-family interface ownership alias")?;
    if !status.success() {
        bail!("restore WireGuard-family interface ownership alias exited with {status}");
    }
    let index = interface_index(&prepared.interface)?;
    let connection = state
        .connection
        .as_mut()
        .context("WireGuard-family connection ownership record is missing")?;
    connection.interface_index = Some(index);
    connection.interface_owner = Some(owner);
    Ok(())
}

pub fn refresh_connection(store: &Store, state: &mut State) -> Result<()> {
    if let Some(connection) = state.connection.as_mut()
        && connection.process_start_ticks.is_none()
        && let Some(pid) = connection.pid
    {
        connection.process_start_ticks = process_start_ticks(pid);
    }
    let stale = state.connection.as_ref().is_some_and(|connection| {
        if connection.recovery_required {
            return true;
        }
        let Some(profile) = state.profiles.get(&connection.profile_id) else {
            return true;
        };
        if let Some(pid) = connection.pid {
            if connection.process_start_ticks != process_start_ticks(pid) {
                return true;
            }
            if profile.protocol == Protocol::Xray {
                return match xray_process_info(pid) {
                    Ok(worker) => {
                        connection.interface.as_deref() != Some(&worker.interface)
                            || verify_openvpn_interface_identity(&worker.interface, connection).is_err()
                    }
                    Err(_) => true,
                };
            }
            if profile.protocol == Protocol::OpenVpn {
                return openvpn_process_configuration(pid, None).is_err();
            }
            return !process_belongs_to_profile(pid, profile);
        }
        let Some(interface) = connection.interface.as_deref() else {
            return true;
        };
        let Ok(spec) = quick_spec(&profile.protocol) else {
            return true;
        };
        let Ok(executable) = resolve_network_program(spec.probe_program) else {
            return true;
        };
        let Ok(path) = std::env::join_paths(network_program_directories()) else {
            return true;
        };
        let Ok(configuration) = store.validated_profile_text(profile) else {
            return true;
        };
        let expected_peers = configuration_values(&configuration, "PublicKey");
        expected_peers.is_empty()
            || !interface_matches_profile(&executable, interface, &expected_peers, &path)
                .unwrap_or(false)
            || verify_openvpn_interface_identity(interface, connection).is_err()
    });
    if stale {
        bail!("recorded connection is stale; ownership metadata was retained for recovery");
    }
    Ok(())
}

fn process_belongs_to_profile(pid: u32, profile: &Profile) -> bool {
    let Ok(command_line) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    command_line
        .split(|byte| *byte == 0)
        .any(|argument| argument == profile.source.as_bytes())
}

pub(super) fn interface_index(interface: &str) -> Result<u32> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    {
        bail!("invalid network interface name");
    }
    fs::read_to_string(Path::new("/sys/class/net").join(interface).join("ifindex"))
        .context("read network interface index")?
        .trim()
        .parse()
        .context("parse network interface index")
}

pub(super) fn interface_owner(interface: &str) -> Result<String> {
    let owner = fs::read_to_string(Path::new("/sys/class/net").join(interface).join("ifalias"))
        .context("read network interface ownership alias")?;
    let owner = owner.trim();
    if owner.is_empty() {
        bail!("network interface has no ownership alias");
    }
    Ok(owner.to_owned())
}

pub(super) fn verify_openvpn_interface_identity(
    interface: &str,
    connection: &Connection,
) -> Result<()> {
    let saved_index = connection
        .interface_index
        .context("stale OpenVPN interface has no saved ownership index")?;
    if interface_index(interface)? != saved_index {
        bail!("stale OpenVPN interface ownership index changed");
    }
    let saved_owner = connection
        .interface_owner
        .as_deref()
        .context("stale OpenVPN interface has no saved ownership alias")?;
    if interface_owner(interface)? != saved_owner {
        bail!("stale OpenVPN interface ownership alias changed");
    }
    Ok(())
}

fn remove_openvpn_runtime(directory: Option<&str>) -> Result<()> {
    let Some(directory) = directory else {
        return Ok(());
    };
    let directory = Path::new(directory);
    if directory.parent() != Some(Path::new("/run/amn")) {
        bail!("saved OpenVPN runtime directory is outside /run/amn");
    }
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(directory).context("remove staged OpenVPN configuration")
        }
        Ok(_) => bail!("saved OpenVPN runtime path is not an owned directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect staged OpenVPN configuration"),
    }
}

fn cleanup_owned_openvpn_artifacts(
    prepared: &PreparedOpenVpn,
    connection: &Connection,
) -> Result<()> {
    let interface_exists = Command::new(&prepared.ip)
        .args(["link", "show", "dev", &prepared.interface])
        .env("PATH", &prepared.path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();
    if interface_exists {
        verify_openvpn_interface_identity(&prepared.interface, connection)?;
        let status = Command::new(&prepared.ip)
            .args(["link", "delete", "dev", &prepared.interface])
            .env("PATH", &prepared.path)
            .status()
            .context("delete indexed stale OpenVPN interface")?;
        if !status.success() {
            bail!("delete indexed stale OpenVPN interface exited with {status}");
        }
    }
    remove_openvpn_runtime(connection.runtime_directory.as_deref())
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

fn resolve_network_program(program: &str) -> Result<PathBuf> {
    let candidates = if Path::new(program).is_absolute() {
        vec![PathBuf::from(program)]
    } else if is_bundled_network_program(program) {
        bundled_program_directories()
            .into_iter()
            .map(|directory| directory.join(program))
            .collect()
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

fn is_bundled_network_program(program: &str) -> bool {
    matches!(
        program,
        "wg"
            | "wg-quick"
            | "wireguard-go"
            | "awg"
            | "awg-quick"
            | "amneziawg-go"
            | "openvpn"
            | "tun2socks"
            | "amnezia-xray-runner"
    )
}

fn bundled_program_directories() -> Vec<PathBuf> {
    let Ok(executable) = std::env::current_exe() else {
        return Vec::new();
    };
    executable_relative_program_directories(&executable)
        .into_iter()
        .filter_map(|directory| fs::canonicalize(directory).ok())
        .filter(|directory| is_trusted_network_path(directory))
        .collect()
}

fn executable_relative_program_directories(executable: &Path) -> Vec<PathBuf> {
    let Some(directory) = executable.parent() else {
        return Vec::new();
    };
    vec![
        directory.join("libexec").join("amn"),
        directory.join("..").join("libexec").join("amn"),
    ]
}

fn network_program_directories() -> Vec<PathBuf> {
    let mut directories = bundled_program_directories();
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

