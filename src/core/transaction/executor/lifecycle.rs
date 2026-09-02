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
        disconnecting: false,
        pid: Some(pid),
        process_start_ticks: process_start_ticks(pid),
        interface: Some(prepared.interface.clone()),
        interface_index: None,
        interface_owner: None,
        runtime_directory: Some(runtime_directory.to_string_lossy().into_owned()),
        quick_root_owned: false,
        xray_route: None,
        xray_owned_routes: Vec::new(),
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
    let mut connection = connection.clone();
    if connection.process_start_ticks.is_none()
        && let Some(pid) = connection.pid
        && let Some(runtime_directory) = connection.runtime_directory.as_deref()
        && openvpn_process_configuration(pid, Some(&prepared.executable)).is_ok_and(|path| {
            path == Path::new(runtime_directory).join("openvpn.conf")
        })
        && connection
            .interface
            .as_deref()
            .is_some_and(|interface| verify_openvpn_interface_identity(interface, &connection).is_ok())
    {
        connection.process_start_ticks = process_start_ticks(pid);
        if !dry_run && let Some(current) = state.connection.as_mut() {
            current.process_start_ticks = connection.process_start_ticks;
        }
    }
    let pid = match verify_connection_process(&connection) {
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
                verify_openvpn_interface_identity(&prepared.interface, &connection)
                    .context("OpenVPN process is stale and interface ownership changed")?;
            }
            if connection.pid.is_some_and(|pid| {
                openvpn_process_configuration(pid, Some(&prepared.executable)).is_ok()
            }) {
                bail!(
                    "legacy OpenVPN process has no complete start-time and interface ownership identity"
                );
            }
            if dry_run {
                return Ok(if interface_exists {
                    "delete the indexed stale OpenVPN interface and private runtime directory\nrollback: restore the ownership record".into()
                } else {
                    "remove the stale OpenVPN private runtime directory and clear its ownership record\nrollback: restore the ownership record".into()
                });
            }
            let disconnected = disconnected_state(state);
            let pending = pending_disconnect_state(state)?;
            store
                .save(&pending)
                .context("persist pending stale OpenVPN cleanup")?;
            if let Err(error) = cleanup_owned_openvpn_artifacts(&prepared, &connection) {
                if let Some(connection) = state.connection.as_mut() {
                    connection.recovery_required = true;
                    connection.disconnecting = true;
                }
                if let Err(persist_error) = store.save(state) {
                    return Err(error).context(format!(
                        "stale OpenVPN cleanup failed and ownership metadata could not be persisted; recovery remains in memory: {persist_error:#}"
                    ));
                }
                return Err(error).context("clean stale OpenVPN resources");
            }
            store
                .save(&disconnected)
                .context("persist completed stale OpenVPN cleanup")?;
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
    let saved_runtime = connection
        .runtime_directory
        .as_deref()
        .context("OpenVPN connection has no saved runtime ownership path")?;
    if runtime_directory
        .as_deref()
        .is_none_or(|actual| Path::new(saved_runtime) != actual)
    {
        bail!("saved OpenVPN runtime directory does not match the owned process configuration");
    }
    if dry_run {
        return Ok(format!(
            "terminate owned OpenVPN process group {pid}\nrollback: restart the validated OpenVPN profile"
        ));
    }
    let disconnected = disconnected_state(state);
    let pending = pending_disconnect_state(state)?;
    store
        .save(&pending)
        .context("persist pending OpenVPN disconnect")?;
    if let Err(error) = stop_process_group(&prepared.kill, &prepared.path, pid, "OpenVPN") {
        if let Some(connection) = state.connection.as_mut() {
            connection.recovery_required = true;
        }
        if let Err(persist_error) = store.save(state) {
            if let Some(connection) = state.connection.as_mut() {
                connection.disconnecting = true;
            }
            return Err(error).context(format!(
                "OpenVPN disconnect failed and ordinary state restoration failed; pending ownership remains durable and recovery remains in memory: {persist_error:#}"
            ));
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
        let mut orphaned = pending.clone();
        let mut orphan_connection = connection.clone();
        orphan_connection.pid = None;
        orphan_connection.process_start_ticks = None;
        orphan_connection.recovery_required = true;
        orphan_connection.disconnecting = true;
        orphan_connection.interface_index = Some(expected_interface_index);
        orphan_connection.interface_owner = Some(expected_interface_owner);
        orphan_connection.runtime_directory = runtime_directory_text.map(str::to_owned);
        orphaned.connection = Some(orphan_connection.clone());
        *state = orphaned.clone();
        if let Err(persist_error) = store.save(&orphaned) {
            return match cleanup_owned_openvpn_artifacts(&prepared, &orphan_connection) {
                Ok(()) => {
                    store
                        .save(&disconnected)
                        .context("persist completed OpenVPN cleanup")?;
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
    store
        .save(&disconnected)
        .context("persist completed OpenVPN disconnect")?;
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

    let preflight = prepare_network_plan(
        store,
        &profile,
        &plan,
        &state.settings,
        false,
        None,
    )?;
    if preflight.interface_existed {
        bail!(
            "refusing to connect because interface already exists: {}",
            preflight.interface
        );
    }
    drop(preflight);
    let planned_runtime = Path::new("/etc/wireguard")
        .join(uuid::Uuid::new_v4().simple().to_string());
    let mut staging = state.clone();
    staging.connection = Some(Connection {
        profile_id: profile.id.clone(),
        recovery_required: true,
        disconnecting: false,
        pid: None,
        process_start_ticks: None,
        interface: plan.interface.clone(),
        interface_index: None,
        interface_owner: None,
        runtime_directory: Some(planned_runtime.to_string_lossy().into_owned()),
        quick_root_owned: false,
        xray_route: None,
        xray_owned_routes: Vec::new(),
    });
    store
        .save(&staging)
        .context("persist WireGuard-family connect staging ownership before filesystem mutation")?;
    *state = staging;
    let mut prepared = prepare_network_plan(
        store,
        &profile,
        &plan,
        &state.settings,
        true,
        Some(&planned_runtime),
    )?;
    if prepared.interface_existed {
        prepared.cleanup_runtime().context(
            "clean WireGuard-family staging after an interface appeared during connect preflight",
        )?;
        let disconnected = disconnected_state(state);
        store
            .save(&disconnected)
            .context("clear WireGuard-family staging ownership after connect preflight changed")?;
        *state = disconnected;
        bail!(
            "refusing to connect because interface appeared during preflight: {}",
            prepared.interface
        );
    }
    let mut command = network_command(&prepared.program, &prepared.args, &prepared);
    command.stdin(Stdio::null());
    let mut log = if state.settings.logging {
        let log_path = store
            .root()
            .join("logs")
            .join(format!("connection-{}.log", uuid::Uuid::new_v4().simple()));
        Some(create_private_log(&log_path)?)
    } else {
        None
    };

    let output = match command
        .output()
        .with_context(|| format!("run {}", plan.program()))
    {
        Ok(output) => output,
        Err(error) => return fail_with_rollback(store, state, &profile.id, &plan, &prepared, error),
    };
    if let Some(log) = log.as_mut() {
        let logged = std::io::Write::write_all(log, &output.stdout)
            .and_then(|()| std::io::Write::write_all(log, &output.stderr));
        if let Err(error) = logged {
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
    if !output.status.success() {
        return fail_with_rollback(
            store,
            state,
            &profile.id,
            &plan,
            &prepared,
            network_command_failure(plan.program(), &output),
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
    if let Err(error) = prepared.cleanup_runtime() {
        let (runtime_directory, quick_root_owned) = prepared.retained_runtime();
        let rollback_material_exists = prepared
            .rollback_args
            .last()
            .is_some_and(|argument| Path::new(argument).is_file());
        if rollback_material_exists {
            return fail_with_rollback(
                store,
                state,
                &profile.id,
                &plan,
                &prepared,
                error.context("clean connected WireGuard-family staged runtime"),
            );
        }
        let mut retained = state.clone();
        retained.connection = Some(Connection {
            profile_id: profile.id.clone(),
            recovery_required: true,
            disconnecting: false,
            pid: None,
            process_start_ticks: None,
            interface: plan.interface.clone(),
            interface_index: Some(interface_index),
            interface_owner: Some(interface_owner),
            runtime_directory: runtime_directory
                .map(|path| path.to_string_lossy().into_owned()),
            quick_root_owned,
            xray_route: None,
            xray_owned_routes: Vec::new(),
        });
        *state = retained.clone();
        return match store.save(&retained) {
            Ok(()) => Err(error).context(
                "WireGuard-family interface connected, but runtime-root cleanup requires a disconnect retry",
            ),
            Err(persist_error) => Err(error).context(format!(
                "WireGuard-family interface connected, but runtime-root cleanup and recovery persistence failed; exact ownership remains in memory: {persist_error:#}"
            )),
        };
    }
    let connection = Connection {
        profile_id: profile.id.clone(),
        recovery_required: false,
        disconnecting: false,
        pid: None,
        process_start_ticks: None,
        interface: plan.interface.clone(),
        interface_index: Some(interface_index),
        interface_owner: Some(interface_owner),
        runtime_directory: None,
        quick_root_owned: false,
        xray_route: None,
        xray_owned_routes: Vec::new(),
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

fn pending_disconnect_state(state: &State) -> Result<State> {
    let mut pending = state.clone();
    let connection = pending
        .connection
        .as_mut()
        .context("disconnect ownership record is missing")?;
    connection.disconnecting = true;
    Ok(pending)
}

fn disconnected_state(state: &State) -> State {
    let mut disconnected = state.clone();
    disconnected.connection = None;
    disconnected
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
    if connection.runtime_directory.is_some() || connection.quick_root_owned {
        let pending = pending_disconnect_state(state)?;
        store
            .save(&pending)
            .context("persist pending retained WireGuard-family runtime cleanup")?;
        if let Err(error) = cleanup_retained_quick_runtime(
            connection.runtime_directory.as_deref().map(Path::new),
            connection.quick_root_owned,
        ) {
            if let Some(connection) = state.connection.as_mut() {
                connection.recovery_required = true;
                connection.disconnecting = true;
            }
            let _ = store.save(state);
            return Err(error).context("clean retained WireGuard-family runtime");
        }
        if let Some(saved) = state.connection.as_mut() {
            saved.runtime_directory = None;
            saved.quick_root_owned = false;
        }
        store
            .save(state)
            .context("persist completed retained WireGuard-family runtime cleanup")?;
    }
    let planned_runtime = Path::new("/etc/wireguard")
        .join(uuid::Uuid::new_v4().simple().to_string());
    let mut staging = pending_disconnect_state(state)?;
    if let Some(connection) = staging.connection.as_mut() {
        connection.runtime_directory = Some(planned_runtime.to_string_lossy().into_owned());
        connection.quick_root_owned = false;
    }
    store
        .save(&staging)
        .context("persist WireGuard-family staging ownership before filesystem mutation")?;
    *state = staging;
    let mut prepared = prepare_network_plan(
        store,
        &profile,
        &plan,
        &state.settings,
        true,
        Some(&planned_runtime),
    )?;
    if !prepared.interface_existed {
        let disconnected = disconnected_state(state);
        let mut pending = pending_disconnect_state(state)?;
        let (runtime_directory, quick_root_owned) = prepared.retained_runtime();
        if let Some(connection) = pending.connection.as_mut() {
            connection.runtime_directory =
                runtime_directory.map(|path| path.to_string_lossy().into_owned());
            connection.quick_root_owned = quick_root_owned;
        }
        store
            .save(&pending)
            .context("persist pending stale WireGuard-family cleanup")?;
        if let Err(error) = (|| -> Result<()> {
            revert_quick_dns(&prepared)?;
            prepared.cleanup_runtime()?;
            if stale_quick_policy_artifacts_exist(&prepared)? {
                bail!(
                    "stale WireGuard-family firewall or policy state remains without exact deletion ownership"
                );
            }
            Ok(())
        })()
        {
            let (runtime_directory, quick_root_owned) = prepared.retained_runtime();
            if let Some(connection) = state.connection.as_mut() {
                connection.recovery_required = true;
                connection.disconnecting = true;
                connection.runtime_directory =
                    runtime_directory.map(|path| path.to_string_lossy().into_owned());
                connection.quick_root_owned = quick_root_owned;
            }
            let _ = store.save(state);
            return Err(error).context("clean stale WireGuard-family resources");
        }
        store
            .save(&disconnected)
            .context("persist completed stale WireGuard-family cleanup")?;
        *state = disconnected;
        return Ok("disconnected".into());
    }
    verify_openvpn_interface_identity(&prepared.interface, &connection)
        .context("refusing to disconnect WireGuard-family interface without exact ownership")?;
    let disconnected = disconnected_state(state);
    let mut pending = pending_disconnect_state(state)?;
    let (runtime_directory, quick_root_owned) = prepared.retained_runtime();
    if let Some(connection) = pending.connection.as_mut() {
        connection.runtime_directory =
            runtime_directory.map(|path| path.to_string_lossy().into_owned());
        connection.quick_root_owned = quick_root_owned;
    }
    store
        .save(&pending)
        .context("persist pending WireGuard-family disconnect")?;
    verify_openvpn_interface_identity(&prepared.interface, &connection)
        .context("WireGuard-family interface ownership changed before disconnect")?;
    let operation = network_command(&prepared.program, &prepared.args, &prepared)
        .output()
        .with_context(|| format!("run {}", plan.program()))
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                Err(network_command_failure(plan.program(), &output))
            }
        })
        .and_then(|()| verify_quick_disconnected(&prepared));
    if let Err(error) = operation {
        let (runtime_directory, quick_root_owned) = prepared.retained_runtime();
        if let Some(connection) = state.connection.as_mut() {
            connection.runtime_directory =
                runtime_directory.map(|path| path.to_string_lossy().into_owned());
            connection.quick_root_owned = quick_root_owned;
        }
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
        if let Some(connection) = state.connection.as_mut() {
            connection.disconnecting = false;
        }
        if let Err(persist_error) = store.save(state) {
            let mut recovery = state.clone();
            if let Some(connection) = recovery.connection.as_mut() {
                connection.disconnecting = true;
                connection.recovery_required = true;
            }
            *state = recovery.clone();
            return match store.save(&recovery) {
                Ok(()) => Err(error).context(format!(
                    "disconnect rollback restored the connection, but ordinary state restoration failed; pending ownership was retained: {persist_error:#}"
                )),
                Err(recovery_error) => Err(error).context(format!(
                    "disconnect rollback restored the connection, but state restoration and pending-ownership persistence failed; recovery remains in memory: {persist_error:#}; {recovery_error:#}"
                )),
            };
        }
        return Err(error).context("WireGuard-family disconnect failed; connection restored");
    }
    if let Err(error) = prepared.cleanup_runtime() {
        let (runtime_directory, quick_root_owned) = prepared.retained_runtime();
        if let Some(connection) = state.connection.as_mut() {
            connection.disconnecting = true;
            connection.recovery_required = true;
            connection.runtime_directory =
                runtime_directory.map(|path| path.to_string_lossy().into_owned());
            connection.quick_root_owned = quick_root_owned;
        }
        return match store.save(state) {
            Ok(()) => Err(error).context(
                "WireGuard-family network teardown completed; staged runtime cleanup requires retry",
            ),
            Err(persist_error) => Err(error).context(format!(
                "WireGuard-family network teardown completed, but runtime cleanup and recovery persistence failed; recovery remains in memory: {persist_error:#}"
            )),
        };
    }
    store
        .save(&disconnected)
        .context("persist completed WireGuard-family disconnect")?;
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
    let inferred_start_ticks = state.connection.as_ref().and_then(|connection| {
        let pid = connection.pid?;
        if connection.process_start_ticks.is_some() {
            return None;
        }
        let profile = state.profiles.get(&connection.profile_id)?;
        let owned = match profile.protocol {
            Protocol::Xray => xray_process_info(pid).is_ok_and(|worker| {
                connection.interface.as_deref() == Some(&worker.interface)
                    && connection.xray_route.as_ref().is_some_and(|route| {
                        route.endpoint == worker.endpoint
                            && route.gateway == worker.gateway
                            && route.uplink == worker.uplink
                    })
                    && verify_openvpn_interface_identity(&worker.interface, connection).is_ok()
            }),
            Protocol::OpenVpn => connection.runtime_directory.as_deref().is_some_and(|runtime| {
                openvpn_process_configuration(pid, None).is_ok_and(|configuration| {
                    configuration == Path::new(runtime).join("openvpn.conf")
                        && connection.interface.as_deref().is_some_and(|interface| {
                            verify_openvpn_interface_identity(interface, connection).is_ok()
                        })
                })
            }),
            _ => process_belongs_to_profile(pid, profile),
        };
        owned.then(|| process_start_ticks(pid)).flatten()
    });
    if let Some(ticks) = inferred_start_ticks
        && let Some(connection) = state.connection.as_mut()
    {
        connection.process_start_ticks = Some(ticks);
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
    let root = Path::new("/run/amn");
    if directory.parent() != Some(root)
        || directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| name.len() != 32 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        bail!("saved OpenVPN runtime directory is outside /run/amn");
    }
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
            if fs::canonicalize(root).context("inspect OpenVPN runtime root")? != root {
                bail!("saved OpenVPN runtime root resolves outside /run/amn");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.uid() != 0 || metadata.permissions().mode() & 0o777 != 0o700 {
                    bail!("saved OpenVPN runtime directory ownership or permissions changed");
                }
            }
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
            | "amn-dns"
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
