use anyhow::{Context, Result};

use crate::core::{model::State, store::Store, transaction};

pub struct Connections<'a> {
    store: &'a Store,
    state: &'a mut State,
}

#[derive(Debug, Clone, Copy)]
pub enum Operation<'a> {
    Connect { profile: Option<&'a str> },
    Disconnect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub profile_id: Option<String>,
    pub pid: Option<u32>,
    pub interface: Option<String>,
}

impl<'a> Connections<'a> {
    pub fn new(store: &'a Store, state: &'a mut State) -> Self {
        Self { store, state }
    }

    pub fn status(&mut self, reconcile: bool) -> Result<ConnectionStatus> {
        if !reconcile {
            let mut snapshot = self.state.clone();
            transaction::refresh_connection(self.store, &mut snapshot)?;
            return Ok(connection_status(&snapshot));
        }
        let before = self.state.connection.clone();
        if let Err(error) = transaction::refresh_connection(self.store, self.state) {
            let stale_xray = self
                .state
                .connection
                .as_ref()
                .and_then(|connection| self.state.profiles.get(&connection.profile_id))
                .is_some_and(|profile| profile.protocol == crate::core::model::Protocol::Xray);
            if stale_xray && reconcile {
                transaction::disconnect(self.store, self.state, false)
                    .context("reconcile stale XRay connection")?;
            } else {
                return Err(error);
            }
        }
        if connection_changed(before.as_ref(), self.state.connection.as_ref()) {
            self.store.save(self.state)?;
        }
        Ok(connection_status(self.state))
    }

    pub fn preview(&mut self, operation: Operation<'_>) -> Result<String> {
        let mut snapshot = self.state.clone();
        match operation {
            Operation::Connect { profile } => {
                transaction::connect(self.store, &mut snapshot, profile, true)
            }
            Operation::Disconnect => transaction::disconnect(self.store, &mut snapshot, true),
        }
    }

    pub fn connect(&mut self, profile: Option<&str>) -> Result<String> {
        transaction::connect(self.store, self.state, profile, false)
    }

    pub fn disconnect(&mut self) -> Result<String> {
        transaction::disconnect(self.store, self.state, false)
    }

    pub fn reconnect(&mut self, preview: bool) -> Result<String> {
        let original = self
            .state
            .connection
            .clone()
            .ok_or_else(|| anyhow::anyhow!("VPN is not connected"))?;
        let profile = original.profile_id.clone();
        let mut connect_preview_state = self.state.clone();
        connect_preview_state.connection = None;
        let connect_preview =
            transaction::connect(self.store, &mut connect_preview_state, Some(&profile), true)?;
        let disconnect_preview = transaction::disconnect(self.store, self.state, true)?;
        if preview {
            return Ok(format!("{disconnect_preview}\n{connect_preview}"));
        }

        transaction::disconnect(self.store, self.state, false)?;
        match transaction::connect(self.store, self.state, Some(&profile), false) {
            Ok(result) => Ok(result),
            Err(connect_error) => {
                match transaction::connect(self.store, self.state, Some(&profile), false) {
                    Ok(_) => Err(connect_error).context(
                        "reconnect failed; previous connection was restored",
                    ),
                    Err(restore_error) => Err(connect_error).context(format!(
                        "reconnect failed and previous connection restoration failed: {restore_error:#}"
                    )),
                }
            }
        }
    }
}

fn connection_status(state: &State) -> ConnectionStatus {
    ConnectionStatus {
        connected: state.connection.is_some(),
        profile_id: state
            .connection
            .as_ref()
            .map(|connection| connection.profile_id.clone()),
        pid: state.connection.as_ref().and_then(|connection| connection.pid),
        interface: state
            .connection
            .as_ref()
            .and_then(|connection| connection.interface.clone()),
    }
}

fn connection_changed(
    before: Option<&crate::core::model::Connection>,
    after: Option<&crate::core::model::Connection>,
) -> bool {
    match (before, after) {
        (None, None) => false,
        (Some(before), Some(after)) => {
            before.profile_id != after.profile_id
                || before.recovery_required != after.recovery_required
                || before.pid != after.pid
                || before.process_start_ticks != after.process_start_ticks
                || before.interface != after.interface
                || before.interface_index != after.interface_index
                || before.interface_owner != after.interface_owner
                || before.runtime_directory != after.runtime_directory
                || before.xray_route.as_ref().map(|route| (&route.endpoint, &route.gateway, &route.uplink))
                    != after.xray_route.as_ref().map(|route| (&route.endpoint, &route.gateway, &route.uplink))
        }
        _ => true,
    }
}
