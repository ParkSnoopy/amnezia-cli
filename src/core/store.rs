use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    fs,
    io::{
        Read,
        Write,
    },
    path::{
        Path,
        PathBuf,
    },
};

use anyhow::{
    Context,
    Result,
    bail,
};
use flate2::read::ZlibDecoder;
use uuid::Uuid;

use crate::core::model::{
    Profile,
    Protocol,
    RouteMode,
    State,
};

const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BACKUP_BYTES: usize = 64 * 1024 * 1024;

#[derive(serde::Serialize, serde::Deserialize)]
struct BackupFile {
    #[serde(default = "backup_format_version")]
    format_version: u32,
    state: State,
    #[serde(default)]
    profiles: BTreeMap<String, String>,
}

const fn backup_format_version() -> u32 {
    1
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn discover(override_root: Option<PathBuf>) -> Result<Self> {
        Self::discover_with_writes(override_root, true)
    }

    pub fn discover_read_only(override_root: Option<PathBuf>) -> Result<Self> {
        Self::discover_with_writes(override_root, false)
    }

    fn discover_with_writes(override_root: Option<PathBuf>, writable: bool) -> Result<Self> {
        let root = match override_root {
            Some(path) => path,
            None => {
                dirs::data_local_dir()
                    .context("cannot determine local data directory")?
                    .join("amn")
            }
        };
        if writable {
            fs::create_dir_all(&root)?;
            let root = fs::canonicalize(root)?;
            secure_directory(&root)?;
            secure_directory(&root.join("profiles"))?;
            secure_directory(&root.join("logs"))?;
            return Ok(Self { root });
        }
        let root = if root.exists() {
            fs::canonicalize(root)?
        } else if root.is_absolute() {
            root
        } else {
            std::env::current_dir()?.join(root)
        };
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    pub fn load(&self) -> Result<State> {
        self.load_with_migration(true)
    }

    pub fn load_without_migration(&self) -> Result<State> {
        self.load_with_migration(false)
    }

    fn load_with_migration(&self, persist_migration: bool) -> Result<State> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(State::default());
        }
        let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let mut document: serde_json::Value = serde_json::from_slice(&data)
            .with_context(|| format!("parse {}", path.display()))?;
        let (migrated, removed_sources) = migrate_removed_features(&mut document);
        let state: State = serde_json::from_value(document)
            .with_context(|| format!("parse {}", path.display()))?;
        self.validate_state(&state)?;
        self.validate_profile_sources(&state)?;
        if migrated && persist_migration {
            self.save(&state).context("persist removed-feature state migration")?;
            for source in removed_sources {
                self.remove_managed_profile_source(&source)?;
            }
        }
        Ok(state)
    }

    pub fn save(&self, state: &State) -> Result<()> {
        let path = self.state_path();
        let temporary = path.with_extension("json.new");
        let data = serde_json::to_vec_pretty(state)?;
        write_private(&temporary, &data)?;
        fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))?;
        sync_parent_directory(&path)
    }

    pub fn import_profile(
        &self,
        state: &mut State,
        path: &Path,
        name: Option<String>,
    ) -> Result<Vec<String>> {
        if fs::metadata(path)
            .with_context(|| format!("inspect {}", path.display()))?
            .len()
            > MAX_PROFILE_BYTES as u64
        {
            bail!("profile exceeds the 16 MiB size limit");
        }
        let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let text = String::from_utf8(data).context("profile is not UTF-8 text")?;
        let configurations = normalize_imported_profiles(&text, path)?;
        for (text, protocol) in &configurations {
            reject_executable_directives(text, protocol)
                .and_then(|_| validate_protocol_configuration(text, protocol))
                .with_context(|| format!("{protocol} configuration is unusable"))?;
        }
        let base_name = name.unwrap_or_else(|| {
            path.file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("VPN")
                .to_owned()
        });
        let multiple = configurations.len() > 1;
        let mut updated = state.clone();
        let mut imported = Vec::new();
        let mut destinations = Vec::new();
        for (text, protocol) in configurations {
            let id = Uuid::new_v4().simple().to_string();
            let file_stem = if matches!(protocol, Protocol::WireGuard | Protocol::AmneziaWg) {
                format!("amn{}", id.chars().take(11).collect::<String>())
            } else {
                id.clone()
            };
            let destination = self
                .root
                .join("profiles")
                .join(format!("{file_stem}.{}", profile_extension(&protocol)));
            if let Err(error) = write_private(&destination, text.as_bytes()) {
                for written in &destinations {
                    let _ = fs::remove_file(written);
                }
                return Err(error).context("profile import rolled back");
            }
            destinations.push(destination.clone());
            let profile = Profile {
                id: id.clone(),
                name: if multiple {
                    format!("{base_name} ({protocol})")
                } else {
                    base_name.clone()
                },
                protocol,
                source: destination.to_string_lossy().into_owned(),
                enabled: true,
            };
            updated.profiles.insert(id.clone(), profile);
            imported.push(id);
        }
        if updated.default_profile.is_none() {
            updated.default_profile = imported.first().cloned();
        }
        if let Err(error) = self.save(&updated) {
            for destination in destinations {
                let _ = fs::remove_file(destination);
            }
            return Err(error).context("profile import rolled back");
        }
        *state = updated;
        Ok(imported)
    }

    pub fn remove_profile(&self, state: &mut State, id: &str) -> Result<()> {
        let profile = state
            .profiles
            .get(id)
            .context("selected profile no longer exists")?;
        if state
            .connection
            .as_ref()
            .is_some_and(|connection| connection.profile_id == id)
        {
            bail!("profile is connected; disconnect first");
        }
        let source = fs::canonicalize(&profile.source)?;
        let profiles_root = fs::canonicalize(self.root.join("profiles"))?;
        if source.parent() != Some(profiles_root.as_path()) {
            bail!("refusing to remove profile source outside managed profile directory");
        }
        let mut updated = state.clone();
        updated.profiles.remove(id);
        if updated.default_profile.as_deref() == Some(id) {
            updated.default_profile = updated.profiles.keys().next().cloned();
        }
        let staged = profiles_root.join(format!(".remove-{}", Uuid::new_v4().simple()));
        fs::rename(&source, &staged)?;
        if let Err(error) = self.save(&updated) {
            let rollback = fs::rename(&staged, &source);
            return match rollback {
                Ok(()) => Err(error).context("profile removal rolled back"),
                Err(rollback_error) => {
                    Err(error).context(format!(
                        "profile removal failed and file rollback failed: {rollback_error}"
                    ))
                }
            };
        }
        *state = updated;
        fs::remove_file(staged).context("remove staged profile file")?;
        Ok(())
    }

    pub fn export_profile(&self, state: &State, id: &str, destination: &Path) -> Result<()> {
        let profile = state
            .profiles
            .get(id)
            .context("selected profile no longer exists")?;
        let data = fs::read(&profile.source)?;
        write_private(destination, &data)
            .with_context(|| format!("export profile to {}", destination.display()))
    }

    pub fn backup(&self, state: &State, destination: &Path) -> Result<()> {
        let mut backup_state = state.clone();
        backup_state.connection = None;
        let profiles = state
            .profiles
            .iter()
            .map(|(id, profile)| Ok((id.clone(), fs::read_to_string(&profile.source)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let backup = BackupFile {
            format_version: 1,
            state: backup_state,
            profiles,
        };
        let data = serde_json::to_vec_pretty(&backup)?;
        if data.len() > MAX_BACKUP_BYTES {
            bail!("backup exceeds the 64 MiB size limit");
        }
        write_private(destination, &data)
            .with_context(|| format!("write backup {}", destination.display()))
    }

    pub fn restore(&self, current: &State, source: &Path) -> Result<State> {
        if fs::metadata(source)
            .with_context(|| format!("inspect backup {}", source.display()))?
            .len()
            > MAX_BACKUP_BYTES as u64
        {
            bail!("backup exceeds the 64 MiB size limit");
        }
        let data = fs::read(source).with_context(|| format!("read backup {}", source.display()))?;
        let mut document: serde_json::Value =
            serde_json::from_slice(&data).context("invalid backup")?;
        if is_amnezia_settings_backup(&document) {
            return self.restore_amnezia_settings(current, &document);
        }
        if let Some(state) = document.get_mut("state") {
            migrate_removed_features(state);
        }
        let mut backup: BackupFile = serde_json::from_value(document).context("invalid backup")?;
        backup
            .profiles
            .retain(|id, _| backup.state.profiles.contains_key(id));
        if backup.format_version != 1 {
            bail!(
                "unsupported backup format version: {}",
                backup.format_version
            );
        }
        let mut state = backup.state;
        state.connection = None;
        if state.profiles.len() != backup.profiles.len() {
            bail!("backup profile index does not match profile data");
        }
        let profiles_root = self.root.join("profiles");
        let mut destinations = BTreeSet::new();
        for (index, (id, profile)) in state.profiles.iter().enumerate() {
            let parsed_id = Uuid::parse_str(id)
                .with_context(|| format!("backup profile {} has an invalid identity", index + 1))?;
            if parsed_id.simple().to_string() != *id || profile.id != *id {
                bail!("backup profile {} has inconsistent identity data", index + 1);
            }
            let text = backup
                .profiles
                .get(id)
                .with_context(|| format!("backup profile {} has no configuration", index + 1))?;
            if text.len() > MAX_PROFILE_BYTES {
                bail!("backup profile {} exceeds the 16 MiB size limit", index + 1);
            }
            reject_executable_directives(text, &profile.protocol)?;
            validate_protocol_configuration(text, &profile.protocol)?;
            let destination = restored_profile_path(&profiles_root, id, &profile.protocol);
            if !destinations.insert(destination) {
                bail!("backup profiles resolve to duplicate filenames");
            }
        }
        self.validate_state(&state)?;

        let previous_profiles = current
            .profiles
            .values()
            .enumerate()
            .map(|(index, profile)| {
                let source = Path::new(&profile.source);
                let file_name = source
                    .file_name()
                    .context("current profile path has no file name")?
                    .to_owned();
                let data = fs::read(source).with_context(|| {
                    format!("read current profile configuration {}", index + 1)
                })?;
                Ok((file_name, data))
            })
            .collect::<Result<Vec<_>>>()?;
        let transaction_id = Uuid::new_v4().simple().to_string();
        let staging = self.root.join(format!("profiles.restore-{transaction_id}"));
        let previous = self
            .root
            .join(format!("profiles.previous-{transaction_id}"));
        create_private_directory(&staging)?;
        let staged_result = (|| -> Result<()> {
            for (id, profile) in &mut state.profiles {
                let text = backup
                    .profiles
                    .get(id)
                    .context("validated profile data disappeared")?;
                let staged_path = restored_profile_path(&staging, id, &profile.protocol);
                write_private(&staged_path, text.as_bytes())?;
                profile.source = restored_profile_path(&profiles_root, id, &profile.protocol)
                    .to_string_lossy()
                    .into_owned();
            }
            Ok(())
        })();
        if let Err(error) = staged_result {
            cleanup_restore_directory(&staging, "partial restored profiles").with_context(|| {
                format!("backup restore staging failed and cleanup also failed: {error:#}")
            })?;
            return Err(error);
        }

        if let Err(error) = fs::rename(&profiles_root, &previous) {
            cleanup_restore_directory(&staging, "staged restored profiles").with_context(|| {
                format!("current profiles could not be staged and imported-profile cleanup failed: {error:#}")
            })?;
            return Err(error).context("stage current profiles for backup restore");
        }
        if let Err(error) = fs::rename(&staging, &profiles_root) {
            if let Err(rollback_error) = fs::rename(&previous, &profiles_root) {
                restore_profile_tree(&profiles_root, &previous_profiles).with_context(|| {
                    format!(
                        "activate restored profiles failed and current-profile rename rollback failed: {error:#}; {rollback_error:#}"
                    )
                })?;
                let previous_cleanup = cleanup_restore_directory(&previous, "previous profiles");
                let staging_cleanup =
                    cleanup_restore_directory(&staging, "staged restored profiles");
                if let Err(previous_error) = previous_cleanup {
                    return Err(previous_error).context(format!(
                        "restored profiles were not activated and current profiles were reconstructed: {error:#}; {rollback_error:#}; staging cleanup: {staging_cleanup:?}"
                    ));
                }
                staging_cleanup.with_context(|| {
                    format!("activate restored profiles failed and staging cleanup also failed: {error:#}")
                })?;
                return Err(error).context("activate restored profiles");
            }
            cleanup_restore_directory(&staging, "staged restored profiles").with_context(|| {
                format!("activate restored profiles failed and staging cleanup also failed: {error:#}")
            })?;
            return Err(error).context("activate restored profiles");
        }
        if let Err(error) = fs::remove_dir_all(&previous) {
            restore_profile_tree(&profiles_root, &previous_profiles)
                .context("restore current profiles after old-profile cleanup failed")?;
            return Err(error).context("remove replaced profiles before committing restore");
        }
        let commit_result = self
            .validate_state(&state)
            .and_then(|_| self.validate_profile_sources(&state))
            .and_then(|_| self.save(&state));
        if let Err(error) = commit_result {
            restore_profile_tree(&profiles_root, &previous_profiles)
                .context("restore current profiles after state commit failed")?;
            return Err(error).context("restore rolled back");
        }
        Ok(state)
    }

    fn restore_amnezia_settings(
        &self,
        current: &State,
        document: &serde_json::Value,
    ) -> Result<State> {
        let object = document
            .as_object()
            .context("Amnezia backup must be a JSON object")?;
        let mut updated = current.clone();
        update_amnezia_settings(&mut updated, object)?;

        let Some(value) = object.get("Servers/serversList") else {
            updated.connection = None;
            self.validate_state(&updated)?;
            self.save(&updated)?;
            return Ok(updated);
        };

        let servers = amnezia_server_list(value)?;
        let default_server = object
            .get("Servers/defaultServerIndex")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        let default_server_id = object
            .get("Servers/defaultServerId")
            .and_then(serde_json::Value::as_str);
        let mut configurations = Vec::new();
        let mut default_configuration = None;
        for (server_index, server) in servers.iter().enumerate() {
            let name = server
                .get("description")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("VPN");
            let Ok(extracted) = extract_amnezia_protocols(server) else {
                continue;
            };
            let multiple = extracted.len() > 1;
            for (text, protocol) in extracted {
                reject_executable_directives(&text, &protocol)
                    .and_then(|_| validate_protocol_configuration(&text, &protocol))
                    .with_context(|| format!("{protocol} configuration is unusable"))?;
                if text.len() > MAX_PROFILE_BYTES {
                    bail!("backup profile exceeds the 16 MiB size limit");
                }
                let profile_name = if multiple {
                    format!("{name} {protocol}")
                } else {
                    name.to_owned()
                };
                let is_default = default_server == Some(server_index)
                    || default_server_id.is_some_and(|id| {
                        server
                            .get("storageServerId")
                            .and_then(serde_json::Value::as_str)
                            == Some(id)
                    });
                if is_default && default_configuration.is_none() {
                    default_configuration = Some(configurations.len());
                }
                configurations.push((profile_name, text, protocol));
            }
        }
        if !servers.is_empty() && configurations.is_empty() {
            bail!("Amnezia backup contains no supported VPN protocol configuration");
        }

        let profiles_root = self.root.join("profiles");
        let previous_profiles = current
            .profiles
            .values()
            .enumerate()
            .map(|(index, profile)| {
                let source = Path::new(&profile.source);
                let file_name = source
                    .file_name()
                    .context("current profile path has no file name")?
                    .to_owned();
                let data = fs::read(source).with_context(|| {
                    format!("read current profile configuration {}", index + 1)
                })?;
                Ok((file_name, data))
            })
            .collect::<Result<Vec<_>>>()?;
        let transaction_id = Uuid::new_v4().simple().to_string();
        let staging = self.root.join(format!("profiles.import-{transaction_id}"));
        let previous = self
            .root
            .join(format!("profiles.previous-{transaction_id}"));
        create_private_directory(&staging)?;

        updated.profiles.clear();
        updated.default_profile = None;
        updated.connection = None;
        let stage_result = configurations.into_iter().enumerate().try_for_each(
            |(index, (name, text, protocol))| -> Result<()> {
                let id = Uuid::new_v4().simple().to_string();
                let staged = restored_profile_path(&staging, &id, &protocol);
                write_private(&staged, text.as_bytes())?;
                let destination = restored_profile_path(&profiles_root, &id, &protocol);
                updated.profiles.insert(
                    id.clone(),
                    Profile {
                        id: id.clone(),
                        name,
                        protocol,
                        source: destination.to_string_lossy().into_owned(),
                        enabled: true,
                    },
                );
                if default_configuration == Some(index) {
                    updated.default_profile = Some(id);
                }
                Ok(())
            },
        );
        if let Err(error) = stage_result {
            cleanup_restore_directory(&staging, "partial imported server list")
                .context("backup import failed and staging cleanup also failed")?;
            return Err(error).context("backup import rolled back");
        }
        self.validate_state(&updated)?;

        if let Err(error) = fs::rename(&profiles_root, &previous) {
            cleanup_restore_directory(&staging, "staged imported server list")
                .context("backup import failed and staging cleanup also failed")?;
            return Err(error).context("stage current profiles for server-list replacement");
        }
        if let Err(error) = fs::rename(&staging, &profiles_root) {
            if fs::rename(&previous, &profiles_root).is_err() {
                restore_profile_tree(&profiles_root, &previous_profiles)
                    .context("reconstruct current profiles after import activation failed")?;
                let previous_cleanup = cleanup_restore_directory(&previous, "previous profiles");
                let staging_cleanup =
                    cleanup_restore_directory(&staging, "staged imported server list");
                previous_cleanup.context("remove previous profiles after reconstruction")?;
                staging_cleanup.context("remove staged server list after reconstruction")?;
                return Err(error).context("activate imported server list");
            }
            cleanup_restore_directory(&staging, "staged imported server list")?;
            return Err(error).context("activate imported server list");
        }
        if let Err(error) = fs::remove_dir_all(&previous) {
            restore_profile_tree(&profiles_root, &previous_profiles)
                .context("restore current profiles after server-list cleanup failed")?;
            return Err(error).context("remove replaced server list before committing import");
        }
        if let Err(error) = self
            .validate_profile_sources(&updated)
            .and_then(|_| self.save(&updated))
        {
            restore_profile_tree(&profiles_root, &previous_profiles)
                .context("restore current profiles after server-list commit failed")?;
            return Err(error).context("backup import rolled back");
        }
        Ok(updated)
    }

    fn validate_state(&self, state: &State) -> Result<()> {
        if let Some(id) = &state.default_profile
            && !state.profiles.contains_key(id)
        {
            bail!("default profile no longer exists");
        }

        for (index, (id, profile)) in state.profiles.iter().enumerate() {
            if profile.id != *id {
                bail!("profile {} has inconsistent internal identity", index + 1);
            }
        }

        if let Some(connection) = &state.connection
            && !state.profiles.contains_key(&connection.profile_id)
        {
            bail!("connection references a profile that no longer exists");
        }
        Ok(())
    }

    fn remove_managed_profile_source(&self, source: &str) -> Result<()> {
        let source = Path::new(source);
        if !source.exists() {
            return Ok(());
        }
        let profiles_root = fs::canonicalize(self.root.join("profiles"))?;
        let source = fs::canonicalize(source).context("inspect removed profile configuration")?;
        if source.parent() == Some(profiles_root.as_path()) {
            fs::remove_file(&source).context("remove unsupported profile configuration")?;
        }
        Ok(())
    }

    pub(crate) fn validated_profile_text(&self, profile: &Profile) -> Result<String> {
        let profiles_root = fs::canonicalize(self.root.join("profiles"))?;
        let source = fs::canonicalize(&profile.source).context("profile configuration is missing")?;
        if source.parent() != Some(profiles_root.as_path()) {
            bail!("profile configuration is outside the managed profile directory");
        }
        let text = fs::read_to_string(&source)?;
        reject_executable_directives(&text, &profile.protocol)?;
        validate_protocol_configuration(&text, &profile.protocol)?;
        Ok(text)
    }

    fn validate_profile_sources(&self, state: &State) -> Result<()> {
        for profile in state.profiles.values() {
            self.validated_profile_text(profile)?;
        }
        Ok(())
    }
}

fn is_amnezia_settings_backup(document: &serde_json::Value) -> bool {
    document.as_object().is_some_and(|object| {
        object
            .keys()
            .any(|key| key.starts_with("Servers/") || key.starts_with("Conf/"))
    })
}

fn cleanup_restore_directory(path: &Path, label: &str) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {label}")),
    }
}

fn restore_profile_tree(
    profiles_root: &Path,
    profiles: &[(std::ffi::OsString, Vec<u8>)],
) -> Result<()> {
    if profiles_root.exists() {
        fs::remove_dir_all(profiles_root)?;
    }
    create_private_directory(profiles_root)?;
    for (file_name, data) in profiles {
        write_private(&profiles_root.join(file_name), data)?;
    }
    Ok(())
}

fn amnezia_server_list(value: &serde_json::Value) -> Result<Vec<serde_json::Value>> {
    let parsed;
    let value = if let Some(text) = value.as_str() {
        parsed = serde_json::from_str::<serde_json::Value>(text)
            .context("Servers/serversList is not valid JSON")?;
        &parsed
    } else {
        value
    };
    value
        .as_array()
        .cloned()
        .context("Servers/serversList must be an array or a JSON-encoded array")
}

fn backup_bool(value: &serde_json::Value) -> Option<bool> {
    value.as_bool().or_else(|| {
        value
            .as_str()
            .and_then(|value| value.parse::<bool>().ok())
    })
}

fn backup_routes(value: &serde_json::Value) -> Result<Vec<String>> {
    let mut values = match value {
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        serde_json::Value::Object(entries) => {
            let mut routes = Vec::new();
            for (key, value) in entries {
                if crate::core::routing::Network::parse(key).is_ok() {
                    routes.push(key.clone());
                    continue;
                }
                match value {
                    serde_json::Value::String(value) => routes.push(value.clone()),
                    serde_json::Value::Array(values) => routes.extend(
                        values
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_owned),
                    ),
                    _ => {}
                }
            }
            routes
        }
        _ => bail!("split-tunnel backup setting must be an object or array"),
    };
    for route in &values {
        crate::core::routing::Network::parse(route)
            .with_context(|| format!("invalid split-tunnel route in backup: {route}"))?;
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn update_amnezia_settings(
    state: &mut State,
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    if let Some(value) = object.get("Conf/saveLogs") {
        state.settings.logging = backup_bool(value).context("Conf/saveLogs must be true or false")?;
    }
    if let Some(value) = object.get("Conf/routeMode") {
        state.settings.route_mode = match value.as_u64() {
            Some(0) => RouteMode::All,
            Some(1) => RouteMode::OnlyListed,
            Some(2) => RouteMode::ExceptListed,
            _ => bail!("Conf/routeMode must be 0, 1, or 2"),
        };
    }
    if object
        .get("Conf/sitesSplitTunnelingEnabled")
        .and_then(backup_bool)
        == Some(false)
    {
        state.settings.route_mode = RouteMode::All;
    }
    let routes_key = match state.settings.route_mode {
        RouteMode::OnlyListed => Some("Conf/ForwardSites"),
        RouteMode::ExceptListed => Some("Conf/ExceptSites"),
        RouteMode::All => None,
    };
    if let Some(value) = routes_key.and_then(|key| object.get(key)) {
        state.settings.split_routes = backup_routes(value)?;
    }

    let primary = object.get("Conf/primaryDns");
    let secondary = object.get("Conf/secondaryDns");
    if primary.is_some() || secondary.is_some() {
        let mut servers = state.settings.dns_servers.clone();
        if let Some(value) = primary {
            if servers.is_empty() {
                servers.push(String::new());
            }
            servers[0] = value
                .as_str()
                .context("Conf/primaryDns must be an IP address")?
                .to_owned();
        }
        if let Some(value) = secondary {
            if servers.len() < 2 {
                servers.resize(2, String::new());
            }
            servers[1] = value
                .as_str()
                .context("Conf/secondaryDns must be an IP address")?
                .to_owned();
        }
        servers.retain(|value| !value.is_empty());
        for server in &servers {
            server
                .parse::<std::net::IpAddr>()
                .with_context(|| format!("invalid DNS server in backup: {server}"))?;
        }
        if servers.is_empty() {
            bail!("backup DNS settings contain no IP address");
        }
        state.settings.dns_servers = servers;
    }
    Ok(())
}

fn migrate_removed_features(document: &mut serde_json::Value) -> (bool, Vec<String>) {
    let Some(root) = document.as_object_mut() else {
        return (false, Vec::new());
    };
    let mut migrated = root.remove("servers").is_some();
    migrated |= root.remove("default_server").is_some();

    let mut removed_ids = BTreeSet::new();
    let mut removed_sources = Vec::new();
    if let Some(profiles) = root.get_mut("profiles").and_then(serde_json::Value::as_object_mut) {
        profiles.retain(|id, profile| {
            let removed = profile
                .get("protocol")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|protocol| matches!(protocol, "ikev2" | "shadowsocks"));
            if removed {
                removed_ids.insert(id.clone());
                if let Some(source) = profile.get("source").and_then(serde_json::Value::as_str) {
                    removed_sources.push(source.to_owned());
                }
                migrated = true;
            }
            !removed
        });
    }
    if root
        .get("default_profile")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| removed_ids.contains(id))
    {
        root.insert("default_profile".into(), serde_json::Value::Null);
        migrated = true;
    }
    if root
        .get("connection")
        .and_then(|connection| connection.get("profile_id"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| removed_ids.contains(id))
    {
        root.insert("connection".into(), serde_json::Value::Null);
        migrated = true;
    }
    (migrated, removed_sources)
}

fn profile_extension(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::OpenVpn => "ovpn",
        Protocol::Xray => "json",
        Protocol::WireGuard | Protocol::AmneziaWg => "conf",
    }
}

fn restored_profile_path(profiles_dir: &Path, id: &str, protocol: &Protocol) -> PathBuf {
    let file_stem = if matches!(protocol, Protocol::WireGuard | Protocol::AmneziaWg) {
        format!("amn{}", id.chars().take(11).collect::<String>())
    } else {
        id.to_owned()
    };
    profiles_dir.join(format!("{file_stem}.{}", profile_extension(protocol)))
}

fn normalize_imported_profiles(text: &str, path: &Path) -> Result<Vec<(String, Protocol)>> {
    let decoded = if let Some(value) = text.trim().strip_prefix("vpn://") {
        let bytes = crate::core::encoding::decode_base64(
            value,
            "Amnezia connection key is not valid base64",
        )?;
        decode_qcompress(&bytes).unwrap_or(bytes)
    } else {
        text.as_bytes().to_vec()
    };
    let decoded = String::from_utf8(decoded).context("decoded Amnezia profile is not UTF-8")?;
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(&decoded)
        && document.get("containers").is_some()
    {
        return extract_amnezia_protocols(&document);
    }
    let protocol = detect_protocol(&decoded, path)?;
    Ok(vec![(decoded, protocol)])
}

fn decode_qcompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 5 {
        return None;
    }
    let expected = u32::from_be_bytes(data[..4].try_into().ok()?) as usize;
    if expected > MAX_PROFILE_BYTES {
        return None;
    }
    let mut output = Vec::with_capacity(expected);
    ZlibDecoder::new(&data[4..])
        .take(expected as u64 + 1)
        .read_to_end(&mut output)
        .ok()?;
    (output.len() == expected).then_some(output)
}

fn amnezia_server_dns(document: &serde_json::Value, key: &str) -> Option<String> {
    document
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        .map(|value| value.to_string())
}

fn resolve_amnezia_dns_placeholders(
    configuration: String,
    document: &serde_json::Value,
) -> String {
    let mut configuration = configuration;
    for (placeholder, key) in [("$PRIMARY_DNS", "dns1"), ("$SECONDARY_DNS", "dns2")] {
        if let Some(server) = amnezia_server_dns(document, key) {
            configuration = configuration.replace(placeholder, &server);
        }
    }
    configuration
}

fn extract_amnezia_protocols(document: &serde_json::Value) -> Result<Vec<(String, Protocol)>> {
    let containers = document
        .get("containers")
        .and_then(serde_json::Value::as_array)
        .context("Amnezia bundle has no containers array")?;
    let preferred = document
        .get("defaultContainer")
        .or_else(|| document.get("default_container"))
        .and_then(serde_json::Value::as_str);
    let ordered = containers
        .iter()
        .filter(|container| {
            preferred.is_some_and(|name| {
                container
                    .get("container")
                    .and_then(serde_json::Value::as_str)
                    == Some(name)
            })
        })
        .chain(containers.iter().filter(|container| {
            !preferred.is_some_and(|name| {
                container
                    .get("container")
                    .and_then(serde_json::Value::as_str)
                    == Some(name)
            })
        }));
    let mut profiles = Vec::new();
    for container in ordered {
        let name = container
            .get("container")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let candidates = if name.contains("openvpn") {
            Some((
                Protocol::OpenVpn,
                ["openvpn", "openvpn_config_data"].as_slice(),
            ))
        } else if name.contains("xray") && !name.contains("ssxray") {
            Some((Protocol::Xray, ["xray", "xray_config_data"].as_slice()))
        } else if name.contains("amnezia-awg") || name.ends_with("awg") {
            Some((
                Protocol::AmneziaWg,
                ["awg", "amneziawg", "awg_config_data"].as_slice(),
            ))
        } else if name.contains("wireguard") {
            Some((
                Protocol::WireGuard,
                ["wireguard", "wireguard_config_data"].as_slice(),
            ))
        } else {
            None
        };
        let Some((protocol, keys)) = candidates else {
            continue;
        };
        let Some(value) = keys.iter().find_map(|key| container.get(*key)) else {
            continue;
        };
        let Some(last) = value
            .get("last_config")
            .and_then(serde_json::Value::as_str)
            .or_else(|| value.get("config").and_then(serde_json::Value::as_str))
        else {
            continue;
        };
        let configuration = if matches!(
            protocol,
            Protocol::OpenVpn | Protocol::WireGuard | Protocol::AmneziaWg
        ) {
            serde_json::from_str::<serde_json::Value>(last)
                .ok()
                .and_then(|wrapper| {
                    wrapper
                        .get("config")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| last.to_owned())
        } else {
            last.to_owned()
        };
        let configuration = if matches!(protocol, Protocol::WireGuard | Protocol::AmneziaWg) {
            resolve_amnezia_dns_placeholders(configuration, document)
        } else {
            configuration
        };
        profiles.push((configuration, protocol));
    }
    if profiles.is_empty() {
        bail!("Amnezia bundle contains no supported VPN protocol configuration");
    }
    Ok(profiles)
}

pub fn detect_protocol(text: &str, path: &Path) -> Result<Protocol> {
    let lower = text.to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if lower.contains("[interface]") && lower.contains("[peer]") {
        if ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"]
            .iter()
            .any(|field| {
                lower
                    .lines()
                    .any(|line| line.trim_start().starts_with(&format!("{field} =")))
            })
        {
            return Ok(Protocol::AmneziaWg);
        }
        return Ok(Protocol::WireGuard);
    }
    if extension == "ovpn"
        || lower
            .lines()
            .any(|line| line.trim_start().starts_with("remote "))
    {
        return Ok(Protocol::OpenVpn);
    }

    if lower.trim_start().starts_with('{')
        && (lower.contains("\"outbounds\"") || lower.contains("\"inbounds\""))
    {
        return Ok(Protocol::Xray);
    }
    if ["vless://", "vmess://", "trojan://"]
        .iter()
        .any(|prefix| lower.trim_start().starts_with(prefix))
    {
        return Ok(Protocol::Xray);
    }

    bail!("unsupported profile format")
}

fn secure_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "private directory must not be a symbolic link: {}",
                path.display()
            );
        }
        Ok(metadata) if !metadata.is_dir() => {
            bail!(
                "private directory path is not a directory: {}",
                path.display()
            );
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).with_context(|| format!("create {}", path.display()))?;
        }
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path).with_context(|| format!("create {}", path.display()))?;
    secure_directory(path)
}

pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("private file path has no parent directory")?;
    let file_name = path
        .file_name()
        .context("private file path has no filename")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.{}.new", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("write {}", path.display()))?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
        sync_parent_directory(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .context("durable file path has no parent directory")?;
        fs::File::open(parent)
            .with_context(|| format!("open {} for durable metadata sync", parent.display()))?
            .sync_all()
            .with_context(|| format!("sync {} metadata", parent.display()))?;
    }
    Ok(())
}

fn reject_executable_directives(text: &str, protocol: &Protocol) -> Result<()> {
    if matches!(protocol, Protocol::WireGuard | Protocol::AmneziaWg) {
        const HOOKS: &[&str] = &["preup", "postup", "predown", "postdown"];
        for line in text.lines() {
            let assignment = line.split_once('=').map(|(key, value)| {
                (
                    key.trim().to_ascii_lowercase(),
                    value.split('#').next().unwrap_or_default().trim(),
                )
            });
            if let Some((key, _)) = assignment.as_ref()
                && HOOKS.contains(&key.as_str())
            {
                bail!("WireGuard profile contains executable hook '{key}'");
            }
            if let Some((key, value)) = assignment.as_ref()
                && key == "saveconfig"
                && value.eq_ignore_ascii_case("true")
            {
                bail!("WireGuard profile contains unsupported mutable directive 'saveconfig'");
            }
        }
        return Ok(());
    }
    if protocol != &Protocol::OpenVpn {
        return Ok(());
    }
    const UNSAFE: &[&str] = &[
        "up",
        "down",
        "route-up",
        "route-pre-down",
        "ipchange",
        "client-connect",
        "client-disconnect",
        "learn-address",
        "auth-user-pass-verify",
        "tls-verify",
        "plugin",
        "config",
        "script-security",
        "daemon",
        "management",
        "management-client",
        "writepid",
        "log",
        "log-append",
        "status",
        "cd",
        "chroot",
        "iproute",
        "tmp-dir",
        "client-config-dir",
        "ifconfig-pool-persist",
        "tls-export-cert",
        "engine",
        "providers",
        "pkcs11-providers",
    ];
    const EXTERNAL_SECRET_FILES: &[&str] = &[
        "ca",
        "cert",
        "key",
        "pkcs12",
        "auth-user-pass",
        "http-proxy-user-pass",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "secret",
        "crl-verify",
        "askpass",
        "auth-gen-token-secret",
        "capath",
        "extra-certs",
        "dh",
    ];
    for line in text.lines() {
        let fields = line
            .trim_start()
            .trim_start_matches('-')
            .split_whitespace()
            .collect::<Vec<_>>();
        let directive = fields.first().copied().unwrap_or("").to_ascii_lowercase();
        if UNSAFE.contains(&directive.as_str()) {
            bail!("OpenVPN profile contains executable directive '{directive}'");
        }
        if EXTERNAL_SECRET_FILES.contains(&directive.as_str())
            && fields.get(1).is_some_and(|value| *value != "[inline]")
        {
            bail!(
                "OpenVPN profile references an external credential file with directive '{directive}'"
            );
        }
        if directive == "auth-user-pass"
            && fields.get(1).is_none()
            && !text.contains("<auth-user-pass>")
        {
            bail!(
                "OpenVPN profile requires interactive credentials; embed auth-user-pass credentials in the profile"
            );
        }
        if directive == "static-challenge" {
            bail!("OpenVPN profile requires an interactive static challenge");
        }
    }
    Ok(())
}

fn validate_protocol_configuration(text: &str, protocol: &Protocol) -> Result<()> {
    crate::core::transaction::validate_protocol(
        protocol,
        text,
        &crate::core::model::Settings::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_wireguard_amneziawg_and_xray() {
        assert_eq!(
            detect_protocol(
                "[Interface]\nPrivateKey=x\n[Peer]\nPublicKey=y",
                Path::new("x.conf")
            )
            .unwrap(),
            Protocol::WireGuard
        );
        assert_eq!(
            detect_protocol(
                "[Interface]\nJc = 4\n[Peer]\nPublicKey=y",
                Path::new("x.conf")
            )
            .unwrap(),
            Protocol::AmneziaWg
        );
        assert_eq!(
            detect_protocol("{\"outbounds\":[]}", Path::new("x.json")).unwrap(),
            Protocol::Xray
        );
        assert_eq!(
            detect_protocol(
                "vless://00000000-0000-0000-0000-000000000000@vpn.example:443",
                Path::new("x.txt")
            )
            .unwrap(),
            Protocol::Xray
        );
    }

    #[test]
    fn migrates_removed_protocol_and_server_state() {
        let mut document = serde_json::json!({
            "profiles": {
                "keep": {"id":"keep","name":"keep","protocol":"wire-guard","source":"/vpn/keep.conf","enabled":true},
                "remove": {"id":"remove","name":"remove","protocol":"ikev2","source":"/vpn/remove.json","enabled":true}
            },
            "default_profile": "remove",
            "settings": crate::core::model::Settings::default(),
            "connection": {"profile_id":"remove","pid":null,"interface":null},
            "servers": {"old": {}},
            "default_server": "old"
        });
        let (migrated, removed_sources) = migrate_removed_features(&mut document);
        assert!(migrated);
        assert_eq!(removed_sources, vec!["/vpn/remove.json"]);
        let state: State = serde_json::from_value(document).unwrap();
        assert_eq!(state.profiles.len(), 1);
        assert!(state.profiles.contains_key("keep"));
        assert!(state.default_profile.is_none());
        assert!(state.connection.is_none());
    }

    #[test]
    fn rejects_removed_ikev2_profiles() {
        assert!(
            detect_protocol(
                "{\"hostName\":\"vpn.example\",\"cert\":\"AA==\"}",
                Path::new("x.json"),
            )
            .is_err()
        );
    }

    #[test]
    fn extracts_default_protocol_from_amnezia_bundle() {
        let bundle = r#"{
            "defaultContainer":"amnezia-openvpn",
            "containers":[{
                "container":"amnezia-openvpn",
                "openvpn":{"last_config":"{\"config\":\"client\\nremote vpn.example 1194\"}"}
            }]
        }"#;
        let configurations = normalize_imported_profiles(bundle, Path::new("bundle.json")).unwrap();
        assert_eq!(configurations.len(), 1);
        let (configuration, protocol) = &configurations[0];
        assert_eq!(*protocol, Protocol::OpenVpn);
        assert_eq!(configuration, "client\nremote vpn.example 1194");
    }

    #[test]
    fn extracts_every_supported_protocol_from_amnezia_bundle() {
        let bundle = r#"{
            "dns1":"10.64.0.1",
            "dns2":"10.64.0.2",
            "defaultContainer":"amnezia-awg",
            "containers":[
                {"container":"amnezia-openvpn","openvpn":{"last_config":"{\"config\":\"client\\nremote vpn.example 1194\"}"}},
                {"container":"amnezia-awg","awg":{"last_config":"{\"config\":\"[Interface]\\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\\nPrivateKey=x\\n[Peer]\\nPublicKey=y\"}"}}
            ]
        }"#;
        let configurations = normalize_imported_profiles(bundle, Path::new("bundle.json")).unwrap();
        assert_eq!(configurations.len(), 2);
        assert_eq!(configurations[0].1, Protocol::AmneziaWg);
        assert!(configurations[0].0.contains("DNS = 10.64.0.1, 10.64.0.2"));
        assert!(!configurations[0].0.contains("$PRIMARY_DNS"));
        assert!(!configurations[0].0.contains("$SECONDARY_DNS"));
        assert_eq!(configurations[1].1, Protocol::OpenVpn);
    }

    #[test]
    fn restores_server_list_without_native_backup_envelope() {
        let root = std::env::temp_dir().join(format!(
            "amn-backup-test-{}",
            Uuid::new_v4().simple()
        ));
        create_private_directory(&root).unwrap();
        create_private_directory(&root.join("profiles")).unwrap();
        let source = root.join("external.backup");
        let servers = serde_json::json!([{
            "description": "Imported",
            "storageServerId": "server-2",
            "defaultContainer": "amnezia-openvpn",
            "containers": [{
                "container": "amnezia-openvpn",
                "openvpn": {
                    "last_config": "{\"config\":\"client\\nremote vpn.example 1194\"}"
                }
            }]
        }]);
        let document = serde_json::json!({
            "Servers/serversList": servers.to_string(),
            "Servers/defaultServerId": "server-2"
        });
        fs::write(&source, serde_json::to_vec(&document).unwrap()).unwrap();
        let store = Store { root: root.clone() };
        let old_source = root.join("profiles").join("old.ovpn");
        write_private(&old_source, b"client\nremote old.example 1194").unwrap();
        let mut current = State::default();
        current.settings.logging = false;
        current.default_profile = Some("old-profile".into());
        current.profiles.insert(
            "old-profile".into(),
            Profile {
                id: "old-profile".into(),
                name: "Old".into(),
                protocol: Protocol::OpenVpn,
                source: old_source.to_string_lossy().into_owned(),
                enabled: true,
            },
        );

        let restored = store.restore(&current, &source).unwrap();

        assert_eq!(restored.profiles.len(), 1);
        assert!(!restored.profiles.contains_key("old-profile"));
        assert!(!old_source.exists());
        let profile = restored.profiles.values().next().unwrap();
        assert_eq!(profile.name, "Imported");
        assert_eq!(restored.default_profile.as_deref(), Some(profile.id.as_str()));
        assert!(!restored.settings.logging);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_amnezia_settings_update_only_supplied_fields() {
        let mut state = State::default();
        state.settings.route_mode = RouteMode::ExceptListed;
        state.settings.split_routes = vec!["10.0.0.0/8".into()];
        state.settings.dns_servers = vec![
            "9.9.9.9".into(),
            "149.112.112.112".into(),
            "8.8.8.8".into(),
        ];
        let document = serde_json::json!({
            "Conf/saveLogs": false,
            "Conf/primaryDns": "1.1.1.1"
        });

        update_amnezia_settings(&mut state, document.as_object().unwrap()).unwrap();

        assert!(!state.settings.logging);
        assert_eq!(state.settings.route_mode, RouteMode::ExceptListed);
        assert_eq!(state.settings.split_routes, ["10.0.0.0/8"]);
        assert_eq!(
            state.settings.dns_servers,
            ["1.1.1.1", "149.112.112.112", "8.8.8.8"]
        );
    }

    #[test]
    fn imports_upstream_domain_route_arrays() {
        let routes = backup_routes(&serde_json::json!({
            "example.com": ["203.0.113.10", "203.0.113.11"],
            "10.0.0.0/8": []
        }))
        .unwrap();

        assert_eq!(routes, ["10.0.0.0/8", "203.0.113.10", "203.0.113.11"]);
    }

    #[test]
    fn rejects_wireguard_hooks() {
        let result = reject_executable_directives(
            "[Interface]\nPostUp = curl attacker",
            &Protocol::WireGuard,
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("executable hook 'postup'")
        );
        let save = reject_executable_directives(
            "[Interface]\nSaveConfig = true # mutate source",
            &Protocol::WireGuard,
        );
        assert!(
            save.unwrap_err()
                .to_string()
                .contains("unsupported mutable directive 'saveconfig'")
        );
    }

    #[test]
    fn rejects_openvpn_scripts() {
        let result = reject_executable_directives("client\nup /tmp/payload", &Protocol::OpenVpn);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("executable directive 'up'")
        );
        let plugin = reject_executable_directives("client\nplugin evil.so", &Protocol::OpenVpn);
        assert!(
            plugin
                .unwrap_err()
                .to_string()
                .contains("executable directive 'plugin'")
        );
    }

    #[test]
    fn profile_validation_errors_do_not_expose_internal_identity() {
        let root = std::env::temp_dir().join(format!(
            "amn-profile-error-test-{}",
            Uuid::new_v4().simple()
        ));
        create_private_directory(&root).unwrap();
        create_private_directory(&root.join("profiles")).unwrap();
        let identity = "0123456789abcdef0123456789abcdef";
        let profile = Profile {
            id: identity.into(),
            name: "Missing".into(),
            protocol: Protocol::OpenVpn,
            source: root
                .join("profiles")
                .join(format!("{identity}.ovpn"))
                .to_string_lossy()
                .into_owned(),
            enabled: true,
        };
        let error = Store { root: root.clone() }
            .validated_profile_text(&profile)
            .unwrap_err()
            .to_string();

        assert_eq!(error, "profile configuration is missing");
        assert!(!error.contains(identity));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_missing_default_profile_reference() {
        let store = Store {
            root: PathBuf::new(),
        };
        let state = State {
            default_profile: Some("missing".into()),
            ..State::default()
        };
        assert_eq!(
            store.validate_state(&state).unwrap_err().to_string(),
            "default profile no longer exists"
        );
    }
}
