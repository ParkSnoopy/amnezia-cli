use crate::model::{Profile, Protocol, State};
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(serde::Serialize, serde::Deserialize)]
struct BackupFile {
    format_version: u32,
    state: State,
    profiles: BTreeMap<String, String>,
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn discover(override_root: Option<PathBuf>) -> Result<Self> {
        let root = match override_root {
            Some(path) => path,
            None => dirs::data_local_dir()
                .context("cannot determine local data directory")?
                .join("amn"),
        };
        fs::create_dir_all(&root)?;
        let root = fs::canonicalize(root)?;
        secure_directory(&root)?;
        secure_directory(&root.join("profiles"))?;
        secure_directory(&root.join("logs"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    pub fn load(&self) -> Result<State> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(State::default());
        }
        let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let state = serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display()))?;
        self.validate_state(&state)?;
        self.validate_profile_sources(&state)?;
        Ok(state)
    }

    pub fn save(&self, state: &State) -> Result<()> {
        let path = self.state_path();
        let temporary = path.with_extension("json.new");
        let data = serde_json::to_vec_pretty(state)?;
        write_private(&temporary, &data)?;
        fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))
    }

    pub fn import_profile(&self, state: &mut State, path: &Path, name: Option<String>) -> Result<String> {
        let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let text = String::from_utf8(data).context("profile is not UTF-8 text")?;
        let protocol = detect_protocol(&text, path)?;
        reject_executable_directives(&text, &protocol)?;
        let id = Uuid::new_v4().simple().to_string();
        let extension = path.extension().and_then(|value| value.to_str()).unwrap_or("conf");
        let file_stem = if matches!(protocol, Protocol::WireGuard | Protocol::AmneziaWg) {
            format!("amn{}", &id[..11])
        } else {
            id.clone()
        };
        let destination = self.root.join("profiles").join(format!("{file_stem}.{extension}"));
        write_private(&destination, text.as_bytes())?;
        let profile = Profile {
            id: id.clone(),
            name: name.unwrap_or_else(|| {
                path.file_stem().and_then(|value| value.to_str()).unwrap_or("VPN").to_owned()
            }),
            protocol,
            source: destination.to_string_lossy().into_owned(),
            enabled: true,
            server_id: None,
        };
        state.profiles.insert(id.clone(), profile);
        if state.default_profile.is_none() {
            state.default_profile = Some(id.clone());
        }
        self.save(state)?;
        Ok(id)
    }

    pub fn remove_profile(&self, state: &mut State, id: &str) -> Result<()> {
        let profile = state.profiles.get(id).with_context(|| format!("unknown profile: {id}"))?;
        if state.connection.as_ref().is_some_and(|connection| connection.profile_id == id) {
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
        self.save(&updated)?;
        fs::remove_file(source)?;
        *state = updated;
        Ok(())
    }

    pub fn export_profile(&self, state: &State, id: &str, destination: &Path) -> Result<()> {
        let profile = state.profiles.get(id).with_context(|| format!("unknown profile: {id}"))?;
        let data = fs::read(&profile.source)?;
        write_private(destination, &data)
            .with_context(|| format!("export profile to {}", destination.display()))
    }

    pub fn backup(&self, state: &State, destination: &Path) -> Result<()> {
        let mut backup_state = state.clone();
        backup_state.connection = None;
        let profiles = state.profiles.iter()
            .map(|(id, profile)| Ok((id.clone(), fs::read_to_string(&profile.source)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let backup = BackupFile { format_version: 1, state: backup_state, profiles };
        write_private(destination, &serde_json::to_vec_pretty(&backup)?)
            .with_context(|| format!("write backup {}", destination.display()))
    }

    pub fn restore(&self, source: &Path) -> Result<State> {
        let data = fs::read(source).with_context(|| format!("read backup {}", source.display()))?;
        let backup: BackupFile = serde_json::from_slice(&data).context("invalid backup")?;
        if backup.format_version != 1 {
            bail!("unsupported backup format version: {}", backup.format_version);
        }
        let mut state = backup.state;
        state.connection = None;
        if state.profiles.len() != backup.profiles.len() {
            bail!("backup profile index does not match profile data");
        }
        let profiles_root = self.root.join("profiles");
        let mut destinations = BTreeSet::new();
        for (id, profile) in &state.profiles {
            let parsed_id = Uuid::parse_str(id).with_context(|| format!("invalid profile ID in backup: {id}"))?;
            if parsed_id.simple().to_string() != *id || profile.id != *id {
                bail!("profile ID does not match canonical backup key: {id}");
            }
            let text = backup.profiles.get(id).with_context(|| format!("missing profile data: {id}"))?;
            reject_executable_directives(text, &profile.protocol)?;
            let destination = restored_profile_path(&profiles_root, id, &profile.protocol);
            if !destinations.insert(destination) {
                bail!("backup profile IDs resolve to duplicate filenames");
            }
        }
        self.validate_state(&state)?;

        let transaction_id = Uuid::new_v4().simple().to_string();
        let staging = self.root.join(format!("profiles.restore-{transaction_id}"));
        let previous = self.root.join(format!("profiles.previous-{transaction_id}"));
        create_private_directory(&staging)?;
        let staged_result = (|| -> Result<()> {
            for (id, profile) in &mut state.profiles {
                let text = backup.profiles.get(id).context("validated profile data disappeared")?;
                let staged_path = restored_profile_path(&staging, id, &profile.protocol);
                write_private(&staged_path, text.as_bytes())?;
                profile.source = restored_profile_path(&profiles_root, id, &profile.protocol)
                    .to_string_lossy()
                    .into_owned();
            }
            Ok(())
        })();
        if let Err(error) = staged_result {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }

        fs::rename(&profiles_root, &previous)?;
        if let Err(error) = fs::rename(&staging, &profiles_root) {
            let _ = fs::rename(&previous, &profiles_root);
            let _ = fs::remove_dir_all(&staging);
            return Err(error).context("activate restored profiles");
        }
        let commit_result = self.validate_state(&state)
            .and_then(|_| self.validate_profile_sources(&state))
            .and_then(|_| self.save(&state));
        if let Err(error) = commit_result {
            let failed = self.root.join(format!("profiles.failed-{transaction_id}"));
            let _ = fs::rename(&profiles_root, &failed);
            let rollback_result = fs::rename(&previous, &profiles_root);
            let _ = fs::remove_dir_all(&failed);
            if let Err(rollback_error) = rollback_result {
                return Err(error).context(format!("restore failed and profile rollback failed: {rollback_error}"));
            }
            return Err(error).context("restore rolled back");
        }
        fs::remove_dir_all(previous)?;
        Ok(state)
    }

    fn validate_state(&self, state: &State) -> Result<()> {
        if let Some(id) = &state.default_profile
            && !state.profiles.contains_key(id)
        {
            bail!("default profile does not exist: {id}");
        }
        if let Some(id) = &state.default_server
            && !state.servers.contains_key(id)
        {
            bail!("default server does not exist: {id}");
        }
        for (id, profile) in &state.profiles {
            if profile.id != *id {
                bail!("profile ID does not match state key: {id}");
            }
            if let Some(server_id) = &profile.server_id
                && !state.servers.contains_key(server_id)
            {
                bail!("profile {id} references unknown server: {server_id}");
            }
        }
        for (id, server) in &state.servers {
            if server.id != *id {
                bail!("server ID does not match state key: {id}");
            }
            if let Some(profile_id) = &server.default_profile
                && !state.profiles.contains_key(profile_id)
            {
                bail!("server {id} references unknown profile: {profile_id}");
            }
        }
        if let Some(connection) = &state.connection
            && !state.profiles.contains_key(&connection.profile_id)
        {
            bail!("connection references unknown profile: {}", connection.profile_id);
        }
        Ok(())
    }

    fn validate_profile_sources(&self, state: &State) -> Result<()> {
        let profiles_root = fs::canonicalize(self.root.join("profiles"))?;
        for profile in state.profiles.values() {
            let source = fs::canonicalize(&profile.source)
                .with_context(|| format!("profile file is missing: {}", profile.source))?;
            if source.parent() != Some(profiles_root.as_path()) {
                bail!("profile source is outside managed profile directory: {}", profile.source);
            }
            let text = fs::read_to_string(&source)?;
            reject_executable_directives(&text, &profile.protocol)?;
        }
        Ok(())
    }
}

fn restored_profile_path(profiles_dir: &Path, id: &str, protocol: &Protocol) -> PathBuf {
    let file_stem = if matches!(protocol, Protocol::WireGuard | Protocol::AmneziaWg) {
        format!("amn{}", &id[..11])
    } else {
        id.to_owned()
    };
    profiles_dir.join(format!("{file_stem}.conf"))
}

pub fn detect_protocol(text: &str, path: &Path) -> Result<Protocol> {
    let lower = text.to_ascii_lowercase();
    let extension = path.extension().and_then(|value| value.to_str()).unwrap_or("").to_ascii_lowercase();
    if lower.contains("[interface]") && lower.contains("[peer]") {
        if ["jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"]
            .iter()
            .any(|field| lower.lines().any(|line| line.trim_start().starts_with(&format!("{field} ="))))
        {
            return Ok(Protocol::AmneziaWg);
        }
        return Ok(Protocol::WireGuard);
    }
    if extension == "ovpn" || lower.lines().any(|line| line.trim_start().starts_with("remote ")) {
        return Ok(Protocol::OpenVpn);
    }
    if lower.trim_start().starts_with('{') && (lower.contains("\"outbounds\"") || lower.contains("\"inbounds\"")) {
        return Ok(Protocol::Xray);
    }
    if ["vless://", "vmess://", "trojan://"].iter().any(|prefix| lower.trim_start().starts_with(prefix)) {
        return Ok(Protocol::Xray);
    }
    if lower.trim_start().starts_with("ss://") {
        return Ok(Protocol::Shadowsocks);
    }
    if lower.contains("conn ") && lower.contains("left") && lower.contains("right") {
        return Ok(Protocol::Ikev2);
    }
    if lower.trim_start().starts_with("vpn://") || lower.contains("\"containers\"") {
        return Ok(Protocol::Amnezia);
    }
    bail!("unsupported profile format")
}

fn secure_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("private directory must not be a symbolic link: {}", path.display());
        }
        Ok(metadata) if !metadata.is_dir() => {
            bail!("private directory path is not a directory: {}", path.display());
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
    let parent = path.parent().context("private file path has no parent directory")?;
    let file_name = path.file_name().context("private file path has no filename")?.to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.{}.new", Uuid::new_v4().simple()));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).with_context(|| format!("write {}", path.display()))?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn reject_executable_directives(text: &str, protocol: &Protocol) -> Result<()> {
    if matches!(protocol, Protocol::WireGuard | Protocol::AmneziaWg) {
        const HOOKS: &[&str] = &["preup", "postup", "predown", "postdown"];
        for line in text.lines() {
            let key = line.split_once('=').map(|(key, _)| key.trim().to_ascii_lowercase());
            if let Some(key) = key && HOOKS.contains(&key.as_str()) {
                bail!("WireGuard profile contains executable hook '{key}'");
            }
        }
        return Ok(());
    }
    if protocol != &Protocol::OpenVpn {
        return Ok(());
    }
    const UNSAFE: &[&str] = &[
        "up", "down", "route-up", "route-pre-down", "ipchange", "client-connect",
        "learn-address", "auth-user-pass-verify", "tls-verify", "plugin", "config",
        "script-security",
    ];
    for line in text.lines() {
        let directive = line.trim_start().trim_start_matches('-').split_whitespace().next().unwrap_or("");
        if UNSAFE.contains(&directive) {
            bail!("OpenVPN profile contains executable directive '{directive}'");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_wireguard_and_amneziawg() {
        assert_eq!(detect_protocol("[Interface]\nPrivateKey=x\n[Peer]\nPublicKey=y", Path::new("x.conf")).unwrap(), Protocol::WireGuard);
        assert_eq!(detect_protocol("[Interface]\nJc = 4\n[Peer]\nPublicKey=y", Path::new("x.conf")).unwrap(), Protocol::AmneziaWg);
    }

    #[test]
    fn rejects_wireguard_hooks() {
        let result = reject_executable_directives("[Interface]\nPostUp = curl attacker", &Protocol::WireGuard);
        assert!(result.unwrap_err().to_string().contains("executable hook 'postup'"));
    }

    #[test]
    fn rejects_openvpn_scripts() {
        let result = reject_executable_directives("client\nup /tmp/payload", &Protocol::OpenVpn);
        assert!(result.unwrap_err().to_string().contains("executable directive 'up'"));
        let plugin = reject_executable_directives("client\nplugin evil.so", &Protocol::OpenVpn);
        assert!(plugin.unwrap_err().to_string().contains("executable directive 'plugin'"));
    }

    #[test]
    fn rejects_missing_default_profile_reference() {
        let store = Store { root: PathBuf::new() };
        let state = State { default_profile: Some("missing".into()), ..State::default() };
        assert_eq!(store.validate_state(&state).unwrap_err().to_string(), "default profile does not exist: missing");
    }
}
