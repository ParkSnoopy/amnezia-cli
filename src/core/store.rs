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
    State,
};

const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BACKUP_BYTES: usize = 64 * 1024 * 1024;

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
            None => {
                dirs::data_local_dir()
                    .context("cannot determine local data directory")?
                    .join("amn")
            }
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
        let state =
            serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display()))?;
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
            .with_context(|| format!("unknown profile: {id}"))?;
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
            .with_context(|| format!("unknown profile: {id}"))?;
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

    pub fn restore(&self, source: &Path) -> Result<State> {
        if fs::metadata(source)
            .with_context(|| format!("inspect backup {}", source.display()))?
            .len()
            > MAX_BACKUP_BYTES as u64
        {
            bail!("backup exceeds the 64 MiB size limit");
        }
        let data = fs::read(source).with_context(|| format!("read backup {}", source.display()))?;
        let backup: BackupFile = serde_json::from_slice(&data).context("invalid backup")?;
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
        for (id, profile) in &state.profiles {
            let parsed_id = Uuid::parse_str(id)
                .with_context(|| format!("invalid profile ID in backup: {id}"))?;
            if parsed_id.simple().to_string() != *id || profile.id != *id {
                bail!("profile ID does not match canonical backup key: {id}");
            }
            let text = backup
                .profiles
                .get(id)
                .with_context(|| format!("missing profile data: {id}"))?;
            if text.len() > MAX_PROFILE_BYTES {
                bail!("backup profile exceeds the 16 MiB size limit: {id}");
            }
            reject_executable_directives(text, &profile.protocol)?;
            validate_protocol_configuration(text, &profile.protocol)?;
            let destination = restored_profile_path(&profiles_root, id, &profile.protocol);
            if !destinations.insert(destination) {
                bail!("backup profile IDs resolve to duplicate filenames");
            }
        }
        self.validate_state(&state)?;

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
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }

        fs::rename(&profiles_root, &previous)?;
        if let Err(error) = fs::rename(&staging, &profiles_root) {
            let _ = fs::rename(&previous, &profiles_root);
            let _ = fs::remove_dir_all(&staging);
            return Err(error).context("activate restored profiles");
        }
        let commit_result = self
            .validate_state(&state)
            .and_then(|_| self.validate_profile_sources(&state))
            .and_then(|_| self.save(&state));
        if let Err(error) = commit_result {
            let failed = self.root.join(format!("profiles.failed-{transaction_id}"));
            let _ = fs::rename(&profiles_root, &failed);
            let rollback_result = fs::rename(&previous, &profiles_root);
            let _ = fs::remove_dir_all(&failed);
            if let Err(rollback_error) = rollback_result {
                return Err(error).context(format!(
                    "restore failed and profile rollback failed: {rollback_error}"
                ));
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
        }
        for (id, server) in &state.servers {
            if server.id != *id {
                bail!("server ID does not match state key: {id}");
            }
        }
        if let Some(connection) = &state.connection
            && !state.profiles.contains_key(&connection.profile_id)
        {
            bail!(
                "connection references unknown profile: {}",
                connection.profile_id
            );
        }
        Ok(())
    }

    pub(crate) fn validated_profile_text(&self, profile: &Profile) -> Result<String> {
        let profiles_root = fs::canonicalize(self.root.join("profiles"))?;
        let source = fs::canonicalize(&profile.source)
            .with_context(|| format!("profile file is missing: {}", profile.source))?;
        if source.parent() != Some(profiles_root.as_path()) {
            bail!(
                "profile source is outside managed profile directory: {}",
                profile.source
            );
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

fn profile_extension(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::OpenVpn => "ovpn",
        Protocol::Xray | Protocol::Shadowsocks | Protocol::Ikev2 => "json",
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
        } else if name.contains("ssxray") || name.contains("shadowsocks") {
            Some((
                Protocol::Shadowsocks,
                ["ssxray", "shadowsocks", "ssxray_config_data"].as_slice(),
            ))
        } else if name.contains("xray") {
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
        } else if name.contains("ipsec") || name.contains("ikev2") {
            Some((Protocol::Ikev2, ["ikev2", "ikev2_config_data"].as_slice()))
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
        && serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .is_some_and(|document| {
                let configuration = document.get("ikev2_config_data").unwrap_or(&document);
                let classic = ["cert", "certificate"]
                    .iter()
                    .any(|key| configuration.get(*key).is_some())
                    && ["hostName", "host_name", "host"]
                        .iter()
                        .any(|key| configuration.get(*key).is_some());
                let android = configuration
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    == Some("ikev2-cert")
                    && configuration.pointer("/remote/addr").is_some()
                    && configuration.pointer("/local/p12").is_some();
                let nested = configuration
                    .get("config")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
                    .is_some_and(|value| {
                        value.get("cert").is_some() && value.get("hostName").is_some()
                    });
                let encoded = document
                    .get("ikev2_config_data")
                    .is_some_and(serde_json::Value::is_string);
                classic || android || nested || encoded
            })
    {
        return Ok(Protocol::Ikev2);
    }
    if lower.trim_start().starts_with('{')
        && (lower.contains("\"outbounds\"") || lower.contains("\"inbounds\""))
    {
        if serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|document| {
                document
                    .get("outbounds")
                    .and_then(serde_json::Value::as_array)
                    .cloned()
            })
            .is_some_and(|outbounds| {
                outbounds.iter().any(|outbound| {
                    outbound.get("protocol").and_then(serde_json::Value::as_str)
                        == Some("shadowsocks")
                })
            })
        {
            return Ok(Protocol::Shadowsocks);
        }
        return Ok(Protocol::Xray);
    }
    if lower.trim_start().starts_with("ss://") {
        return Ok(Protocol::Shadowsocks);
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
    match protocol {
        Protocol::OpenVpn => {
            crate::core::openvpn::prepare(text, &crate::core::model::Settings::default())?;
        }
        Protocol::Xray => {
            crate::core::xray::RawConfiguration::parse(text)?;
        }
        Protocol::Shadowsocks => {
            crate::core::shadowsocks::parse(text)?;
        }
        Protocol::Ikev2 => {
            crate::core::ikev2::validate(text)?;
        }
        Protocol::WireGuard | Protocol::AmneziaWg => {
            let has_private_key =
                text.lines()
                    .filter_map(|line| line.split_once('='))
                    .any(|(key, value)| {
                        key.trim().eq_ignore_ascii_case("PrivateKey")
                            && !value
                                .split('#')
                                .next()
                                .unwrap_or_default()
                                .trim()
                                .is_empty()
                    });
            if !has_private_key {
                bail!("WireGuard profile has no private key");
            }
            let has_public_key =
                text.lines()
                    .filter_map(|line| line.split_once('='))
                    .any(|(key, value)| {
                        key.trim().eq_ignore_ascii_case("PublicKey")
                            && !value
                                .split('#')
                                .next()
                                .unwrap_or_default()
                                .trim()
                                .is_empty()
                    });
            if !has_public_key {
                bail!("WireGuard profile has no peer public key");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_wireguard_amneziawg_and_raw_xray() {
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
                "{\"hostName\":\"vpn.example\",\"cert\":\"AA==\"}",
                Path::new("x.json")
            )
            .unwrap(),
            Protocol::Ikev2
        );
        let shadowsocks = r#"{"outbounds":[{"protocol":"shadowsocks"}]}"#;
        assert_eq!(
            detect_protocol(shadowsocks, Path::new("x.json")).unwrap(),
            Protocol::Shadowsocks
        );
        assert!(detect_protocol("vless://unsupported-share-link", Path::new("x.txt")).is_err());
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
            "defaultContainer":"amnezia-awg",
            "containers":[
                {"container":"amnezia-openvpn","openvpn":{"last_config":"{\"config\":\"client\\nremote vpn.example 1194\"}"}},
                {"container":"amnezia-awg","awg":{"last_config":"{\"config\":\"[Interface]\\nPrivateKey=x\\n[Peer]\\nPublicKey=y\"}"}}
            ]
        }"#;
        let configurations = normalize_imported_profiles(bundle, Path::new("bundle.json")).unwrap();
        assert_eq!(configurations.len(), 2);
        assert_eq!(configurations[0].1, Protocol::AmneziaWg);
        assert_eq!(configurations[1].1, Protocol::OpenVpn);
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
            "default profile does not exist: missing"
        );
    }
}
