use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const RESOLVER_PATH: &str = "/etc/resolv.conf";
const STATE_ROOT: &str = "/run/amn/dns";

struct Paths {
    resolver: PathBuf,
    state_root: PathBuf,
    require_root_owner: bool,
}

impl Paths {
    fn system() -> Self {
        Self {
            resolver: RESOLVER_PATH.into(),
            state_root: STATE_ROOT.into(),
            require_root_owner: true,
        }
    }
}

struct Record {
    target: PathBuf,
    mode: u32,
    original: Vec<u8>,
    applied: Vec<u8>,
}

fn main() -> ExitCode {
    match run(&env::args().collect::<Vec<_>>(), &Paths::system()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String], paths: &Paths) -> Result<(), String> {
    if effective_user_id() != Some(0) {
        return Err("DNS changes require root permission".into());
    }
    match arguments.get(1).map(String::as_str) {
        Some("set") => {
            let interface = arguments.get(2).ok_or("DNS set requires an interface")?;
            let values = arguments.get(3..).unwrap_or_default();
            let search_index = values.iter().position(|value| value == "--search");
            let (servers, search) = match search_index {
                Some(index) => (&values[..index], &values[index + 1..]),
                None => (values, &[][..]),
            };
            set_dns(paths, interface, servers, search)
        }
        Some("unset") => {
            let interface = arguments.get(2).ok_or("DNS unset requires an interface")?;
            if arguments.len() != 3 {
                return Err("DNS unset accepts exactly one interface".into());
            }
            unset_dns(paths, interface)
        }
        _ => Err("usage: amn-dns set INTERFACE SERVER... | amn-dns unset INTERFACE".into()),
    }
}

fn set_dns(
    paths: &Paths,
    interface: &str,
    servers: &[String],
    search: &[String],
) -> Result<(), String> {
    validate_interface(interface)?;
    if servers.is_empty() {
        return Err("DNS set requires at least one server".into());
    }
    let mut applied = Vec::new();
    for server in servers {
        let server = server
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid DNS server: {server}"))?;
        writeln!(applied, "nameserver {server}").map_err(|error| error.to_string())?;
    }
    if !search.is_empty() {
        for domain in search {
            validate_search_domain(domain)?;
        }
        writeln!(applied, "search {}", search.join(" ")).map_err(|error| error.to_string())?;
    }

    let target = resolver_target(paths)?;
    let state = paths.state_root.join(interface);
    if state.exists() {
        let record = read_record(&state)?;
        let current = read_file(&target)?;
        if record.target == target && record.applied == applied && current == applied {
            return Ok(());
        }
        if record.target == target && record.applied == applied && current == record.original {
            return atomic_write(&target, &record.applied, record.mode);
        }
        return Err(format!(
            "DNS ownership state already exists for interface {interface}"
        ));
    }

    ensure_owned_directory(&paths.state_root, paths.require_root_owner)?;
    fs::create_dir(&state).map_err(|error| format!("create DNS state: {error}"))?;
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("protect DNS state: {error}"))?;
    let metadata = fs::metadata(&target).map_err(|error| format!("inspect resolver: {error}"))?;
    let record = Record {
        target: target.clone(),
        mode: metadata.permissions().mode() & 0o777,
        original: read_file(&target)?,
        applied,
    };
    if let Err(error) = write_record(&state, &record)
        .and_then(|()| atomic_write(&target, &record.applied, record.mode))
    {
        let _ = fs::remove_dir_all(&state);
        return Err(error);
    }
    Ok(())
}

fn unset_dns(paths: &Paths, interface: &str) -> Result<(), String> {
    validate_interface(interface)?;
    let state = paths.state_root.join(interface);
    if !state.exists() {
        return Ok(());
    }
    let record = read_record(&state)?;
    let target = resolver_target(paths)?;
    if target != record.target {
        return Err("resolver target changed while the VPN connection was active".into());
    }
    let current = read_file(&target)?;
    if current == record.original {
        remove_state(&state)?;
        return Ok(());
    }
    if current != record.applied {
        return Err("resolver contents changed outside amn; refusing to overwrite them".into());
    }
    atomic_write(&target, &record.original, record.mode)?;
    remove_state(&state)
}

fn validate_search_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty()
        || domain.len() > 253
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
    {
        return Err(format!("invalid DNS search domain: {domain}"));
    }
    Ok(())
}

fn validate_interface(interface: &str) -> Result<(), String> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err("invalid DNS interface name".into());
    }
    Ok(())
}

fn resolver_target(paths: &Paths) -> Result<PathBuf, String> {
    let target = fs::canonicalize(&paths.resolver)
        .map_err(|error| format!("resolve {}: {error}", paths.resolver.display()))?;
    let metadata = fs::symlink_metadata(&target)
        .map_err(|error| format!("inspect resolver target {}: {error}", target.display()))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o022 != 0 {
        return Err("resolver target must be a regular file without group or other write access".into());
    }
    if paths.require_root_owner && metadata.uid() != 0 {
        return Err("resolver target must be owned by root".into());
    }
    Ok(target)
}

fn ensure_owned_directory(path: &Path, require_root_owner: bool) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        ensure_owned_directory(parent, require_root_owner)?;
    }
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect {}: {error}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("create {}: {error}", path.display())),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(format!("{} must be a protected directory", path.display()));
    }
    if require_root_owner && metadata.uid() != 0 {
        return Err(format!("{} must be owned by root", path.display()));
    }
    Ok(())
}

fn write_record(state: &Path, record: &Record) -> Result<(), String> {
    let target = record
        .target
        .to_str()
        .ok_or("resolver target path is not valid UTF-8")?;
    write_private(&state.join("target"), target.as_bytes())?;
    write_private(&state.join("mode"), record.mode.to_string().as_bytes())?;
    write_private(&state.join("original"), &record.original)?;
    write_private(&state.join("applied"), &record.applied)
}

fn read_record(state: &Path) -> Result<Record, String> {
    let target = String::from_utf8(read_file(&state.join("target"))?)
        .map_err(|_| "saved resolver target is not UTF-8")?;
    let mode = String::from_utf8(read_file(&state.join("mode"))?)
        .map_err(|_| "saved resolver mode is not UTF-8")?
        .parse::<u32>()
        .map_err(|_| "saved resolver mode is invalid")?;
    if mode & !0o777 != 0 {
        return Err("saved resolver mode is invalid".into());
    }
    Ok(Record {
        target: target.into(),
        mode,
        original: read_file(&state.join("original"))?,
        applied: read_file(&state.join("applied"))?,
    })
}

fn write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write {}: {error}", path.display()))
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("resolver target has no parent directory")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("resolver target name is not valid UTF-8")?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch")?
        .as_nanos();
    let temporary = parent.join(format!(".{name}.amn-{}-{nonce}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
            .map_err(|error| format!("create resolver replacement: {error}"))?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("write resolver replacement: {error}"))?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("set resolver permissions: {error}"))?;
        fs::rename(&temporary, path).map_err(|error| format!("replace resolver: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut contents = Vec::new();
    fs::File::open(path)
        .and_then(|mut file| file.read_to_end(&mut contents))
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(contents)
}

fn remove_state(state: &Path) -> Result<(), String> {
    fs::remove_dir_all(state).map_err(|error| format!("remove DNS state: {error}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(label: &str) -> Paths {
        let root = env::temp_dir().join(format!("amn-dns-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let resolver = root.join("resolv.conf");
        fs::write(&resolver, b"nameserver 192.0.2.1\n").unwrap();
        fs::set_permissions(&resolver, fs::Permissions::from_mode(0o644)).unwrap();
        Paths {
            resolver,
            state_root: root.join("state"),
            require_root_owner: false,
        }
    }

    #[test]
    fn restores_the_exact_resolver_contents() {
        let paths = paths("restore");
        set_dns(
            &paths,
            "amnxray0",
            &["1.1.1.1".into(), "1.0.0.1".into()],
            &[],
        )
        .unwrap();
        assert_eq!(
            fs::read(&paths.resolver).unwrap(),
            b"nameserver 1.1.1.1\nnameserver 1.0.0.1\n"
        );
        unset_dns(&paths, "amnxray0").unwrap();
        assert_eq!(
            fs::read(&paths.resolver).unwrap(),
            b"nameserver 192.0.2.1\n"
        );
        assert!(!paths.state_root.join("amnxray0").exists());
        fs::remove_dir_all(paths.resolver.parent().unwrap()).unwrap();
    }

    #[test]
    fn refuses_to_overwrite_an_external_resolver_change() {
        let paths = paths("ownership");
        set_dns(&paths, "amnawg0", &["1.1.1.1".into()], &[]).unwrap();
        fs::write(&paths.resolver, b"nameserver 198.51.100.1\n").unwrap();
        let error = unset_dns(&paths, "amnawg0").unwrap_err();
        assert!(error.contains("changed outside amn"));
        assert!(paths.state_root.join("amnawg0").is_dir());
        fs::remove_dir_all(paths.resolver.parent().unwrap()).unwrap();
    }

    #[test]
    fn existing_ownership_can_reapply_after_partial_unset() {
        let paths = paths("reapply");
        let servers = ["1.1.1.1".into()];
        set_dns(&paths, "amnxray0", &servers, &[]).unwrap();
        fs::write(&paths.resolver, b"nameserver 192.0.2.1\n").unwrap();

        set_dns(&paths, "amnxray0", &servers, &[]).unwrap();

        assert_eq!(
            fs::read(&paths.resolver).unwrap(),
            b"nameserver 1.1.1.1\n"
        );
        assert!(paths.state_root.join("amnxray0").is_dir());
        fs::remove_dir_all(paths.resolver.parent().unwrap()).unwrap();
    }

    #[test]
    fn missing_state_is_an_idempotent_unset() {
        let paths = paths("missing");
        unset_dns(&paths, "amnwg0").unwrap();
        fs::remove_dir_all(paths.resolver.parent().unwrap()).unwrap();
    }
}
