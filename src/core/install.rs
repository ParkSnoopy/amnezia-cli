use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use uuid::Uuid;

const PROGRAMS: &[&str] = &[
    "wg",
    "wg-quick",
    "wireguard-go",
    "awg",
    "awg-quick",
    "openvpn",
    "tun2socks",
    "amneziawg-go",
    "amnezia-xray-runner",
    "amn-dns",
];
const DATA_FILES: &[&str] = &["geoip.dat", "geosite.dat"];

pub fn install() -> Result<String> {
    if effective_user_id() != Some(0) {
        bail!("init requires root permission; run `sudo ./amn init`");
    }
    let executable = std::env::current_exe().context("locate running amn binary")?;
    install_from(&executable, Path::new("/usr/local"))?;
    Ok("Installed amn in /usr/local/bin and bundled programs in /usr/local/libexec/amn"
        .to_owned())
}

fn install_from(executable: &Path, prefix: &Path) -> Result<()> {
    let executable = fs::canonicalize(executable).context("resolve running amn binary")?;
    require_regular_file(&executable)?;
    let source_directory = bundled_directory(&executable)?;
    for name in PROGRAMS.iter().chain(DATA_FILES) {
        require_regular_file(&source_directory.join(name))?;
    }

    let bin_directory = prefix.join("bin");
    let libexec_directory = prefix.join("libexec");
    fs::create_dir_all(&bin_directory).context("create installation binary directory")?;
    fs::create_dir_all(&libexec_directory).context("create installation program directory")?;

    let transaction = Uuid::new_v4().simple().to_string();
    let staged_binary = bin_directory.join(format!(".amn-install-{transaction}"));
    let staged_programs = libexec_directory.join(format!(".amn-install-{transaction}"));
    fs::create_dir(&staged_programs).context("stage bundled program directory")?;

    let result = (|| {
        copy_file(&executable, &staged_binary, 0o755)?;
        for name in PROGRAMS {
            copy_file(&source_directory.join(name), &staged_programs.join(name), 0o755)?;
        }
        for name in DATA_FILES {
            copy_file(&source_directory.join(name), &staged_programs.join(name), 0o644)?;
        }
        activate_installation(
            &staged_binary,
            &staged_programs,
            &bin_directory.join("amn"),
            &libexec_directory.join("amn"),
            &transaction,
        )
    })();

    if result.is_err() {
        remove_path(&staged_binary);
        remove_path(&staged_programs);
    }
    result
}

fn bundled_directory(executable: &Path) -> Result<PathBuf> {
    let directory = executable.parent().context("running amn binary has no parent directory")?;
    [
        directory.join("libexec").join("amn"),
        directory.join("..").join("libexec").join("amn"),
    ]
    .into_iter()
    .find_map(|candidate| fs::canonicalize(candidate).ok())
    .context("bundled programs were not found relative to the running amn binary")
}

fn activate_installation(
    staged_binary: &Path,
    staged_programs: &Path,
    installed_binary: &Path,
    installed_programs: &Path,
    transaction: &str,
) -> Result<()> {
    let binary_backup = installed_binary.with_file_name(format!(".amn-backup-{transaction}"));
    let programs_backup = installed_programs.with_file_name(format!(".amn-backup-{transaction}"));
    let had_binary = installed_binary.exists() || installed_binary.is_symlink();
    let had_programs = installed_programs.exists() || installed_programs.is_symlink();

    if had_programs {
        fs::rename(installed_programs, &programs_backup).context("stage installed programs for replacement")?;
    }
    if let Err(error) = fs::rename(staged_programs, installed_programs) {
        if had_programs {
            let _ = fs::rename(&programs_backup, installed_programs);
        }
        return Err(error).context("install bundled programs");
    }
    if had_binary
        && let Err(error) = fs::rename(installed_binary, &binary_backup)
    {
        rollback_programs(installed_programs, &programs_backup, had_programs);
        return Err(error).context("stage installed amn binary for replacement");
    }
    if let Err(error) = fs::rename(staged_binary, installed_binary) {
        if had_binary {
            let _ = fs::rename(&binary_backup, installed_binary);
        }
        rollback_programs(installed_programs, &programs_backup, had_programs);
        return Err(error).context("install amn binary");
    }

    remove_path(&binary_backup);
    remove_path(&programs_backup);
    Ok(())
}

fn rollback_programs(installed: &Path, backup: &Path, had_previous: bool) {
    remove_path(installed);
    if had_previous {
        let _ = fs::rename(backup, installed);
    }
}

fn copy_file(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    fs::copy(source, destination)
        .with_context(|| format!("copy installation file {}", source.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(destination, fs::Permissions::from_mode(mode))
            .with_context(|| format!("set installation permissions on {}", destination.display()))?;
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect installation source {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("installation source is not a regular file: {}", path.display());
    }
    Ok(())
}

fn remove_path(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_dir() {
        let _ = fs::remove_dir_all(path);
    } else {
        let _ = fs::remove_file(path);
    }
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

    #[test]
    fn installs_binary_and_bundle_in_usr_local_layout() {
        let root = std::env::temp_dir().join(format!("amn-install-test-{}", Uuid::new_v4().simple()));
        let release = root.join("release");
        let source_programs = release.join("libexec/amn");
        fs::create_dir_all(&source_programs).unwrap();
        fs::write(release.join("amn"), b"amn").unwrap();
        for name in PROGRAMS.iter().chain(DATA_FILES) {
            fs::write(source_programs.join(name), name.as_bytes()).unwrap();
        }

        let prefix = root.join("usr/local");
        install_from(&release.join("amn"), &prefix).unwrap();

        assert_eq!(fs::read(prefix.join("bin/amn")).unwrap(), b"amn");
        for name in PROGRAMS.iter().chain(DATA_FILES) {
            assert_eq!(
                fs::read(prefix.join("libexec/amn").join(name)).unwrap(),
                name.as_bytes()
            );
        }

        fs::write(release.join("amn"), b"updated").unwrap();
        fs::write(source_programs.join("wireguard-go"), b"updated").unwrap();
        install_from(&release.join("amn"), &prefix).unwrap();
        assert_eq!(fs::read(prefix.join("bin/amn")).unwrap(), b"updated");
        assert_eq!(
            fs::read(prefix.join("libexec/amn/wireguard-go")).unwrap(),
            b"updated"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
