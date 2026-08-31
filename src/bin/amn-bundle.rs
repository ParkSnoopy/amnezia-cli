use std::{
    env,
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "--release", "--bin", "amn"])
        .status()
        .context("build amn for the bundle")?;
    if !status.success() {
        bail!("amn release build failed with {status}");
    }

    let executable = env::current_exe().context("locate bundle builder")?;
    let profile = executable
        .parent()
        .context("bundle builder has no profile directory")?;
    let source = profile.join("amn");
    if !source.is_file() {
        bail!("release executable is missing: {}", source.display());
    }

    let source_helpers = profile.join("libexec").join("amn");
    let destination = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("bundle");
    if bundle_matches(&source, &source_helpers, &destination)? {
        println!("{} (cached)", destination.display());
        return Ok(());
    }
    if destination.exists() {
        fs::remove_dir_all(&destination)
            .with_context(|| format!("remove stale bundle {}", destination.display()))?;
    }
    fs::create_dir_all(&destination)
        .with_context(|| format!("create bundle {}", destination.display()))?;
    fs::copy(&source, destination.join("amn"))
        .with_context(|| format!("copy {} into bundle", source.display()))?;
    copy_directory(
        &source_helpers,
        &destination.join("libexec").join("amn"),
    )?;
    println!("{}", destination.display());
    Ok(())
}

fn bundle_matches(executable: &Path, helpers: &Path, bundle: &Path) -> Result<bool> {
    if !files_match(executable, &bundle.join("amn"))? {
        return Ok(false);
    }
    directories_match(helpers, &bundle.join("libexec").join("amn"))
}

fn directories_match(source: &Path, destination: &Path) -> Result<bool> {
    if !source.is_dir() || !destination.is_dir() {
        return Ok(false);
    }
    let mut source_entries = directory_entries(source)?;
    let mut destination_entries = directory_entries(destination)?;
    source_entries.sort_by_key(|entry| entry.file_name());
    destination_entries.sort_by_key(|entry| entry.file_name());
    if source_entries.len() != destination_entries.len() {
        return Ok(false);
    }
    for (source_entry, destination_entry) in source_entries.iter().zip(&destination_entries) {
        if source_entry.file_name() != destination_entry.file_name() {
            return Ok(false);
        }
        let source_type = source_entry
            .file_type()
            .with_context(|| format!("inspect {}", source_entry.path().display()))?;
        let destination_type = destination_entry
            .file_type()
            .with_context(|| format!("inspect {}", destination_entry.path().display()))?;
        if source_type.is_dir() && destination_type.is_dir() {
            if !directories_match(&source_entry.path(), &destination_entry.path())? {
                return Ok(false);
            }
        } else if source_type.is_file() && destination_type.is_file() {
            if !files_match(&source_entry.path(), &destination_entry.path())? {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }
    Ok(true)
}

fn directory_entries(directory: &Path) -> Result<Vec<fs::DirEntry>> {
    fs::read_dir(directory)
        .with_context(|| format!("read {}", directory.display()))?
        .map(|entry| entry.with_context(|| format!("read {} entry", directory.display())))
        .collect()
}

fn files_match(source: &Path, destination: &Path) -> Result<bool> {
    let source_metadata = match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", source.display())),
    };
    let destination_metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", destination.display()));
        }
    };
    if source_metadata.len() != destination_metadata.len() {
        return Ok(false);
    }
    if source_metadata.permissions().mode() != destination_metadata.permissions().mode() {
        return Ok(false);
    }
    let mut source_file = fs::File::open(source)
        .with_context(|| format!("open {}", source.display()))?;
    let mut destination_file = fs::File::open(destination)
        .with_context(|| format!("open {}", destination.display()))?;
    let mut source_buffer = [0_u8; 64 * 1024];
    let mut destination_buffer = [0_u8; 64 * 1024];
    loop {
        let source_read = source_file
            .read(&mut source_buffer)
            .with_context(|| format!("read {}", source.display()))?;
        let destination_read = destination_file
            .read(&mut destination_buffer)
            .with_context(|| format!("read {}", destination.display()))?;
        if source_read != destination_read
            || source_buffer[..source_read] != destination_buffer[..destination_read]
        {
            return Ok(false);
        }
        if source_read == 0 {
            return Ok(true);
        }
    }
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("create {}", destination.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry.with_context(|| format!("read {} entry", source.display()))?;
        let source = entry.path();
        let destination = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", source.display()))?;
        if file_type.is_dir() {
            copy_directory(&source, &destination)?;
        } else if file_type.is_file() {
            fs::copy(&source, &destination).with_context(|| {
                format!("copy {} to {}", source.display(), destination.display())
            })?;
        } else {
            bail!("bundle input is not a regular file or directory: {}", source.display());
        }
    }
    Ok(())
}
