use std::{
    env,
    fs,
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

    let destination = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("bundle");
    if destination.exists() {
        fs::remove_dir_all(&destination)
            .with_context(|| format!("remove stale bundle {}", destination.display()))?;
    }
    fs::create_dir_all(&destination)
        .with_context(|| format!("create bundle {}", destination.display()))?;
    fs::copy(&source, destination.join("amn"))
        .with_context(|| format!("copy {} into bundle", source.display()))?;
    copy_directory(
        &profile.join("libexec").join("amn"),
        &destination.join("libexec").join("amn"),
    )?;
    println!("{}", destination.display());
    Ok(())
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
