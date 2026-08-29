use crate::core::model::Server;
use crate::core::runner;
use anyhow::{Context, Result, bail};
use std::process::{Command, Output};

pub fn run_ssh(server: &Server, remote_args: &[&str], dry_run: bool) -> Result<String> {
    let (program, args) = ssh_command(server, remote_args);
    if dry_run {
        return Ok(format_command(&program, &args));
    }
    let executable = check_dependencies(server)?;
    let output = Command::new(&executable).args(&args).output().with_context(|| format!("start {program}"))?;
    output_text(output)
}

pub fn check_dependencies(server: &Server) -> Result<std::path::PathBuf> {
    if let Some(identity) = &server.identity_file {
        let metadata = std::fs::metadata(identity).with_context(|| format!("read SSH identity {identity}"))?;
        if !metadata.is_file() {
            bail!("SSH identity is not a regular file: {identity}");
        }
    }
    runner::resolve_program("ssh")
}

pub fn ssh_command(server: &Server, remote_args: &[&str]) -> (String, Vec<String>) {
    let mut args = vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-p".into(),
        server.port.to_string(),
    ];
    if let Some(identity) = &server.identity_file {
        args.extend(["-i".into(), identity.clone()]);
    }
    args.push("--".into());
    args.push(format!("{}@{}", server.user, server.host));
    args.extend(remote_args.iter().map(|value| (*value).to_owned()));
    ("ssh".into(), args)
}

fn output_text(output: Output) -> Result<String> {
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!("SSH failed ({}): {}", output.status, error);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn format_command(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(|value| {
            if value.chars().all(|character| character.is_ascii_alphanumeric() || "-._/:=@".contains(character)) {
                value.to_owned()
            } else {
                format!("'{value}'", value = value.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn scan(server: &Server, dry_run: bool) -> Result<String> {
    if dry_run {
        return Ok(format!("{}\n{}", run_ssh(server, &["command", "-v", "docker"], true)?, run_ssh(
            server,
            &["docker", "ps", "--all", "--format", "{{.Names}}\\t{{.Status}}\\t{{.Image}}"],
            true,
        )?));
    }
    run_ssh(server, &["command", "-v", "docker"], false)
        .context("remote Docker dependency is unavailable")?;
    run_ssh(
        server,
        &["docker", "ps", "--all", "--format", "{{.Names}}\\t{{.Status}}\\t{{.Image}}"],
        dry_run,
    )
}

pub fn reboot(server: &Server, confirmed: bool, dry_run: bool) -> Result<String> {
    if !confirmed {
        bail!("reboot requires --yes");
    }
    if dry_run {
        return Ok(format!("{}\n{}", run_ssh(server, &["sudo", "-n", "true"], true)?, run_ssh(server, &["sudo", "reboot"], true)?));
    }
    run_ssh(server, &["sudo", "-n", "true"], false).context("remote passwordless sudo dependency is unavailable")?;
    run_ssh(server, &["sudo", "reboot"], false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_arguments_do_not_use_shell() {
        let server = Server {
            id: "id".into(), name: "name".into(), host: "vpn.example".into(), port: 2222,
            user: "admin".into(), identity_file: Some("/home/me/key".into()),
        };
        let (program, args) = ssh_command(&server, &["docker", "ps"]);
        assert_eq!(program, "ssh");
        assert_eq!(args.last().unwrap(), "ps");
        assert!(args.contains(&"admin@vpn.example".to_owned()));
        assert!(!args.iter().any(|value| value.contains(';')));
    }
}
