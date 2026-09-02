use std::process::Command;

#[test]
fn invalid_command_prints_complete_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_amn"))
        .arg("invalid-command")
        .output()
        .expect("run amn");
    assert!(!output.status.success());

    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(text.contains("unrecognized subcommand 'invalid-command'"));
    assert!(text.contains("Usage: amn [OPTIONS] [COMMAND]"));
    assert!(text.contains("Commands:"));
    assert!(text.contains("install"));
    assert!(!text.contains("  init"));
    assert!(text.contains("doctor"));
}

#[test]
fn generates_bash_and_zsh_completions_without_creating_state() {
    let data_directory = std::env::temp_dir().join(format!(
        "amn-completion-test-{}",
        std::process::id()
    ));
    assert!(!data_directory.exists());

    let bash = Command::new(env!("CARGO_BIN_EXE_amn"))
        .arg("--data-dir")
        .arg(&data_directory)
        .args(["completion", "bash"])
        .output()
        .expect("generate Bash completion");
    assert!(bash.status.success());
    assert!(!data_directory.exists());
    let bash = String::from_utf8(bash.stdout).unwrap();
    assert!(bash.contains("_amn()"));
    assert!(bash.contains("complete"));

    let zsh = Command::new(env!("CARGO_BIN_EXE_amn"))
        .args(["completion", "zsh"])
        .output()
        .expect("generate Zsh completion");
    assert!(zsh.status.success());
    let zsh = String::from_utf8(zsh.stdout).unwrap();
    assert!(zsh.contains("#compdef amn"));
    assert!(zsh.contains("_amn"));
}
