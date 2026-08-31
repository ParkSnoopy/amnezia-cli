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
    assert!(text.contains("init"));
    assert!(text.contains("doctor"));
}
