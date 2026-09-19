use std::process::{Command, Output};

fn host(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_portty-host"))
        .args(args)
        .env_remove("PORTTY_HOST_DETACHED_CHILD")
        .output()
        .expect("run portty-host")
}

#[test]
fn help_is_a_successful_non_daemon_command() {
    let output = host(&["--help"]);

    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Portty host daemon"), "{stderr}");
    assert!(stderr.contains("portty-host serve"), "{stderr}");
}

#[test]
fn version_matches_the_built_package() {
    let output = host(&["--version"]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("portty-host {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_command_fails_with_usage() {
    let output = host(&["not-a-portty-command"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unknown command `not-a-portty-command`"),
        "{stderr}"
    );
    assert!(stderr.contains("USAGE:"), "{stderr}");
}
