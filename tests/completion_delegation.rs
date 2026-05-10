use std::process::Command;

fn command_stdout(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .expect("completion test command must be available");

    assert!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("completion output must be UTF-8")
}

fn bash_apt_prefix_candidates() -> Vec<String> {
    let script = r#"
source /usr/share/bash-completion/bash_completion
source completions/odus.bash
COMP_LINE="odus apt up"
COMP_POINT=${#COMP_LINE}
COMP_WORDS=(odus apt up)
COMP_CWORD=2
_odus
printf '%s\n' "${COMPREPLY[@]}"
"#;
    command_stdout("bash", &["-lc", script])
        .lines()
        .map(str::to_owned)
        .collect()
}

fn fish_apt_prefix_candidates() -> Vec<String> {
    let script = r#"source completions/odus.fish; complete -C "odus apt up""#;
    command_stdout("fish", &["-c", script])
        .lines()
        .map(|line| line.split('\t').next().unwrap_or(line).to_owned())
        .collect()
}

fn assert_apt_prefix_is_delegated(candidates: Vec<String>) {
    assert!(candidates.contains(&"update".to_owned()));
    assert!(candidates.contains(&"upgrade".to_owned()));
    assert!(!candidates.contains(&"uptime".to_owned()));
}

#[test]
fn bash_delegates_to_wrapped_command_completion() {
    assert_apt_prefix_is_delegated(bash_apt_prefix_candidates());
}

#[test]
fn fish_delegates_to_wrapped_command_completion() {
    assert_apt_prefix_is_delegated(fish_apt_prefix_candidates());
}
