//! The `beezip` binary end to end: generated and built-in subcommands, output modes, exit codes.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

fn beezip() -> Command {
    Command::new(env!("CARGO_BIN_EXE_beezip"))
}

fn stdout_json(cmd: &mut Command) -> Value {
    let out = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&out).expect("stdout is one JSON document")
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn help_lists_generated_and_builtin_subcommands() {
    let out = beezip()
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(out).unwrap();
    for sub in ["version", "run", "commands", "schema", "mcp", "--output"] {
        assert!(help.contains(sub), "`{sub}` missing from --help:\n{help}");
    }
}

#[test]
fn version_subcommand_is_human_readable() {
    beezip()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with(format!("BeeZip {VERSION} (")));
}

#[test]
fn run_app_version_as_json() {
    let out = stdout_json(beezip().args(["run", "app.version", "--output", "json"]));
    assert_eq!(out["version"], VERSION);
    assert!(out["platform"].as_str().is_some_and(|p| p.contains('-')));
    assert!(matches!(out["profile"].as_str(), Some("debug" | "release")));
}

#[test]
fn generated_subcommand_and_run_agree() {
    let generated = stdout_json(beezip().args(["--output", "json", "version"]));
    let generic = stdout_json(beezip().args(["--output", "json", "run", "app.version"]));
    assert_eq!(generated, generic);
}

#[test]
fn json_args_from_a_file() {
    let dir = std::env::temp_dir().join(format!("beezip-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("args.json");
    std::fs::write(&file, "{}").unwrap();
    let out = stdout_json(
        beezip()
            .args(["run", "app.version", "--output", "json", "--json"])
            .arg(format!("@{}", file.display())),
    );
    assert_eq!(out["version"], VERSION);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unknown_fields_are_invalid_args() {
    beezip()
        .args(["run", "app.version", "--json", r#"{"bogus":1}"#])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("InvalidArgs"));
}

#[test]
fn malformed_json_is_invalid_args() {
    beezip()
        .args(["run", "app.version", "--json", "{nope"])
        .assert()
        .code(2);
}

#[test]
fn unknown_command_is_not_found() {
    beezip()
        .args(["run", "no.such"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("NotFound"));
}

#[test]
fn errors_are_json_in_json_mode() {
    let out = beezip()
        .args(["--output", "json", "run", "no.such"])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();
    let out: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(out["error"]["code"], "NotFound");
}

#[test]
fn ndjson_streams_job_events() {
    let out = beezip()
        .args(["--output", "ndjson", "run", "app.version"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let events: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events.first().unwrap()["type"], "Started");
    let last = events.last().unwrap();
    assert_eq!(last["type"], "Finished");
    assert_eq!(last["output"]["version"], VERSION);
}

#[test]
fn schema_prints_input_and_output_schemas() {
    let out = stdout_json(beezip().args(["--output", "json", "schema", "app.version"]));
    assert_eq!(out["name"], "app.version");
    assert_eq!(out["effect"], "ReadOnly");
    assert_eq!(out["input"]["type"], "object");
    assert_eq!(out["input"]["additionalProperties"], false);
    assert!(out["output"]["properties"]["version"].is_object());
}

#[test]
fn commands_lists_app_version() {
    beezip()
        .arg("commands")
        .assert()
        .success()
        .stdout(predicate::str::contains("app.version"));
}

#[test]
fn shell_plan_turns_a_click_into_steps() {
    let zip = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty/7z-deflate.zip")
        .canonicalize()
        .unwrap();
    let dir = zip.parent().unwrap();
    let out = stdout_json(
        beezip()
            .args(["--output", "json", "shell", "plan", "extract-folder"])
            .arg(&zip),
    );
    assert_eq!(out["steps"][0]["kind"], "run");
    assert_eq!(out["steps"][0]["command"], "archive.extract");
    assert_eq!(out["steps"][0]["title"], "Extracting 7z-deflate.zip");
    assert_eq!(
        out["steps"][0]["args"]["dest"],
        dir.join("7z-deflate").display().to_string()
    );
    // `run` takes the job file itself.
    let request = serde_json::json!({ "version": 1, "item": "open", "paths": [zip] });
    let generic = stdout_json(
        beezip()
            .args(["--output", "json", "run", "shell.plan", "--json"])
            .arg(request.to_string()),
    );
    assert_eq!(
        generic["steps"][0],
        serde_json::json!({ "kind": "open", "paths": [zip] })
    );
}
