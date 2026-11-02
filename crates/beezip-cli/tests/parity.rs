//! Every registry command reaches every surface it claims, with the same schema everywhere.

use assert_cmd::Command;
use beezip_commands::registry;
use beezip_mcp::{tool_name, tools};
use serde_json::Value;

const COMMANDS_TS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../apps/desktop/src/gen/commands.ts"
);

fn beezip() -> Command {
    Command::new(env!("CARGO_BIN_EXE_beezip"))
}

#[test]
fn cli_reaches_every_command() {
    for entry in registry().entries() {
        let out = beezip()
            .args(["--output", "json", "schema", entry.name])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let schema: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            schema["input"],
            Value::Object((*entry.input_schema).clone()),
            "{}",
            entry.name
        );

        if let Some(spec) = entry.cli {
            beezip().args([spec.name, "--help"]).assert().success();
            for alias in spec.aliases {
                beezip().args([alias, "--help"]).assert().success();
            }
        }
    }
}

#[test]
fn mcp_lists_exactly_the_mcp_commands_with_the_same_schemas() {
    let tools = tools(registry());
    for entry in registry().entries() {
        let tool = tools.iter().find(|t| t.name == tool_name(entry.name));
        match (entry.surfaces.mcp, tool) {
            (true, Some(tool)) => {
                assert_eq!(*tool.input_schema, *entry.input_schema, "{}", entry.name);
                assert_eq!(
                    tool.output_schema.as_deref(),
                    Some(&*entry.output_schema),
                    "{}",
                    entry.name
                );
            }
            (true, None) => panic!("{} is missing from tools/list", entry.name),
            (false, Some(_)) => panic!("{} is hidden from MCP but listed", entry.name),
            (false, None) => {}
        }
    }
    let visible = registry()
        .entries()
        .iter()
        .filter(|e| e.surfaces.mcp)
        .count();
    assert_eq!(tools.len(), visible);
}

#[test]
fn typescript_bindings_have_every_command() {
    let ts = std::fs::read_to_string(COMMANDS_TS)
        .expect("apps/desktop/src/gen/commands.ts exists; run `cargo xtask codegen`");
    for entry in registry().entries() {
        assert!(
            ts.contains(&format!("\"{}\": {{ input:", entry.name)),
            "{} is not in commands.ts; run `cargo xtask codegen`",
            entry.name
        );
    }
}
