//! `shell.plan` (docs/M4.md §6.1) on real files: a temporary folder stands in for the folder
//! Explorer's selection is in.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::Path, sync::Arc};

use beezip_commands::{CmdError, Engine, ErrorCode, NonInteractive, discard_events, registry};
use serde_json::{Value, json};

fn plan(item: &str, paths: &[&Path]) -> Result<Vec<Value>, CmdError> {
    plan_json(json!({ "version": 1, "item": item, "paths": paths }))
}

fn plan_json(request: Value) -> Result<Vec<Value>, CmdError> {
    let out = Engine::new(registry())
        .invoke(
            "shell.plan",
            request,
            Arc::new(NonInteractive),
            discard_events(),
        )
        .unwrap()
        .join()?;
    Ok(out["steps"].as_array().unwrap().clone())
}

fn touch(path: &Path) -> &Path {
    std::fs::write(path, b"").unwrap();
    path
}

fn p(path: &Path) -> Value {
    json!(path)
}

#[test]
fn extract_here_is_smart_and_extract_folder_uses_the_stem() {
    let dir = tempfile::tempdir().unwrap();
    let a = touch(&dir.path().join("a.zip")).to_path_buf();
    let b = touch(&dir.path().join("photos.tar.zst")).to_path_buf();

    let steps = plan("extract-here", &[&a, &b]).unwrap();
    assert_eq!(
        steps,
        [
            json!({ "kind": "run", "title": "Extracting a.zip", "command": "archive.extract",
                    "args": { "archive": p(&a), "dest": p(dir.path()), "smart": true } }),
            json!({ "kind": "run", "title": "Extracting photos.tar.zst", "command": "archive.extract",
                    "args": { "archive": p(&b), "dest": p(dir.path()), "smart": true } }),
        ]
    );

    let steps = plan("extract-folder", &[&b]).unwrap();
    assert_eq!(
        steps[0]["args"],
        json!({ "archive": p(&b), "dest": p(&dir.path().join("photos")) })
    );

    let steps = plan("test", &[&a, &b]).unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[1]["title"], "Testing photos.tar.zst");
    assert_eq!(steps[1]["command"], "archive.test");
    assert_eq!(steps[1]["args"], json!({ "archive": p(&b) }));
}

#[test]
fn a_volume_set_is_one_step_from_its_first_part() {
    let dir = tempfile::tempdir().unwrap();
    let parts: Vec<_> = ["a.7z.001", "a.7z.002", "a.7z.003"]
        .iter()
        .map(|n| touch(&dir.path().join(n)).to_path_buf())
        .collect();
    // Selected in any order, and not every part.
    let steps = plan("extract-folder", &[&parts[2], &parts[0]]).unwrap();
    assert_eq!(steps.len(), 1, "{steps:?}");
    assert_eq!(steps[0]["title"], "Extracting a.7z");
    assert_eq!(
        steps[0]["args"],
        json!({ "archive": p(&parts[0]), "dest": p(&dir.path().join("a")) })
    );

    let rar: Vec<_> = ["b.part1.rar", "b.part2.rar"]
        .iter()
        .map(|n| touch(&dir.path().join(n)).to_path_buf())
        .collect();
    let steps = plan("extract-folder", &[&rar[1], &rar[0], &parts[1]]).unwrap();
    assert_eq!(steps.len(), 2, "{steps:?}");
    assert_eq!(steps[0]["args"]["archive"], p(&rar[0]));
    assert_eq!(steps[0]["args"]["dest"], p(&dir.path().join("b")));
    assert_eq!(steps[1]["args"]["archive"], p(&parts[0]));

    // The extract dialog takes one set.
    let steps = plan("extract-to", &[&parts[1], &parts[2]]).unwrap();
    assert_eq!(
        steps,
        [json!({ "kind": "extract_dialog", "archive": p(&parts[0]) })]
    );
    let err = plan("extract-to", &[&parts[0], &rar[0]]).unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgs);
}

#[test]
fn a_gap_or_a_missing_path_fails_only_its_step() {
    let dir = tempfile::tempdir().unwrap();
    let one = touch(&dir.path().join("c.zip.001")).to_path_buf();
    let three = touch(&dir.path().join("c.zip.003")).to_path_buf();
    let gone = dir.path().join("gone.zip");
    let ok = touch(&dir.path().join("ok.zip")).to_path_buf();

    let steps = plan("extract-here", &[&three, &gone, &ok]).unwrap();
    assert_eq!(steps.len(), 3, "{steps:?}");
    assert_eq!(steps[0]["kind"], "failed");
    assert_eq!(steps[0]["title"], "c.zip.003");
    assert_eq!(steps[0]["error"]["code"], "NotFound");
    assert_eq!(steps[1]["kind"], "failed");
    assert_eq!(steps[1]["title"], "gone.zip");
    assert_eq!(steps[1]["error"]["code"], "NotFound");
    assert!(
        steps[1]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("isn't there any more")
    );
    assert_eq!(steps[2]["args"]["archive"], p(&ok));

    // Core sees the gap from the first part too, since a later part exists.
    let steps = plan("test", &[&one]).unwrap();
    assert_eq!(steps[0]["kind"], "failed");
    assert_eq!(steps[0]["title"], "c.zip.001");

    let steps = plan("open", &[&gone, &ok]).unwrap();
    assert_eq!(steps[0]["kind"], "failed");
    assert_eq!(steps[1], json!({ "kind": "open", "paths": [p(&ok)] }));

    let steps = plan("add-zip", &[&gone]).unwrap();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0]["kind"], "failed");
}

#[test]
fn add_items_name_the_archive_as_the_menu_does() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let a = touch(&work.join("a.txt")).to_path_buf();
    let b = work.join("pics");
    std::fs::create_dir(&b).unwrap();

    // One file: its own name, without its extension.
    let steps = plan("add-zip", &[&a]).unwrap();
    assert_eq!(
        steps,
        [
            json!({ "kind": "run", "title": "Creating a.zip", "command": "archive.create",
                 "args": { "output": p(&work.join("a.zip")), "inputs": [p(&a)] } })
        ]
    );
    // One folder: its name.
    let steps = plan("add-7z", &[&b]).unwrap();
    assert_eq!(steps[0]["args"]["output"], p(&work.join("pics.7z")));
    // Several: their folder's name.
    let steps = plan("add-tar-zst", &[&a, &b]).unwrap();
    assert_eq!(steps[0]["title"], "Creating work.tar.zst");
    assert_eq!(steps[0]["args"]["output"], p(&work.join("work.tar.zst")));
    assert_eq!(steps[0]["args"]["inputs"], json!([p(&a), p(&b)]));
    assert!(steps[0].get("existing").is_none());

    // An archive that's there: the window asks, and knows a free name for keeping both. An
    // empty file isn't an archive, so nothing can be added to it.
    touch(&work.join("work.zip"));
    touch(&work.join("work (1).zip"));
    let steps = plan("add-zip", &[&a, &b]).unwrap();
    assert_eq!(
        steps[0]["existing"],
        json!({ "path": p(&work.join("work.zip")), "keep_both": p(&work.join("work (2).zip")),
                "can_add": false })
    );
    touch(&work.join("work.tar.zst"));
    let steps = plan("add-tar-zst", &[&a, &b]).unwrap();
    assert_eq!(
        steps[0]["existing"]["keep_both"],
        p(&work.join("work (1).tar.zst"))
    );
}

fn thirdparty(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/thirdparty")
        .join(name)
}

#[test]
fn an_existing_archive_can_be_added_to_when_an_edit_could() {
    // docs/M5.md §9: `can_add` follows archive.add's own refusals.
    let dir = tempfile::tempdir().unwrap();
    let a = touch(&dir.path().join("a.txt")).to_path_buf();
    let can_add = |fixture: &str, ext: &str| {
        let archive = dir.path().join(format!("a{ext}"));
        std::fs::copy(thirdparty(fixture), &archive).unwrap();
        let item = match ext {
            ".zip" => "add-zip",
            ".7z" => "add-7z",
            _ => "add-tar-zst",
        };
        let steps = plan(item, &[&a]).unwrap();
        std::fs::remove_file(&archive).unwrap();
        steps[0]["existing"]["can_add"].as_bool().unwrap()
    };
    assert!(can_add("7z-deflate.zip", ".zip"));
    assert!(can_add("7z-zipcrypto.zip", ".zip"), "encrypted entries");
    assert!(can_add("7z-lzma2-mt.7z", ".7z"));
    assert!(can_add("bsdtar.tar.zst", ".tar.zst"));
    // Names encrypted: the job window asks for the password when it adds.
    assert!(can_add("7z-aes-mhe.7z", ".7z"));
    // Self-extracting, and not an archive BeeZip writes.
    assert!(!can_add("7z-sfx.exe", ".7z"));
    assert!(!can_add("7z-readme.md.gz", ".zip"));

    let archive = dir.path().join("a.zip");
    std::fs::copy(thirdparty("7z-deflate.zip"), &archive).unwrap();
    let mut perms = std::fs::metadata(&archive).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&archive, perms.clone()).unwrap();
    let steps = plan("add-zip", &[&a]).unwrap();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&archive, perms).unwrap();
    assert_eq!(steps[0]["existing"]["can_add"], false, "read-only");
}

#[test]
fn dialogs_go_to_the_main_window() {
    let dir = tempfile::tempdir().unwrap();
    let a = touch(&dir.path().join("a.zip")).to_path_buf();
    let b = touch(&dir.path().join("b.txt")).to_path_buf();
    assert_eq!(
        plan("compress-to", &[&a, &b]).unwrap(),
        [json!({ "kind": "create_dialog", "inputs": [p(&a), p(&b)] })]
    );
    assert_eq!(
        plan("open", &[&a]).unwrap(),
        [json!({ "kind": "open", "paths": [p(&a)] })]
    );
}

#[test]
fn bad_requests_are_invalid_args() {
    let dir = tempfile::tempdir().unwrap();
    let a = touch(&dir.path().join("a.zip")).to_path_buf();
    for request in [
        json!({ "version": 2, "item": "test", "paths": [p(&a)] }),
        json!({ "version": 1, "item": "explode", "paths": [p(&a)] }),
        json!({ "version": 1, "item": "test", "paths": [] }),
        json!({ "version": 1, "item": "test", "paths": ["a.zip"] }),
        json!({ "item": "test", "paths": [p(&a)] }),
        json!({ "version": 1, "item": "test", "paths": [p(&a)], "extra": true }),
    ] {
        let err = plan_json(request.clone()).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs, "{request}: {err:?}");
    }
    let err = plan_json(json!({ "version": 1, "item": "test", "paths": ["a.zip"] })).unwrap_err();
    assert!(err.message.contains("isn't absolute"), "{}", err.message);
}

#[test]
fn shell_plan_is_hidden_from_mcp() {
    let entry = registry().get("shell.plan").unwrap();
    assert!(!entry.surfaces.mcp && entry.surfaces.cli && entry.surfaces.gui);
    assert_eq!(entry.cli.unwrap().words(), ["shell", "plan"]);
}
