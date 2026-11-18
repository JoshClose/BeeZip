//! The classic menu's keys (docs/M4.md §5.1), all under HKCU, so no admin:
//!
//! ```text
//! Software\Classes\CLSID\{classic root}\InprocServer32   (default) = <dll>, ThreadingModel = Apartment
//! Software\Classes\*\shell\BeeZip                         ExplorerCommandHandler = {classic root}
//! Software\Classes\Directory\shell\BeeZip                 ExplorerCommandHandler = {classic root}
//! ```
//!
//! Without the cascade each visible item gets a verb of its own, `BeeZip.<nn>-<id>`, with its own
//! CLSID. Explorer orders static verbs by key name (checked on Windows 10), so `<nn>`, the item's
//! place in the menu in two digits, keeps them in menu order. Explorer re-reads the keys for
//! every menu.
//!
//! Before 0.8.0 the number had one digit (`BeeZip.7-add-7z`), which nine items fit and ten
//! don't (`BeeZip.10-…` sorts before `BeeZip.2-…`), and an item added in the middle renumbers
//! the ones after it. So the verbs in place are found by their form, under any number, and a
//! copy that registers the menu removes an older copy's.

use std::path::{Path, PathBuf};

use beezip_menu::{Item, clsid};
use windows_registry::CURRENT_USER;

use super::{Hive, reg_error};
use crate::CmdError;

/// The file types the menu is on: every file, and folders.
const TYPES: [&str; 2] = ["*", "Directory"];
const ROOT_VERB: &str = "BeeZip";

/// An item's top-level verb when the menu isn't cascaded.
pub fn flat_verb(item: Item) -> String {
    let n = Item::ALL.iter().position(|i| *i == item).unwrap_or(0) + 1;
    format!("{ROOT_VERB}.{n:02}-{}", item.id())
}

/// The item a top-level verb is for, under any number: `BeeZip.08-add-7z`, and `BeeZip.7-add-7z`
/// as it was before 0.8.0.
fn flat_item(verb: &str) -> Option<Item> {
    let (n, id) = verb
        .strip_prefix(ROOT_VERB)?
        .strip_prefix('.')?
        .split_once('-')?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Item::from_id(id)
}

/// The menu's verbs under a type's `shell` key, in the order Explorer shows them, each with the
/// class it names: the root, and every item's under whatever number it was given.
fn verbs_of(hive: &Hive, ty: &str) -> Vec<(String, u128)> {
    let Ok(shell) = CURRENT_USER.open(hive.key(&format!(r"Classes\{ty}\shell"))) else {
        return Vec::new();
    };
    let Ok(keys) = shell.keys() else {
        return Vec::new();
    };
    let mut found: Vec<(String, u128)> = keys
        .filter_map(|name| {
            if name == ROOT_VERB {
                Some((name, clsid::CLASSIC_ROOT))
            } else {
                flat_item(&name).map(|item| (name, item.clsid()))
            }
        })
        .collect();
    found.sort();
    found
}

fn verb_key(hive: &Hive, ty: &str, verb: &str) -> String {
    hive.key(&format!(r"Classes\{ty}\shell\{verb}"))
}

fn clsid_key(hive: &Hive, clsid: u128) -> String {
    hive.key(&format!(r"Classes\CLSID\{}", clsid::braced(clsid)))
}

/// What is registered now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    /// The DLL the CLSID keys name.
    pub dll: Option<PathBuf>,
    /// The root verb is there, rather than one verb per item.
    pub cascade: bool,
    /// Each verb found, as `*\shell\BeeZip`.
    pub verbs: Vec<String>,
}

/// The keys in place, or `None` when there is no verb.
pub fn read(hive: &Hive) -> Option<Keys> {
    let mut verbs = Vec::new();
    let mut cascade = false;
    let mut clsids = Vec::new();
    for ty in TYPES {
        for (verb, id) in verbs_of(hive, ty) {
            cascade |= id == clsid::CLASSIC_ROOT;
            verbs.push(format!(r"{ty}\shell\{verb}"));
            clsids.push(id);
        }
    }
    if verbs.is_empty() {
        return None;
    }
    let dll = clsids.iter().find_map(|id| {
        let key = CURRENT_USER
            .open(format!(r"{}\InprocServer32", clsid_key(hive, *id)))
            .ok()?;
        key.get_string("")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    });
    Some(Keys {
        dll,
        cascade,
        verbs,
    })
}

/// Registers the menu for `dll`, replacing whatever form was there. Returns what it did.
pub fn register(
    hive: &Hive,
    dll: &Path,
    cascade: bool,
    hidden: &[Item],
) -> Result<Vec<String>, CmdError> {
    unregister(hive)?;
    let dll_text = dll.to_string_lossy();
    let server = |id: u128| -> Result<(), CmdError> {
        let key = CURRENT_USER
            .create(format!(r"{}\InprocServer32", clsid_key(hive, id)))
            .map_err(|e| reg_error("registering BeeZip's menu", &e))?;
        key.set_string("", &*dll_text)
            .and_then(|()| key.set_string("ThreadingModel", "Apartment"))
            .map_err(|e| reg_error("registering BeeZip's menu", &e))
    };
    let verb = |verb: &str, id: u128| -> Result<(), CmdError> {
        for ty in TYPES {
            let key = CURRENT_USER
                .create(verb_key(hive, ty, verb))
                .map_err(|e| reg_error("adding BeeZip's menu", &e))?;
            key.set_string("ExplorerCommandHandler", clsid::braced(id))
                .map_err(|e| reg_error("adding BeeZip's menu", &e))?;
        }
        Ok(())
    };
    if cascade {
        server(clsid::CLASSIC_ROOT)?;
        verb(ROOT_VERB, clsid::CLASSIC_ROOT)?;
        return Ok(vec![format!(
            "registered the classic menu (a \"BeeZip\" submenu) for {}",
            dll.display()
        )]);
    }
    let shown: Vec<Item> = Item::ALL
        .into_iter()
        .filter(|i| !hidden.contains(i))
        .collect();
    for item in &shown {
        server(item.clsid())?;
        verb(&flat_verb(*item), item.clsid())?;
    }
    Ok(vec![format!(
        "registered the classic menu ({} items at the top level) for {}",
        shown.len(),
        dll.display()
    )])
}

/// Removes every verb and CLSID key the classic menu can have. Returns what it removed.
pub fn unregister(hive: &Hive) -> Result<Vec<String>, CmdError> {
    let mut removed = Vec::new();
    for ty in TYPES {
        for (verb, _) in verbs_of(hive, ty) {
            if remove_tree(&verb_key(hive, ty, &verb))? {
                removed.push(format!(r"removed {ty}\shell\{verb}"));
            }
        }
    }
    for id in std::iter::once(clsid::CLASSIC_ROOT).chain(Item::ALL.into_iter().map(Item::clsid)) {
        remove_tree(&clsid_key(hive, id))?;
    }
    // The parents, when only BeeZip's keys were in them: `*\shell`, `*`, `Directory\shell`…
    for ty in TYPES {
        remove_if_empty(&hive.key(&format!(r"Classes\{ty}\shell")))?;
        remove_if_empty(&hive.key(&format!(r"Classes\{ty}")))?;
    }
    Ok(removed)
}

/// Deletes `path` when it has no subkey and no value.
pub(crate) fn remove_if_empty(path: &str) -> Result<(), CmdError> {
    let Ok(key) = CURRENT_USER.open(path) else {
        return Ok(());
    };
    let empty = key.keys().is_ok_and(|mut k| k.next().is_none())
        && key.values().is_ok_and(|mut v| v.next().is_none());
    drop(key);
    if empty {
        remove_tree(path)?;
    }
    Ok(())
}

/// Deletes `path` and everything under it. `false` when it wasn't there.
pub(crate) fn remove_tree(path: &str) -> Result<bool, CmdError> {
    if CURRENT_USER.open(path).is_err() {
        return Ok(false);
    }
    CURRENT_USER
        .remove_tree(path)
        .map(|()| true)
        .map_err(|e| reg_error(&format!("removing HKCU\\{path}"), &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Cleanup(Hive);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = CURRENT_USER.remove_tree(self.0.base());
        }
    }

    #[test]
    fn flat_verbs_sort_in_menu_order() {
        let verbs: Vec<String> = Item::ALL.into_iter().map(flat_verb).collect();
        let mut sorted = verbs.clone();
        sorted.sort();
        assert_eq!(verbs, sorted);
        assert_eq!(verbs[0], "BeeZip.01-open");
        assert_eq!(verbs[9], "BeeZip.10-compress-to");
        for item in Item::ALL {
            assert_eq!(flat_item(&flat_verb(item)), Some(item));
        }
        // As they were numbered before 0.8.0, and what isn't BeeZip's.
        assert_eq!(flat_item("BeeZip.7-add-7z"), Some(Item::Add7z));
        assert_eq!(flat_item("BeeZip.9-compress-to"), Some(Item::CompressTo));
        for not in [
            "BeeZip",
            "BeeZip.",
            "BeeZip.x-open",
            "BeeZip.1-nope",
            "BeeZipper.1-open",
        ] {
            assert_eq!(flat_item(not), None, "{not}");
        }
    }

    /// A menu an older copy registered, numbered as it was then, is seen and replaced whole.
    #[test]
    fn an_older_copys_verbs_are_replaced() {
        let hive = Hive::test("classic-older");
        let _cleanup = Cleanup(hive.clone());
        let dll = Path::new(r"C:\BeeZip\beezip_shell_0.8.0.dll");
        let older = ["BeeZip.1-open", "BeeZip.7-add-7z", "BeeZip.9-compress-to"];
        for ty in TYPES {
            for verb in older {
                CURRENT_USER
                    .create(verb_key(&hive, ty, verb))
                    .unwrap()
                    .set_string("ExplorerCommandHandler", "{x}")
                    .unwrap();
            }
            // Someone else's verb stays.
            CURRENT_USER
                .create(verb_key(&hive, ty, "Other.1-open"))
                .unwrap();
        }
        let keys = read(&hive).unwrap();
        assert!(!keys.cascade);
        assert_eq!(keys.verbs.len(), 6);

        register(&hive, dll, false, &[]).unwrap();
        let keys = read(&hive).unwrap();
        assert_eq!(keys.verbs.len(), 2 * Item::ALL.len());
        for verb in older {
            assert!(!keys.verbs.iter().any(|v| v.ends_with(verb)), "{verb}");
        }
        assert!(keys.verbs.contains(&r"*\shell\BeeZip.08-add-7z".to_owned()));

        assert_eq!(unregister(&hive).unwrap().len(), 2 * Item::ALL.len());
        assert_eq!(read(&hive), None);
        for ty in TYPES {
            assert!(
                CURRENT_USER
                    .open(verb_key(&hive, ty, "Other.1-open"))
                    .is_ok()
            );
        }
    }

    #[test]
    fn register_read_and_unregister() {
        let hive = Hive::test("classic");
        let _cleanup = Cleanup(hive.clone());
        let dll = Path::new(r"C:\BeeZip\beezip_shell_0.1.0.dll");
        assert_eq!(read(&hive), None);

        register(&hive, dll, true, &[]).unwrap();
        let keys = read(&hive).unwrap();
        assert!(keys.cascade);
        assert_eq!(keys.dll.as_deref(), Some(dll));
        assert_eq!(keys.verbs, [r"*\shell\BeeZip", r"Directory\shell\BeeZip"]);
        let root = CURRENT_USER
            .open(hive.key(r"Classes\*\shell\BeeZip"))
            .unwrap();
        assert_eq!(
            root.get_string("ExplorerCommandHandler").unwrap(),
            "{B788B651-F40D-446D-A601-2D23F9E0C37B}"
        );
        let server = CURRENT_USER
            .open(hive.key(r"Classes\CLSID\{B788B651-F40D-446D-A601-2D23F9E0C37B}\InprocServer32"))
            .unwrap();
        assert_eq!(server.get_string("ThreadingModel").unwrap(), "Apartment");

        // Switching to the flat form leaves no root verb behind.
        register(&hive, dll, false, &[Item::Test]).unwrap();
        let keys = read(&hive).unwrap();
        assert!(!keys.cascade);
        assert_eq!(keys.verbs.len(), 2 * 9);
        assert!(!keys.verbs.iter().any(|v| v.ends_with(r"\BeeZip")));
        assert!(!keys.verbs.iter().any(|v| v.ends_with("-test")));
        assert_eq!(keys.dll.as_deref(), Some(dll));

        let removed = unregister(&hive).unwrap();
        assert_eq!(removed.len(), 18);
        assert_eq!(read(&hive), None);
        // Nothing but the empty CLSID folder is left under Classes.
        assert!(CURRENT_USER.open(hive.key(r"Classes\*")).is_err());
        assert!(CURRENT_USER.open(hive.key(r"Classes\Directory")).is_err());
        assert!(
            CURRENT_USER
                .open(hive.key(r"Classes\CLSID\{EA0379CD-D0D3-4A69-A9D2-583104EED7DC}"))
                .is_err()
        );
    }
}
