//! The sanitiser's invariants: whatever the input, an accepted path is relative, stays under the
//! destination, and has no `..`, no device name and no forbidden character. Sanitising it again
//! changes nothing.

#![no_main]

use std::path::{Component, Path};

use beezip_core::safefs::sanitize::{Refusal, sanitize};
use libfuzzer_sys::fuzz_target;

const DEVICES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];

fn is_device(component: &str) -> bool {
    let base = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ');
    let upper = base.to_uppercase();
    DEVICES.contains(&upper.as_str())
        || ["COM", "LPT"].iter().any(|p| {
            upper.strip_prefix(p).is_some_and(|n| {
                let mut digits = n.chars();
                matches!(digits.next(), Some('1'..='9' | '¹' | '²' | '³'))
                    && digits.next().is_none()
            })
        })
}

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let safe = match sanitize(&input) {
        Ok(s) => s,
        Err(Refusal::Traversal) => {
            assert!(input.replace('\\', "/").split('/').any(|c| c == ".."));
            return;
        }
        Err(Refusal::Empty) => return,
    };
    assert!(!safe.components.is_empty());
    for c in &safe.components {
        assert!(
            !c.is_empty() && c != "." && c != "..",
            "{c:?} from {input:?}"
        );
        assert!(
            !c.contains(['/', '\\', '<', '>', ':', '"', '|', '?', '*']),
            "{c:?}"
        );
        assert!(!c.chars().any(char::is_control), "{c:?}");
        assert!(!c.ends_with(['.', ' ']), "{c:?}");
        assert!(!is_device(c), "{c:?} from {input:?}");
    }
    let joined = safe.joined();
    let dest = Path::new("dest");
    let full = dest.join(&joined);
    assert!(full.starts_with(dest));
    assert!(
        Path::new(&joined)
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        "{joined:?} from {input:?}"
    );
    let again = sanitize(&joined).expect("a sanitised path is accepted again");
    assert_eq!(again.components, safe.components, "from {input:?}");
    assert!(!again.renamed, "{joined:?} changed on a second pass");
});
