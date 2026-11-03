//! The path rules of docs/M1.md §3.5. Some paths are rewritten (extraction continues and the
//! rewrite is reported); some are refused (the entry is skipped).
//!
//! The rules are the same on every platform, so an archive extracts to the same names
//! everywhere.

/// An entry path made safe: relative components to join under the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafePath {
    pub components: Vec<String>,
    /// A prefix was stripped or a component changed, so the result is worth reporting.
    /// Normalising `\` to `/` and dropping `.` or empty components don't count.
    pub renamed: bool,
}

impl SafePath {
    pub fn joined(&self) -> String {
        self.components.join("/")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A `..` component.
    Traversal,
    /// Nothing is left once prefixes, `.` and empty components are gone.
    Empty,
}

const DEVICES: [&str; 8] = [
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM", "LPT",
];

/// Applies the rules, in order:
/// 1. `\` counts as a separator; `.` and empty components are dropped.
/// 2. A leading `/`, drive (`C:`), UNC (`\\server\share`) or `\\?\` prefix is stripped.
/// 3. Any `..` component is refused.
/// 4. `<>:"|?*` and control characters become `_` (closing the NTFS stream hole).
/// 5. Trailing dots and spaces become `_`.
/// 6. Device names (`CON`, `aux.txt`, `COM1`, `LPT²`…) get a `_` prefix.
pub fn sanitize(path: &str) -> Result<SafePath, Refusal> {
    let unified = path.replace('\\', "/");
    let (rest, stripped) = strip_prefix(&unified);
    let mut renamed = stripped;
    let mut components = Vec::new();
    for comp in rest.split('/') {
        match comp {
            "" | "." => {}
            ".." => return Err(Refusal::Traversal),
            _ => {
                let safe = sanitize_component(comp);
                renamed |= safe != comp;
                components.push(safe);
            }
        }
    }
    if components.is_empty() {
        return Err(Refusal::Empty);
    }
    Ok(SafePath {
        components,
        renamed,
    })
}

/// Whether `path` is absolute in either Unix or Windows terms.
pub fn is_absolute(path: &str) -> bool {
    let unified = path.replace('\\', "/");
    strip_prefix(&unified).1
}

/// Strips `//?/` and `//./`, then `UNC/server/share` or `//server/share`, then a drive, then
/// leading slashes. Returns what's left and whether anything was stripped.
fn strip_prefix(p: &str) -> (&str, bool) {
    let orig = p;
    let mut p = p;
    if let Some(rest) = p.strip_prefix("//?/").or_else(|| p.strip_prefix("//./")) {
        p = rest;
        // Compare bytes: slicing the str at 4 panics inside a multi-byte character (found by
        // the `paths` fuzzer). When the bytes match, they are ASCII, so 4 is a boundary.
        if p.as_bytes()
            .get(..4)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"UNC/"))
        {
            p = skip_components(&p[4..], 2);
        }
    } else if let Some(rest) = p.strip_prefix("//") {
        p = skip_components(rest.trim_start_matches('/'), 2);
    }
    // A drive only when a separator or the end follows: `C:\x` and `C:`. `a:b` is a name with
    // a stream in it, and its `:` becomes `_` like any other.
    let bytes = p.as_bytes();
    if bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes.get(2), None | Some(b'/'))
    {
        p = &p[2..];
    }
    p = p.trim_start_matches('/');
    (p, p.len() != orig.len())
}

/// `rest` without its first `n` `/`-separated components.
fn skip_components(rest: &str, n: usize) -> &str {
    let mut r = rest;
    for _ in 0..n {
        r = match r.find('/') {
            Some(i) => &r[i + 1..],
            None => "",
        };
    }
    r
}

fn sanitize_component(comp: &str) -> String {
    let mut s: String = comp
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let keep = s.trim_end_matches(['.', ' ']).len();
    if keep < s.len() {
        let tail = "_".repeat(s.len() - keep);
        s.truncate(keep);
        s.push_str(&tail);
    }
    if is_device(&s) {
        s.insert(0, '_');
    }
    s
}

/// `CON`, `nul.txt`, `COM1`, `lpt³.log`, `CONIN$`… with or without an extension. Windows also
/// ignores trailing spaces before the extension (`NUL .txt`).
fn is_device(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = base.to_uppercase();
    DEVICES.iter().any(|d| match *d {
        "COM" | "LPT" => upper.strip_prefix(d).is_some_and(|n| {
            matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        }),
        d => upper == d,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(path: &str) -> (String, bool) {
        let s = sanitize(path).unwrap_or_else(|e| panic!("{path}: {e:?}"));
        (s.joined(), s.renamed)
    }

    /// The sanitiser's table: input, output, whether it counts as renamed.
    #[test]
    fn table() {
        let cases: &[(&str, &str, bool)] = &[
            ("a/b.txt", "a/b.txt", false),
            ("a\\b\\c.txt", "a/b/c.txt", false),
            ("./a//b/./c", "a/b/c", false),
            ("dir/", "dir", false),
            // Prefixes.
            ("/etc/passwd", "etc/passwd", true),
            ("C:\\Windows\\win.ini", "Windows/win.ini", true),
            ("C:relative.txt", "C_relative.txt", true),
            ("C:..\\x", "C___/x", true),
            ("\\\\server\\share\\x.txt", "x.txt", true),
            ("\\\\?\\C:\\x\\y", "x/y", true),
            ("\\\\?\\UNC\\srv\\sh\\z", "z", true),
            ("\\\\.\\C:\\dev", "dev", true),
            // Multi-byte characters right after the prefix (a fuzzer find: this panicked).
            ("\\\\?\\ab\u{FFFD}x", "ab\u{FFFD}x", true),
            ("//?/é", "é", true),
            ("\\\\?\\UNC\\é\\ü\\z", "z", true),
            // Characters.
            ("a:b", "a_b", true),
            ("file.txt:stream", "file.txt_stream", true),
            ("what?.txt", "what_.txt", true),
            ("<>|\"*.x", "_____.x", true),
            ("tab\there", "tab_here", true),
            // Trailing dots and spaces.
            ("trailing.", "trailing_", true),
            ("spaces  ", "spaces__", true),
            ("dir./file", "dir_/file", true),
            ("...", "___", true),
            // Devices.
            ("CON", "_CON", true),
            ("aux.txt", "_aux.txt", true),
            ("sub/nul.tar.gz", "sub/_nul.tar.gz", true),
            ("COM1", "_COM1", true),
            ("lpt9.log", "_lpt9.log", true),
            ("COM²", "_COM²", true),
            ("CONIN$", "_CONIN$", true),
            ("NUL .txt", "_NUL .txt", true),
            ("COM10", "COM10", false),
            ("console", "console", false),
            ("CONFIG.SYS", "CONFIG.SYS", false),
            // Non-ASCII is fine.
            ("ünïcödé/日本語.txt", "ünïcödé/日本語.txt", false),
        ];
        for (input, want, renamed) in cases {
            assert_eq!(ok(input), ((*want).to_owned(), *renamed), "{input:?}");
        }
    }

    #[test]
    fn refusals() {
        for p in [
            "../x",
            "a/../../x",
            "a\\..\\b",
            "..",
            "/../etc",
            "C:\\..\\x",
        ] {
            assert_eq!(sanitize(p), Err(Refusal::Traversal), "{p}");
        }
        for p in ["", "/", ".", "./", "C:", "\\\\server\\share", "//"] {
            assert_eq!(sanitize(p), Err(Refusal::Empty), "{p}");
        }
    }

    #[test]
    fn absoluteness() {
        assert!(is_absolute("/etc/passwd"));
        assert!(is_absolute("C:\\x"));
        assert!(is_absolute("\\\\srv\\share"));
        assert!(!is_absolute("rel/a"));
        assert!(!is_absolute("../a"));
    }
}
