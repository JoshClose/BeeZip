//! Where tool calls may write (docs/M2.md §3.1–3.2).
//!
//! The server's roots come from `--root` (or `[mcp] roots`). Clients on protocol 2025-11-25
//! or older can also share roots of their own. A non-empty list narrows the server's to the
//! intersection, and an empty one changes nothing. 2026-07-28 deprecates client roots, so
//! newer clients get `--root` alone.

use std::{
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use beezip_commands::{CmdError, ErrorCode, Policy, policy::describe_roots};

#[derive(Debug)]
pub struct Sandbox {
    /// Canonical.
    roots: Vec<PathBuf>,
    read_only: bool,
    unrestricted: bool,
    /// The client's roots, canonical; `None` until fetched, and again once they change.
    client: Mutex<Option<Vec<PathBuf>>>,
}

impl Sandbox {
    /// Fails if a root doesn't exist or isn't a directory.
    pub fn new(roots: &[PathBuf], read_only: bool, unrestricted: bool) -> Result<Self, CmdError> {
        let mut canonical = Vec::new();
        for root in roots {
            let c = std::fs::canonicalize(root)
                .ok()
                .filter(|c| c.is_dir())
                .ok_or_else(|| {
                    CmdError::invalid_args(format!(
                        "--root `{}` isn't an existing directory",
                        root.display()
                    ))
                })?;
            if !canonical.contains(&c) {
                canonical.push(c);
            }
        }
        Ok(Self {
            roots: canonical,
            read_only,
            unrestricted,
            client: Mutex::new(None),
        })
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    fn client(&self) -> std::sync::MutexGuard<'_, Option<Vec<PathBuf>>> {
        self.client.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a write should fetch the client's roots first.
    pub fn needs_client_roots(&self) -> bool {
        !self.unrestricted && !self.read_only && self.client().is_none()
    }

    /// `notifications/roots/list_changed`: fetch them again before the next write.
    pub fn client_roots_changed(&self) {
        *self.client() = None;
    }

    /// Records the client's roots, given as URIs. Anything but an existing `file://` path is
    /// ignored.
    pub fn set_client_roots<'a>(&self, uris: impl IntoIterator<Item = &'a str>) {
        let mut roots: Vec<PathBuf> = uris.into_iter().filter_map(root_path).collect();
        roots.sort();
        roots.dedup();
        *self.client() = Some(roots);
    }

    /// Where writes may go now: `None` means anywhere.
    fn effective(&self) -> Option<Vec<PathBuf>> {
        if self.unrestricted {
            return None;
        }
        match self.client().as_deref() {
            Some(client) if !client.is_empty() => Some(intersect(&self.roots, client)),
            _ => Some(self.roots.clone()),
        }
    }

    /// The policy for one call, from the base policy. A command that writes is refused here,
    /// with the reason, when nothing may be written at all.
    pub fn policy(&self, base: &Policy, writes: bool) -> Result<Policy, CmdError> {
        let mut policy = base.clone();
        policy.read_only |= self.read_only;
        policy.roots = self.effective();
        if writes
            && !policy.read_only
            && let Some(roots) = &policy.roots
            && roots.is_empty()
        {
            return Err(CmdError::new(
                ErrorCode::OutsideSandbox,
                self.why_no_roots(),
            ));
        }
        Ok(policy)
    }

    fn why_no_roots(&self) -> String {
        if self.roots.is_empty() {
            return "BeeZip's MCP server was started without `--root`, so it can't write files. \
                    To allow writes, add `--root <dir>` to its command line in the client's \
                    MCP settings."
                .to_owned();
        }
        let client = self.client().clone().unwrap_or_default();
        format!(
            "none of the client's roots ({}) overlaps BeeZip's `--root` directories ({}), so \
             nothing can be written",
            describe_roots(&client),
            describe_roots(&self.roots)
        )
    }

    /// One sentence for the server's instructions.
    pub fn describe(&self) -> String {
        if self.read_only {
            "This server is read-only: the commands that write files aren't offered.".to_owned()
        } else if self.unrestricted {
            "Commands may write anywhere (the server runs with `--unrestricted`).".to_owned()
        } else if self.roots.is_empty() {
            "The server was started without `--root`, so commands that write files fail with \
             OutsideSandbox; the user can add `--root <dir>` to its command line to allow \
             writes."
                .to_owned()
        } else {
            format!(
                "Commands that write files may only write under {}.",
                describe_roots(&self.roots)
            )
        }
    }
}

/// The canonical path of a `file://` URI that exists.
fn root_path(uri: &str) -> Option<PathBuf> {
    let url = url::Url::parse(uri).ok()?;
    if url.scheme() != "file" {
        return None;
    }
    std::fs::canonicalize(url.to_file_path().ok()?).ok()
}

/// For each pair of roots where one contains the other, the deeper one; minus any that lie
/// inside another.
fn intersect(server: &[PathBuf], client: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for s in server {
        for c in client {
            let deeper: &Path = if c.starts_with(s) {
                c
            } else if s.starts_with(c) {
                s
            } else {
                continue;
            };
            if !out.iter().any(|o| o == deeper) {
                out.push(deeper.to_path_buf());
            }
        }
    }
    let all = out.clone();
    out.retain(|p| !all.iter().any(|q| q != p && p.starts_with(q)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use beezip_commands::{Access, Effect};

    fn uri(path: &Path) -> String {
        url::Url::from_file_path(path).unwrap().to_string()
    }

    struct Tree {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    /// `root/{a/inner, b}`, canonical.
    fn tree() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("a/inner")).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        Tree { _dir: dir, root }
    }

    #[test]
    fn intersection_keeps_the_deeper_root() {
        let t = tree();
        let p = |names: &[&str]| -> Vec<PathBuf> {
            names
                .iter()
                .map(|n| {
                    if n.is_empty() {
                        t.root.clone()
                    } else {
                        t.root.join(n)
                    }
                })
                .collect()
        };
        let cut = |server: &[&str], client: &[&str]| intersect(&p(server), &p(client));
        assert_eq!(cut(&["a"], &["a/inner"]), p(&["a/inner"]));
        assert_eq!(cut(&["a/inner"], &["a"]), p(&["a/inner"]));
        assert_eq!(cut(&["a"], &["b"]), p(&[]));
        assert_eq!(cut(&["a", "b"], &[""]), p(&["a", "b"]));
        // A root inside another adds nothing.
        assert_eq!(cut(&["a"], &["a", "a/inner"]), p(&["a"]));
    }

    #[test]
    fn roots_must_exist() {
        let t = tree();
        let err = Sandbox::new(&[t.root.join("missing")], false, false).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgs);
        std::fs::write(t.root.join("f"), "").unwrap();
        assert!(Sandbox::new(&[t.root.join("f")], false, false).is_err());
        // Spelled two ways, a root counts once.
        let s = Sandbox::new(&[t.root.join("a"), t.root.join("b/../a")], false, false).unwrap();
        assert_eq!(s.roots, [t.root.join("a")]);
    }

    #[test]
    fn client_roots_narrow_and_an_empty_list_does_not() {
        let t = tree();
        let s = Sandbox::new(std::slice::from_ref(&t.root), false, false).unwrap();
        let base = Policy::unrestricted();
        assert!(s.needs_client_roots());
        assert_eq!(
            s.policy(&base, true).unwrap().roots,
            Some(vec![t.root.clone()])
        );

        s.set_client_roots([uri(&t.root.join("a")).as_str(), "https://example.com/x"]);
        assert!(!s.needs_client_roots());
        let p = s.policy(&base, true).unwrap();
        assert_eq!(p.roots, Some(vec![t.root.join("a")]));
        let write = |path: PathBuf| p.check("x.y", Effect::Writes, &[Access::Write(path)]);
        assert!(write(t.root.join("a/inner/new.zip")).is_ok());
        assert_eq!(
            write(t.root.join("b/new.zip")).unwrap_err().code,
            ErrorCode::OutsideSandbox
        );

        // An empty list (or only roots that don't exist) leaves --root as it is.
        s.set_client_roots([uri(&t.root.join("gone")).as_str()]);
        assert_eq!(
            s.policy(&base, true).unwrap().roots,
            Some(vec![t.root.clone()])
        );

        s.client_roots_changed();
        assert!(s.needs_client_roots());
    }

    #[test]
    fn no_roots_refuse_writes_with_the_reason() {
        let t = tree();
        let base = Policy::unrestricted();
        let none = Sandbox::new(&[], false, false).unwrap();
        let err = none.policy(&base, true).unwrap_err();
        assert_eq!(err.code, ErrorCode::OutsideSandbox);
        assert!(err.message.contains("--root"), "{}", err.message);
        // Reads still run.
        assert!(none.policy(&base, false).is_ok());

        let a = Sandbox::new(&[t.root.join("a")], false, false).unwrap();
        a.set_client_roots([uri(&t.root.join("b")).as_str()]);
        let err = a.policy(&base, true).unwrap_err();
        assert!(err.message.contains("overlaps"), "{}", err.message);
    }

    #[test]
    fn read_only_and_unrestricted() {
        let base = Policy::unrestricted();
        let ro = Sandbox::new(&[], true, false).unwrap();
        let p = ro.policy(&base, true).unwrap();
        assert!(p.read_only);
        assert_eq!(
            p.check("x.y", Effect::Writes, &[]).unwrap_err().code,
            ErrorCode::UnsupportedOperation
        );
        assert!(!ro.needs_client_roots());

        let anywhere = Sandbox::new(&[], false, true).unwrap();
        assert_eq!(anywhere.policy(&base, true).unwrap().roots, None);
        assert!(!anywhere.needs_client_roots());
    }
}
