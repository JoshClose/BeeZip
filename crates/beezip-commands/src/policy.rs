//! What a job may do (docs/M1.md §4.1). The engine checks a command's declared accesses against
//! the policy after deserialising its input and before running it.

use std::path::{Path, PathBuf};

use beezip_core::Limits;

use crate::{CmdError, Effect, ErrorCode};

/// A path a command reads or writes, as its `access()` declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Read(PathBuf),
    Write(PathBuf),
}

#[derive(Debug, Clone)]
pub struct Policy {
    /// Refuse every command that isn't read-only.
    pub read_only: bool,
    /// When set, writes outside these directories fail with `OutsideSandbox`. MCP sets them;
    /// the CLI and the GUI don't.
    pub roots: Option<Vec<PathBuf>>,
    pub limits: Limits,
    /// The most entries one `archive.list` page holds, whatever `limit` asks for. For front
    /// ends that pay for every byte of output, like MCP (docs/M2.md §4).
    pub max_list_entries: Option<u64>,
    /// The most bytes one `entry.read` returns, whatever `max_bytes` asks for.
    pub max_read_bytes: Option<u64>,
}

impl Policy {
    /// What the CLI and the GUI use: no restrictions beyond the limits.
    pub fn unrestricted() -> Self {
        Self {
            read_only: false,
            roots: None,
            limits: Limits::default(),
            max_list_entries: None,
            max_read_bytes: None,
        }
    }

    /// Checks a command before it runs.
    pub fn check(&self, name: &str, effect: Effect, accesses: &[Access]) -> Result<(), CmdError> {
        if self.read_only && effect != Effect::ReadOnly {
            return Err(CmdError::new(
                ErrorCode::UnsupportedOperation,
                format!("`{name}` changes files, and this session is read-only"),
            ));
        }
        let Some(roots) = &self.roots else {
            return Ok(());
        };
        let roots: Vec<PathBuf> = roots
            .iter()
            .filter_map(|r| std::fs::canonicalize(r).ok())
            .collect();
        for access in accesses {
            if let Access::Write(path) = access {
                let resolved = resolve(path);
                if !roots.iter().any(|r| resolved.starts_with(r)) {
                    return Err(CmdError::new(
                        ErrorCode::OutsideSandbox,
                        format!(
                            "`{}` is outside the directories this session may write to: {}",
                            display_path(&resolved),
                            describe_roots(&roots)
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The roots, for messages: `C:\a, C:\b`, or `none`.
pub fn describe_roots(roots: &[PathBuf]) -> String {
    if roots.is_empty() {
        return "none".to_owned();
    }
    roots
        .iter()
        .map(|r| display_path(r))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A path as people write it: without the `\\?\` prefix `canonicalize` adds on Windows.
pub fn display_path(path: &Path) -> String {
    let s = path.display().to_string();
    match s.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => s.strip_prefix(r"\\?\").map_or(s.clone(), str::to_owned),
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::unrestricted()
    }
}

/// `path` with its nearest existing ancestor canonicalised, so a junction or symlink on the way
/// is followed before the containment check. The rest is appended as written.
fn resolve(path: &Path) -> PathBuf {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut existing = abs.as_path();
    let mut rest = Vec::new();
    loop {
        if let Ok(canon) = std::fs::canonicalize(existing) {
            let mut out = canon;
            out.extend(rest.iter().rev());
            return out;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                existing = parent;
            }
            _ => return abs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_refuses_writes() {
        let p = Policy {
            read_only: true,
            ..Policy::unrestricted()
        };
        assert!(p.check("a.b", Effect::ReadOnly, &[]).is_ok());
        let err = p.check("a.b", Effect::Writes, &[]).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedOperation);
    }

    #[test]
    fn roots_confine_writes() {
        let dir = tempfile::tempdir().unwrap();
        let p = Policy {
            roots: Some(vec![dir.path().to_path_buf()]),
            ..Policy::unrestricted()
        };
        let inside = Access::Write(dir.path().join("new/deeper/file.zip"));
        assert!(p.check("a.b", Effect::Writes, &[inside]).is_ok());
        let escape = Access::Write(dir.path().join("..").join("x.zip"));
        let err = p.check("a.b", Effect::Writes, &[escape]).unwrap_err();
        assert_eq!(err.code, ErrorCode::OutsideSandbox);
        // The message names the roots, as people write them.
        let root = display_path(&std::fs::canonicalize(dir.path()).unwrap());
        assert!(err.message.ends_with(&root), "{}", err.message);
        assert!(!err.message.contains(r"\\?\"), "{}", err.message);
        // Reads aren't confined by roots.
        let read = Access::Read(PathBuf::from("/elsewhere"));
        assert!(p.check("a.b", Effect::ReadOnly, &[read]).is_ok());
    }

    #[test]
    fn no_roots_refuse_every_write() {
        let dir = tempfile::tempdir().unwrap();
        let p = Policy {
            roots: Some(Vec::new()),
            ..Policy::unrestricted()
        };
        let err = p
            .check(
                "a.b",
                Effect::Writes,
                &[Access::Write(dir.path().join("x"))],
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::OutsideSandbox);
        assert!(err.message.ends_with(": none"), "{}", err.message);
    }

    #[test]
    fn display_path_drops_the_verbatim_prefix() {
        assert_eq!(display_path(Path::new(r"\\?\C:\work")), r"C:\work");
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\server\share")),
            r"\\server\share"
        );
        assert_eq!(display_path(Path::new("/tmp/x")), "/tmp/x");
    }
}
