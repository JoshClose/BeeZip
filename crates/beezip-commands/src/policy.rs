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
    /// When set, writes outside these directories fail with `OutsideSandbox`. MCP sets them in
    /// M2; the CLI and the GUI don't.
    pub roots: Option<Vec<PathBuf>>,
    pub limits: Limits,
}

impl Policy {
    /// What the CLI and the GUI use: no restrictions beyond the limits.
    pub fn unrestricted() -> Self {
        Self {
            read_only: false,
            roots: None,
            limits: Limits::default(),
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
                        format!("`{}` is outside the allowed roots", path.display()),
                    ));
                }
            }
        }
        Ok(())
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
        // Reads aren't confined by roots.
        let read = Access::Read(PathBuf::from("/elsewhere"));
        assert!(p.check("a.b", Effect::ReadOnly, &[read]).is_ok());
    }
}
