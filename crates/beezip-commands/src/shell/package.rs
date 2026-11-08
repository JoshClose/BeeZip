//! The Windows 11 menu's sparse package (docs/M4.md §5.2), through `PackageManager`, from safe
//! Rust. The package, identity `BeeZip`, holds only its manifest and logos; its external location
//! is the folder of the menu's DLL, which the manifest names.
//!
//! - **Signed** (`beezip-sparse.msix`): `AddPackageByUriAsync`, which needs the signature to chain
//!   to a certificate in `LocalMachine\TrustedPeople` or a trusted root (§16, item 2).
//! - **Development** (a folder holding `AppxManifest.xml`): `RegisterPackageByUriAsync` with
//!   `DeveloperMode`, which needs Developer Mode and nothing else: no admin, no certificate.
//!
//! Every operation is for the current user. One that finds the package in use (the surrogate
//! holds the DLL for a few seconds after a menu closes) is tried once more after a pause. Nothing
//! is ever forced to shut down: a BeeZip window opened from the menu runs with the package's
//! identity, and forcing would close it. A registration Windows refuses because the same version
//! is there from another manifest (a development package whose DLL was renamed) removes the old
//! one and tries again.
//!
//! Tests never reach a real package: a test [`Hive`] has no package name, so [`find`] finds
//! nothing and the rest refuse.

use std::path::{Path, PathBuf};
use std::time::Duration;

use windows::ApplicationModel::Package;
use windows::Foundation::Uri;
use windows::Management::Deployment::{
    AddPackageOptions, DeploymentProgress, DeploymentResult, PackageManager, RegisterPackageOptions,
};
use windows_core::{HRESULT, HSTRING};
use windows_future::{AsyncStatus, IAsyncOperationWithProgress};

use super::{Hive, PUBLISHERS};
use crate::{CmdError, ErrorCode};

/// `ERROR_PACKAGES_IN_USE`: a process with the package's identity is running, or the surrogate
/// still holds the DLL.
const PACKAGES_IN_USE: HRESULT = HRESULT(0x8007_3D02_u32 as i32);
/// `ERROR_PACKAGE_ALREADY_EXISTS`: the same version is registered from another manifest.
const ALREADY_EXISTS: HRESULT = HRESULT(0x8007_3CFB_u32 as i32);
/// How long to wait before trying again, once. One removal in the spike waited 5.3 s.
const IN_USE_PAUSE: Duration = Duration::from_secs(6);

/// A registered BeeZip package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub full_name: String,
    /// Registered from a manifest under Developer Mode, rather than from a signed `.msix`.
    pub development: bool,
    /// The external location: the folder the manifest's DLL and app are in.
    pub external: Option<PathBuf>,
    /// The DLL's file name, from the registered manifest.
    pub dll_name: Option<String>,
}

impl Installed {
    /// The DLL the package serves the menu from.
    pub fn dll(&self) -> Option<PathBuf> {
        Some(self.external.as_ref()?.join(self.dll_name.as_ref()?))
    }
}

/// What to register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A signed package.
    Msix(PathBuf),
    /// A folder holding `AppxManifest.xml`, registered under Developer Mode.
    Manifest(PathBuf),
}

fn deploy_error(doing: &str, code: HRESULT, text: Option<String>) -> CmdError {
    let hresult = format!("{:#010x}", code.0);
    let why = text
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| windows_core::Error::from(code).message());
    CmdError::new(ErrorCode::Io, format!("{doing}: {}", why.trim()))
        .with_details(serde_json::json!({ "hresult": hresult }))
}

fn win_error(doing: &str, e: &windows_core::Error) -> CmdError {
    deploy_error(doing, e.code(), Some(e.message()))
}

fn no_packages() -> CmdError {
    CmdError::new(
        ErrorCode::UnsupportedOperation,
        "this registry base is a test's, which has no package",
    )
}

/// The registered BeeZip packages for this user: none, or one.
pub fn find(hive: &Hive) -> Result<Vec<Installed>, CmdError> {
    let Some(name) = hive.package_name() else {
        return Ok(Vec::new());
    };
    let doing = "looking for BeeZip's package";
    let pm = PackageManager::new().map_err(|e| win_error(doing, &e))?;
    let mut out = Vec::new();
    for publisher in PUBLISHERS {
        let found = pm
            .FindPackagesByUserSecurityIdNamePublisher(
                &HSTRING::new(),
                &HSTRING::from(name),
                &HSTRING::from(*publisher),
            )
            .map_err(|e| win_error(doing, &e))?;
        for p in found {
            out.push(describe(&p).map_err(|e| win_error(doing, &e))?);
        }
    }
    Ok(out)
}

fn describe(p: &Package) -> windows_core::Result<Installed> {
    let full_name = p.Id()?.FullName()?.to_string();
    let external = p
        .EffectiveExternalPath()
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let dll_name = p
        .InstalledPath()
        .ok()
        .and_then(|dir| std::fs::read_to_string(Path::new(&dir.to_string()).join(MANIFEST)).ok())
        .and_then(|text| manifest_dll(&text));
    Ok(Installed {
        full_name,
        development: p.IsDevelopmentMode().unwrap_or(false),
        external,
        dll_name,
    })
}

pub const MANIFEST: &str = "AppxManifest.xml";

/// The DLL a manifest's COM class names: `Path="…"` on the `com:Class` element.
pub fn manifest_dll(manifest: &str) -> Option<String> {
    let class = manifest.find("<com:Class ")?;
    let rest = &manifest[class..];
    let rest = &rest[..rest.find('>')?];
    let at = rest.find(" Path=\"")? + " Path=\"".len();
    let value = &rest[at..];
    Some(value[..value.find('"')?].to_owned())
}

/// A `file:` URI for a local path, as `PackageManager` takes them.
pub fn file_uri(path: &Path, dir: bool) -> Result<String, CmdError> {
    let url = if dir {
        url::Url::from_directory_path(path)
    } else {
        url::Url::from_file_path(path)
    };
    url.map(String::from)
        .map_err(|()| CmdError::invalid_args(format!("{} isn't an absolute path", path.display())))
}

fn uri(path: &Path, dir: bool, doing: &str) -> Result<Uri, CmdError> {
    Uri::CreateUri(&HSTRING::from(file_uri(path, dir)?)).map_err(|e| win_error(doing, &e))
}

/// Registers the package from `source`, with `external` as its external location. An existing
/// BeeZip package is updated in place, or replaced when it is of the other kind.
pub fn register(hive: &Hive, source: &Source, external: &Path) -> Result<String, CmdError> {
    if hive.package_name().is_none() {
        return Err(no_packages());
    }
    let development = matches!(source, Source::Manifest(_));
    let mut removed = Vec::new();
    for old in find(hive)? {
        let moved = !old
            .external
            .as_deref()
            .is_some_and(|d| super::same_path(d, external));
        if old.development != development || moved {
            remove(hive, &old.full_name)?;
            removed.push(old.full_name);
        }
    }
    let doing = "registering BeeZip's package";
    let pm = PackageManager::new().map_err(|e| win_error(doing, &e))?;
    let location = uri(external, true, doing)?;
    let start = || -> Result<Operation, CmdError> {
        let op = match source {
            Source::Msix(msix) => {
                let options = AddPackageOptions::new().map_err(|e| win_error(doing, &e))?;
                options
                    .SetExternalLocationUri(&location)
                    .and_then(|()| options.SetForceUpdateFromAnyVersion(true))
                    .map_err(|e| win_error(doing, &e))?;
                pm.AddPackageByUriAsync(&uri(msix, false, doing)?, &options)
            }
            Source::Manifest(dir) => {
                let options = RegisterPackageOptions::new().map_err(|e| win_error(doing, &e))?;
                options
                    .SetExternalLocationUri(&location)
                    .and_then(|()| options.SetDeveloperMode(true))
                    .and_then(|()| options.SetForceUpdateFromAnyVersion(true))
                    .map_err(|e| win_error(doing, &e))?;
                pm.RegisterPackageByUriAsync(&uri(&dir.join(MANIFEST), false, doing)?, &options)
            }
        };
        op.map_err(|e| win_error(doing, &e))
    };
    match retry_in_use(doing, &start) {
        // The same version with another manifest: a development package whose DLL name changed
        // (`xtask shell` names each copy anew), or a rebuilt `.msix`. Windows wants the old one
        // gone first.
        Err((code, _)) if code == ALREADY_EXISTS => {
            for old in find(hive)? {
                remove(hive, &old.full_name)?;
                removed.push(old.full_name);
            }
            retry_in_use(doing, &start).map_err(|(_, e)| e)?;
        }
        other => other.map_err(|(_, e)| e)?,
    }
    let now = find(hive)?;
    let full_name = now.first().map(|p| p.full_name.clone()).ok_or_else(|| {
        CmdError::new(
            ErrorCode::Io,
            format!("{doing}: Windows reported success, but no BeeZip package is registered"),
        )
    })?;
    let kind = if development {
        "a development package"
    } else {
        "the signed package"
    };
    removed.dedup();
    let replaced = match removed.as_slice() {
        [] => String::new(),
        [same] if *same == full_name => ", replacing its earlier registration".into(),
        others => format!(", replacing {}", others.join(", ")),
    };
    Ok(format!(
        "registered Windows 11's menu ({kind}, {full_name}) for {}{replaced}",
        external.display()
    ))
}

/// Removes one package by its full name.
pub fn remove(hive: &Hive, full_name: &str) -> Result<(), CmdError> {
    if hive.package_name().is_none() {
        return Err(no_packages());
    }
    let doing = "removing BeeZip's package";
    let pm = PackageManager::new().map_err(|e| win_error(doing, &e))?;
    retry_in_use(doing, &|| {
        pm.RemovePackageAsync(&HSTRING::from(full_name))
            .map_err(|e| win_error(doing, &e))
    })
    .map_err(|(_, e)| e)
}

type Operation = IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress>;
type Failure = (HRESULT, CmdError);

/// Runs a deployment operation, and once more after a pause when the package is in use. A
/// failure carries its code.
fn retry_in_use(
    doing: &str,
    start: &dyn Fn() -> Result<Operation, CmdError>,
) -> Result<(), Failure> {
    let begin = || start().map_err(|e| (HRESULT(0), e));
    match wait(doing, begin()?) {
        Err((code, _)) if code == PACKAGES_IN_USE => {
            std::thread::sleep(IN_USE_PAUSE);
            wait(doing, begin()?).map_err(|(code, e)| {
                if code != PACKAGES_IN_USE {
                    return (code, e);
                }
                let message = format!(
                    "{doing}: it's in use, by Explorer or by a BeeZip window opened from its \
                     menu. Close BeeZip's windows and try again"
                );
                let e = CmdError::new(ErrorCode::Conflict, message)
                    .with_details(serde_json::json!({ "hresult": format!("{:#010x}", code.0) }));
                (code, e)
            })
        }
        other => other,
    }
}

/// Waits for an operation. A failure carries its code, and the deployment's own words.
fn wait(doing: &str, op: Operation) -> Result<(), (HRESULT, CmdError)> {
    let joined = op.join();
    let status = op.Status().unwrap_or(AsyncStatus::Error);
    let result = joined.ok().or_else(|| op.GetResults().ok());
    if status == AsyncStatus::Completed {
        let failed = result
            .as_ref()
            .and_then(|r| r.ExtendedErrorCode().ok())
            .filter(|c| c.is_err());
        let Some(code) = failed else {
            return Ok(());
        };
        let text = result
            .and_then(|r| r.ErrorText().ok())
            .map(|t| t.to_string());
        return Err((code, deploy_error(doing, code, text)));
    }
    let code = op
        .ErrorCode()
        .ok()
        .filter(|c| c.is_err())
        .or_else(|| result.as_ref().and_then(|r| r.ExtendedErrorCode().ok()))
        .unwrap_or(HRESULT(0x8000_4005_u32 as i32));
    let text = result
        .and_then(|r| r.ErrorText().ok())
        .map(|t| t.to_string());
    Err((code, deploy_error(doing, code, text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_names_its_dll() {
        let text = r#"<com:SurrogateServer DisplayName="x">
              <com:Class Id="03CB0FA0-5D6C-4547-9B65-956DE58D1AF2" Path="beezip_shell_0.1.0.dll" ThreadingModel="STA" />"#;
        assert_eq!(
            manifest_dll(text).as_deref(),
            Some("beezip_shell_0.1.0.dll")
        );
        assert_eq!(manifest_dll("<Package />"), None);
    }

    #[test]
    fn the_template_names_its_dll() {
        let template = include_str!("../../../../packaging/windows/sparse/AppxManifest.xml");
        assert_eq!(manifest_dll(template).as_deref(), Some("{{DLL}}"));
    }

    #[test]
    fn file_uris_escape_spaces() {
        assert_eq!(
            file_uri(Path::new(r"C:\Users\A B\BeeZip"), true).unwrap(),
            "file:///C:/Users/A%20B/BeeZip/"
        );
        assert_eq!(
            file_uri(Path::new(r"C:\BeeZip\beezip-sparse.msix"), false).unwrap(),
            "file:///C:/BeeZip/beezip-sparse.msix"
        );
        assert!(file_uri(Path::new("relative"), false).is_err());
    }

    #[test]
    fn a_test_hive_has_no_package() {
        let hive = Hive::test("package");
        assert_eq!(find(&hive).unwrap(), []);
        let err = remove(&hive, "BeeZip_0.1.0.0_neutral__x").unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedOperation);
    }
}
