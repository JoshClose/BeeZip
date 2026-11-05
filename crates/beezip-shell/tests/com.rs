//! The DLL through COM's own entry points, with nothing registered (docs/M4.md §10): it is
//! loaded with `LoadLibraryW`, its class factories come from `DllGetClassObject`, and the
//! selections are real shell items. Settings come from a test key (`BEEZIP_SHELL_KEY`, which
//! debug builds read), and a click starts `examples/stub_app`.
//!
//! The tests share one DLL and one settings key, so they take turns.
#![cfg(windows)]
#![allow(unsafe_code, clippy::unwrap_used)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use beezip_menu::{Item, clsid};
use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, E_UNEXPECTED, S_OK};
use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemFree, IClassFactory,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Shell::Common::ITEMIDLIST;
use windows::Win32::UI::Shell::{
    ECF_HASSUBCOMMANDS, ECF_SEPARATORBEFORE, ECS_ENABLED, ECS_HIDDEN, IExplorerCommand, ILFree,
    IShellItemArray, SHCreateShellItemArrayFromIDLists, SHParseDisplayName,
};
use windows_core::{GUID, HRESULT, HSTRING, IUnknown, Interface, PWSTR, s};
use windows_registry::CURRENT_USER;

type GetClassObject =
    unsafe extern "system" fn(*const GUID, *const GUID, *mut *mut c_void) -> HRESULT;
type CanUnloadNow = unsafe extern "system" fn() -> HRESULT;
/// What `GetProcAddress` hands back.
type Farproc = unsafe extern "system" fn() -> isize;

struct Dll {
    get_class_object: GetClassObject,
    can_unload_now: CanUnloadNow,
    key: String,
    stub_out: PathBuf,
    /// The selections' files: `target/<profile>/com-test`, made afresh for each run.
    files: PathBuf,
}

/// `target/<profile>`, where cargo put the DLL and the examples.
fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

fn dll() -> &'static Dll {
    static DLL: OnceLock<Dll> = OnceLock::new();
    DLL.get_or_init(|| {
        let key = format!(r"Software\BeeZip-test-com-{}", std::process::id());
        let base = target_dir().join("com-test");
        let _ = std::fs::remove_dir_all(&base);
        let files = base.join("files");
        let stub_out = base.join("stub");
        std::fs::create_dir_all(&files).unwrap();
        std::fs::create_dir_all(&stub_out).unwrap();
        // SAFETY: set once, before the DLL or the stub reads either; the other tests are
        // waiting on this OnceLock and read no environment.
        unsafe {
            std::env::set_var("BEEZIP_SHELL_KEY", &key);
            std::env::set_var("BEEZIP_STUB_OUT", &stub_out);
        }
        // `cargo test` leaves the DLL in deps/, beside this test; `cargo build` copies it up.
        let deps = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("beezip_shell.dll");
        let path = if deps.is_file() {
            deps
        } else {
            target_dir().join("beezip_shell.dll")
        };
        // SAFETY: loading our own DLL, which runs no code at load.
        let module = unsafe { LoadLibraryW(&HSTRING::from(path.as_os_str())) }
            .unwrap_or_else(|e| panic!("loading {}: {e}", path.display()));
        // SAFETY: the exports have exactly these signatures (src/lib.rs).
        let (get, can) = unsafe {
            (
                GetProcAddress(module, s!("DllGetClassObject")).expect("DllGetClassObject"),
                GetProcAddress(module, s!("DllCanUnloadNow")).expect("DllCanUnloadNow"),
            )
        };
        for name in ["a.zip", "b.7z", "notes.txt", "a.7z.001", "a.7z.002"] {
            std::fs::write(files.join(name), "x").unwrap();
        }
        std::fs::create_dir(files.join("photos")).unwrap();
        Dll {
            // SAFETY: as above.
            get_class_object: unsafe { std::mem::transmute::<Farproc, GetClassObject>(get) },
            can_unload_now: unsafe { std::mem::transmute::<Farproc, CanUnloadNow>(can) },
            key,
            stub_out,
            files,
        }
    })
}

/// One test's turn: the others wait, and its settings key goes when it ends.
struct Turn(#[allow(dead_code)] MutexGuard<'static, ()>);

impl Drop for Turn {
    fn drop(&mut self) {
        let _ = CURRENT_USER.remove_tree(&dll().key);
    }
}

/// One test at a time, with COM up on its thread and an empty settings key.
fn turn() -> Turn {
    static TURN: Mutex<()> = Mutex::new(());
    let guard = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    // SAFETY: once per test thread; S_FALSE (already initialised) is fine.
    let _ = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let _ = CURRENT_USER.remove_tree(&dll().key);
    CURRENT_USER.create(&dll().key).unwrap();
    Turn(guard)
}

fn settings() -> windows_registry::Key {
    CURRENT_USER.create(&dll().key).unwrap()
}

fn factory(clsid: u128) -> Result<IClassFactory, HRESULT> {
    let mut out = std::ptr::null_mut();
    // SAFETY: the export's contract; `out` receives an IClassFactory on success.
    let hr =
        unsafe { (dll().get_class_object)(&GUID::from_u128(clsid), &IClassFactory::IID, &mut out) };
    if hr.is_err() {
        return Err(hr);
    }
    // SAFETY: on success `out` is an owned IClassFactory.
    Ok(unsafe { IClassFactory::from_raw(out) })
}

fn command(clsid: u128) -> IExplorerCommand {
    // SAFETY: plain COM call.
    unsafe { factory(clsid).unwrap().CreateInstance(None::<&IUnknown>) }.unwrap()
}

fn path(name: &str) -> PathBuf {
    dll().files.join(name)
}

/// The selection Explorer would pass for these files.
fn items(names: &[&str]) -> IShellItemArray {
    let mut pidls: Vec<*mut ITEMIDLIST> = Vec::new();
    for name in names {
        let mut pidl = std::ptr::null_mut();
        // SAFETY: `pidl` receives an ID list freed below.
        unsafe {
            SHParseDisplayName(
                &HSTRING::from(path(name).as_os_str()),
                None,
                &mut pidl,
                0,
                None,
            )
        }
        .unwrap();
        pidls.push(pidl);
    }
    let borrowed: Vec<*const ITEMIDLIST> = pidls.iter().map(|p| p.cast_const()).collect();
    // SAFETY: live ID lists, which the array copies.
    let array = unsafe { SHCreateShellItemArrayFromIDLists(&borrowed) }.unwrap();
    for p in pidls {
        // SAFETY: each is freed once.
        unsafe { ILFree(Some(p.cast_const())) };
    }
    array
}

fn text(p: PWSTR) -> String {
    // SAFETY: a CoTaskMemAlloc'd string from the DLL, read and freed once.
    let s = unsafe { p.to_string() }.unwrap();
    unsafe { CoTaskMemFree(Some(p.0.cast_const().cast())) };
    s
}

/// The subcommands as Explorer reads them: `(title, separator before, visible)`.
fn subcommands(root: &IExplorerCommand, array: &IShellItemArray) -> Vec<(String, bool, bool)> {
    // SAFETY: plain COM calls on live objects.
    let all = unsafe { root.EnumSubCommands() }.unwrap();
    let mut out = Vec::new();
    loop {
        let mut one = [None];
        let mut fetched = 0;
        // SAFETY: as above; one slot.
        let hr = unsafe { all.Next(&mut one, Some(&mut fetched)) };
        let Some(cmd) = one[0].take() else { break };
        assert_eq!(fetched, 1);
        let flags = unsafe { cmd.GetFlags() }.unwrap();
        let title = text(unsafe { cmd.GetTitle(array) }.unwrap());
        let state = unsafe { cmd.GetState(array, true) }.unwrap();
        out.push((
            title,
            flags & ECF_SEPARATORBEFORE.0 as u32 != 0,
            state == ECS_ENABLED.0 as u32,
        ));
        if hr != S_OK {
            break;
        }
    }
    out
}

/// The visible titles, with `-----` for a separator.
fn shown(subs: &[(String, bool, bool)]) -> Vec<String> {
    let mut out = Vec::new();
    for (title, sep, _) in subs.iter().filter(|s| s.2) {
        if *sep {
            out.push("-----".to_owned());
        }
        out.push(title.clone());
    }
    out
}

fn can_unload() -> bool {
    // SAFETY: the export's contract.
    let hr = unsafe { (dll().can_unload_now)() };
    hr == S_OK
}

#[test]
fn the_root_cascades_for_an_archive() {
    let _turn = turn();
    {
        let root = command(clsid::CLASSIC_ROOT);
        let array = items(&["a.zip"]);
        // SAFETY: plain COM calls.
        unsafe {
            assert_eq!(root.GetFlags().unwrap(), ECF_HASSUBCOMMANDS.0 as u32);
            assert_eq!(root.GetState(&array, true).unwrap(), ECS_ENABLED.0 as u32);
            assert_eq!(text(root.GetTitle(&array).unwrap()), "BeeZip");
            assert_eq!(
                root.GetCanonicalName().unwrap(),
                GUID::from_u128(clsid::CLASSIC_ROOT)
            );
        }
        assert_eq!(
            shown(&subcommands(&root, &array)),
            [
                "Open with BeeZip",
                "Extract here",
                "Extract to \"a\\\"",
                "Extract to…",
                "Test archive",
                "-----",
                "Add to \"a.zip\"",
                "Add to \"a.7z\"",
                "Add to \"a.tar.zst\"",
                "Compress to…",
            ]
        );
    }
    assert!(can_unload(), "every object was released");
}

#[test]
fn selections_get_their_items() {
    let _turn = turn();
    {
        let root = command(clsid::CLASSIC_ROOT);
        let check = |names: &[&str], expected: &[&str]| {
            let array = items(names);
            // SAFETY: plain COM call. Windows 10's Explorer asks GetTitle, not GetState, on
            // the object it enumerates.
            text(unsafe { root.GetTitle(&array) }.unwrap());
            assert_eq!(shown(&subcommands(&root, &array)), expected, "{names:?}");
        };
        check(
            &["notes.txt"],
            &[
                "Add to \"notes.zip\"",
                "Add to \"notes.7z\"",
                "Add to \"notes.tar.zst\"",
                "Compress to…",
            ],
        );
        check(
            &["photos"],
            &[
                "Add to \"photos.zip\"",
                "Add to \"photos.7z\"",
                "Add to \"photos.tar.zst\"",
                "Compress to…",
            ],
        );
        let folder = "files";
        let several = [
            "Open with BeeZip".to_owned(),
            "Extract here".into(),
            "Extract each to its own folder".into(),
            "Test archives".into(),
            "-----".into(),
            format!("Add to \"{folder}.zip\""),
            format!("Add to \"{folder}.7z\""),
            format!("Add to \"{folder}.tar.zst\""),
            "Compress to…".into(),
        ];
        let several: Vec<&str> = several.iter().map(String::as_str).collect();
        check(&["a.zip", "b.7z"], &several);
        let set = &["a.7z.001", "a.7z.002"];
        let array = items(set);
        text(unsafe { root.GetTitle(&array) }.unwrap());
        let titles = shown(&subcommands(&root, &array));
        assert!(
            titles.contains(&"Extract to \"a\\\"".to_owned()),
            "{titles:?}"
        );
        assert!(titles.contains(&"Test archive".to_owned()), "{titles:?}");
    }
    assert!(can_unload());
}

#[test]
fn enumerating_first_still_hides_what_a_selection_lacks() {
    let _turn = turn();
    {
        // A fresh root, asked for its subcommands before any selection: every item comes
        // back, and each one's own GetState hides what a .txt doesn't get.
        let root = command(clsid::CLASSIC_ROOT);
        let array = items(&["notes.txt"]);
        let subs = subcommands(&root, &array);
        assert_eq!(subs.len(), Item::ALL.len());
        assert_eq!(subs.iter().filter(|s| s.2).count(), 4);
    }
    assert!(can_unload());
}

#[test]
fn hidden_items_stay_out() {
    let _turn = turn();
    settings()
        .set_multi_string("Hidden", &["test", "add-tar-zst"])
        .unwrap();
    {
        let root = command(clsid::CLASSIC_ROOT);
        let array = items(&["a.zip"]);
        text(unsafe { root.GetTitle(&array) }.unwrap());
        let titles = shown(&subcommands(&root, &array));
        assert!(!titles.iter().any(|t| t == "Test archive"), "{titles:?}");
        assert!(
            !titles.iter().any(|t| t.ends_with(".tar.zst\"")),
            "{titles:?}"
        );
        assert_eq!(titles.len(), 8, "{titles:?}");
        // Everything hidden: the root itself goes.
        let ids: Vec<&str> = Item::ALL.iter().map(|i| i.id()).collect();
        settings().set_multi_string("Hidden", &ids).unwrap();
        let root = command(clsid::CLASSIC_ROOT);
        assert_eq!(
            unsafe { root.GetState(&array, true) }.unwrap(),
            ECS_HIDDEN.0 as u32
        );
    }
    assert!(can_unload());
}

#[test]
fn an_item_on_its_own_is_a_top_level_verb() {
    let _turn = turn();
    {
        let add = command(Item::AddZip.clsid());
        let open = command(Item::Open.clsid());
        let txt = items(&["notes.txt"]);
        unsafe {
            assert_eq!(text(add.GetTitle(&txt).unwrap()), "Add to \"notes.zip\"");
            assert_eq!(add.GetState(&txt, true).unwrap(), ECS_ENABLED.0 as u32);
            assert_eq!(open.GetState(&txt, true).unwrap(), ECS_HIDDEN.0 as u32);
            assert!(add.EnumSubCommands().is_err());
        }
    }
    assert!(can_unload());
}

#[test]
fn unknown_classes_are_refused() {
    let _turn = turn();
    assert_eq!(factory(0x1234).unwrap_err(), CLASS_E_CLASSNOTAVAILABLE);
    assert!(can_unload());
}

#[test]
fn a_panic_comes_back_as_e_unexpected() {
    let _turn = turn();
    settings().set_string("Panic", "GetTitle").unwrap();
    {
        let root = command(clsid::CLASSIC_ROOT);
        let array = items(&["a.zip"]);
        let err = unsafe { root.GetTitle(&array) }.unwrap_err();
        assert_eq!(err.code(), E_UNEXPECTED);
    }
    assert!(can_unload());
}

/// Waits for the stub's record of a launch.
fn stub_record(dir: &Path) -> serde_json::Value {
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end {
        let found = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "json"));
        if let Some(p) = found {
            let text = std::fs::read_to_string(&p).unwrap();
            std::fs::remove_file(&p).unwrap();
            return serde_json::from_str(&text).unwrap();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the stub didn't start");
}

#[test]
fn a_click_writes_the_request_and_starts_the_app() {
    let _turn = turn();
    let stub = target_dir().join("examples").join("stub_app.exe");
    assert!(stub.is_file(), "{} isn't built", stub.display());
    settings()
        .set_string("App", stub.to_string_lossy())
        .unwrap();
    {
        let test = command(Item::Test.clsid());
        let array = items(&["a.zip", "b.7z"]);
        unsafe { test.Invoke(&array, None) }.unwrap();
    }
    let record = stub_record(&dll().stub_out);
    let args = record["args"].as_array().unwrap();
    assert_eq!(args[0], "--job");
    let file = PathBuf::from(args[1].as_str().unwrap());
    assert_eq!(
        file.parent().unwrap(),
        std::env::temp_dir().join("BeeZip").join("jobs")
    );
    assert!(
        !file.exists(),
        "the stub deletes the request, as BeeZip does"
    );
    let request = beezip_menu::JobRequest::parse(record["request"].as_str().unwrap()).unwrap();
    assert_eq!(request.item, Item::Test);
    assert_eq!(request.paths, [path("a.zip"), path("b.7z")]);
    assert!(can_unload());
}
