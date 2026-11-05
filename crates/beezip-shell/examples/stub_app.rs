//! Stands in for `BeeZip.exe` when tests and manual checks click the menu (docs/M4.md §10). It
//! records its arguments and the job request it was given, then deletes the request as BeeZip
//! would: `{ "args": [...], "request": "<the file's text>" }` goes to `stub_app-<pid>.json` in
//! `BEEZIP_STUB_OUT`, or beside the executable.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = match args.as_slice() {
        [flag, file] if flag == "--job" => {
            let text = std::fs::read_to_string(file).ok();
            let _ = std::fs::remove_file(file);
            text
        }
        _ => None,
    };
    let dir = std::env::var_os("BEEZIP_STUB_OUT")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_exe().ok()?.parent().map(Into::into))
        .unwrap_or_default();
    let out = serde_json::json!({ "args": args, "request": request });
    let path = dir.join(format!("stub_app-{}.json", std::process::id()));
    // Written under another name first, so a reader never sees half a file.
    let partial = path.with_extension("partial");
    if std::fs::write(&partial, out.to_string()).is_ok() {
        let _ = std::fs::rename(&partial, &path);
    }
}
