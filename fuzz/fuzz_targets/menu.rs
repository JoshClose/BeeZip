//! The Explorer menu model (docs/M4.md §10): whatever names a selection has, `menu()` doesn't
//! panic, titles fit, hidden items stay hidden, and a job file's text is read or refused.

#![no_main]

use beezip_menu::{
    Item, JobRequest, Selected, Settings, TITLE_MAX, archive_stem, is_archive, menu, title,
    volume_key,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // The first byte picks the hidden items; each line after it is one selected item, a
    // folder if it starts with `/`, without a path if it starts with `?`.
    let hidden: Vec<Item> = Item::ALL
        .into_iter()
        .enumerate()
        .filter(|(i, _)| data.first().is_some_and(|b| b & (1 << (i % 8)) != 0))
        .map(|(_, item)| item)
        .collect();
    let selection: Vec<Selected> = text
        .lines()
        .skip(1)
        .take(64)
        .map(|line| match line.as_bytes().first() {
            Some(b'?') => Selected { path: None, folder: false },
            Some(b'/') => Selected::folder(format!(r"C:\dir\{}", &line[1..])),
            _ => Selected::file(format!(r"C:\dir\{line}")),
        })
        .collect();
    let settings = Settings { hidden };
    let entries = menu(&selection, &settings);
    for e in &entries {
        assert!(e.title.chars().count() <= TITLE_MAX, "{:?}", e.title);
        assert!(!settings.hidden.contains(&e.item));
    }
    assert!(entries.iter().filter(|e| e.separator_before).count() <= 1);
    for item in Item::ALL {
        assert!(title(item, &selection).chars().count() <= TITLE_MAX);
    }
    for line in text.lines().take(64) {
        assert!(!archive_stem(line).is_empty());
        let _ = is_archive(line);
        let _ = volume_key(line);
    }
    if let Ok(req) = JobRequest::parse(&text) {
        let again = JobRequest::parse(&req.to_json().expect("parsed paths are Unicode"));
        assert_eq!(again.as_ref(), Ok(&req));
    }
});
