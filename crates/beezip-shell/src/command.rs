//! The `IExplorerCommand`s (docs/M4.md §4.1): the root "BeeZip", which cascades, and one command
//! per item. Both registrations serve the same objects: the classic menu by `ExplorerCommandHandler`
//! and the Windows 11 menu from the package's surrogate.
//!
//! Explorer builds the whole cascade before it shows anything (§16, item 7): the root's
//! `GetState` with the selection, its title and flags, then every subcommand's flags, title and
//! state. `EnumSubCommands` has no selection, so the root keeps the entries its last `GetState`
//! computed and hands them to the subcommands; a subcommand given the selection itself recomputes
//! from it.

use std::cell::{Cell, RefCell};

use beezip_menu::{Entry, Item, Selected, clsid};
use windows::Win32::Foundation::{E_INVALIDARG, E_NOTIMPL, E_POINTER, S_FALSE, S_OK};
use windows::Win32::System::Com::{CoTaskMemFree, IBindCtx};
use windows::Win32::System::SystemServices::{SFGAO_FOLDER, SFGAO_STREAM};
use windows::Win32::UI::Shell::{
    ECF_DEFAULT, ECF_HASSUBCOMMANDS, ECF_SEPARATORBEFORE, ECS_ENABLED, ECS_HIDDEN,
    IEnumExplorerCommand, IEnumExplorerCommand_Impl, IExplorerCommand, IExplorerCommand_Impl,
    IShellItemArray, SHStrDupW, SIGDN_FILESYSPATH,
};
use windows_core::{BOOL, GUID, HRESULT, HSTRING, PWSTR, Ref, Result, implement};

use crate::guard::{Live, forced_panic, guard, guard_hr};
use crate::settings::Settings;
use crate::{invoke, log};

/// The root's title in both menus.
pub const ROOT_TITLE: &str = "BeeZip";

/// Which registration made the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    Classic,
    Modern,
}

impl Context {
    fn clsid(self) -> u128 {
        match self {
            Self::Classic => clsid::CLASSIC_ROOT,
            Self::Modern => clsid::MODERN_ROOT,
        }
    }
}

/// The items Explorer selected: each one's file-system path, if it has one, and whether it is a
/// folder. A zip file is a folder to the shell, but also a stream; only a real folder counts.
pub fn selection(array: Option<&IShellItemArray>) -> Result<Vec<Selected>> {
    let Some(array) = array else {
        return Ok(Vec::new());
    };
    // SAFETY: `array` is a live interface Explorer passed for the length of this call.
    let count = unsafe { array.GetCount() }?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        // SAFETY: as above; `i` is below the count it reported.
        let item = unsafe { array.GetItemAt(i) }?;
        // SAFETY: `item` is live; `GetDisplayName` hands back a CoTaskMemAlloc'd string, read
        // here and freed once.
        let path = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }
            .ok()
            .and_then(|p| {
                let s = unsafe { p.to_string() }.ok();
                unsafe { CoTaskMemFree(Some(p.0.cast_const().cast())) };
                s
            });
        // SAFETY: `item` is live.
        let attributes =
            unsafe { item.GetAttributes(SFGAO_FOLDER | SFGAO_STREAM) }.unwrap_or_default();
        let folder = attributes.contains(SFGAO_FOLDER) && !attributes.contains(SFGAO_STREAM);
        out.push(Selected { path, folder });
    }
    Ok(out)
}

/// A string Explorer frees with `CoTaskMemFree`.
fn co_string(s: &str) -> Result<PWSTR> {
    // SAFETY: the HSTRING outlives the call, and SHStrDupW copies it.
    unsafe { SHStrDupW(&HSTRING::from(s)) }
}

/// `"<app>,0"`: BeeZip's icon, when the settings name the app.
fn app_icon(settings: &Settings) -> Result<PWSTR> {
    match &settings.app {
        Some(app) => co_string(&format!("{},0", app.display())),
        None => Err(E_NOTIMPL.into()),
    }
}

/// The root: "BeeZip >".
#[implement(IExplorerCommand)]
pub struct Root {
    context: Context,
    settings: Settings,
    /// The entries for the last selection `GetTitle` or `GetState` was given.
    entries: RefCell<Option<Vec<Entry>>>,
    _live: Live,
}

impl Root {
    pub fn new(context: Context, settings: Settings) -> Self {
        Self {
            context,
            settings,
            entries: RefCell::new(None),
            _live: Live::new(),
        }
    }

    /// The entries for the selection, kept for `EnumSubCommands`, which has none. Windows 10's
    /// Explorer enumerates on an object that only had `GetTitle`, and asks each subcommand for
    /// its flags (the separator) before anything else, so both methods compute them.
    fn entries_for(&self, array: &IShellItemArray) -> Result<Vec<Entry>> {
        let entries = beezip_menu::menu(&selection(Some(array))?, &self.settings.menu());
        *self.entries.borrow_mut() = Some(entries.clone());
        Ok(entries)
    }
}

impl IExplorerCommand_Impl for Root_Impl {
    fn GetTitle(&self, array: Ref<IShellItemArray>) -> Result<PWSTR> {
        guard("Root.GetTitle", || {
            forced_panic("GetTitle", &self.settings);
            if let Some(array) = array.as_ref() {
                let n = self.entries_for(array)?.len();
                log::line(|| format!("Root.GetTitle {:?} -> {n} entries", self.context));
            }
            co_string(ROOT_TITLE)
        })
    }

    fn GetIcon(&self, _array: Ref<IShellItemArray>) -> Result<PWSTR> {
        guard("Root.GetIcon", || app_icon(&self.settings))
    }

    fn GetToolTip(&self, _array: Ref<IShellItemArray>) -> Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetCanonicalName(&self) -> Result<GUID> {
        Ok(GUID::from_u128(self.context.clsid()))
    }

    fn GetState(&self, array: Ref<IShellItemArray>, slow: BOOL) -> Result<u32> {
        guard("Root.GetState", || {
            forced_panic("GetState", &self.settings);
            let n = match array.as_ref() {
                Some(array) => self.entries_for(array)?.len(),
                None => 0,
            };
            log::line(|| {
                format!(
                    "Root.GetState {:?} slow={} -> {n} entries",
                    self.context,
                    slow.as_bool()
                )
            });
            Ok(if n == 0 { ECS_HIDDEN } else { ECS_ENABLED }.0 as u32)
        })
    }

    fn Invoke(&self, _array: Ref<IShellItemArray>, _bind: Ref<IBindCtx>) -> Result<()> {
        Err(E_NOTIMPL.into())
    }

    fn GetFlags(&self) -> Result<u32> {
        Ok(ECF_HASSUBCOMMANDS.0 as u32)
    }

    fn EnumSubCommands(&self) -> Result<IEnumExplorerCommand> {
        guard("Root.EnumSubCommands", || {
            // Given no selection yet, offer every item the settings show, and let each
            // subcommand's own GetState hide what the selection doesn't get.
            let entries = self.entries.borrow().clone().unwrap_or_else(|| {
                Item::ALL
                    .into_iter()
                    .filter(|i| !self.settings.hidden.contains(i))
                    .map(|item| Entry {
                        item,
                        title: beezip_menu::title(item, &[]),
                        separator_before: false,
                    })
                    .collect()
            });
            log::line(|| format!("Root.EnumSubCommands -> {}", entries.len()));
            let commands = entries
                .into_iter()
                .map(|e| ItemCommand::sub(e, self.settings.clone()).into())
                .collect();
            Ok(Commands::new(commands).into())
        })
    }
}

/// One item: a subcommand of the root, or a top-level verb when the classic menu isn't cascaded.
#[implement(IExplorerCommand)]
pub struct ItemCommand {
    item: Item,
    /// The title and separator the root computed, for calls that come without a selection.
    entry: Option<Entry>,
    /// A top-level verb, which shows BeeZip's icon.
    top_level: bool,
    settings: Settings,
    _live: Live,
}

impl ItemCommand {
    pub fn sub(entry: Entry, settings: Settings) -> Self {
        Self {
            item: entry.item,
            entry: Some(entry),
            top_level: false,
            settings,
            _live: Live::new(),
        }
    }

    pub fn top_level(item: Item, settings: Settings) -> Self {
        Self {
            item,
            entry: None,
            top_level: true,
            settings,
            _live: Live::new(),
        }
    }
}

impl IExplorerCommand_Impl for ItemCommand_Impl {
    fn GetTitle(&self, array: Ref<IShellItemArray>) -> Result<PWSTR> {
        guard("Item.GetTitle", || {
            let title = match (array.as_ref(), &self.entry) {
                (None, Some(entry)) => entry.title.clone(),
                (array, _) => beezip_menu::title(self.item, &selection(array)?),
            };
            log::line(|| {
                format!(
                    "Item.GetTitle {} array={} -> {title:?}",
                    self.item.id(),
                    !array.is_null()
                )
            });
            co_string(&title)
        })
    }

    fn GetIcon(&self, _array: Ref<IShellItemArray>) -> Result<PWSTR> {
        guard("Item.GetIcon", || {
            if self.top_level {
                app_icon(&self.settings)
            } else {
                Err(E_NOTIMPL.into())
            }
        })
    }

    fn GetToolTip(&self, _array: Ref<IShellItemArray>) -> Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetCanonicalName(&self) -> Result<GUID> {
        Ok(GUID::from_u128(self.item.clsid()))
    }

    fn GetState(&self, array: Ref<IShellItemArray>, _slow: BOOL) -> Result<u32> {
        guard("Item.GetState", || {
            let visible = match array.as_ref() {
                // The root already left out what its selection doesn't get.
                None => true,
                Some(array) => beezip_menu::menu(&selection(Some(array))?, &self.settings.menu())
                    .iter()
                    .any(|e| e.item == self.item),
            };
            log::line(|| {
                format!(
                    "Item.GetState {} array={} -> {visible}",
                    self.item.id(),
                    !array.is_null()
                )
            });
            Ok(if visible { ECS_ENABLED } else { ECS_HIDDEN }.0 as u32)
        })
    }

    fn Invoke(&self, array: Ref<IShellItemArray>, _bind: Ref<IBindCtx>) -> Result<()> {
        guard("Item.Invoke", || {
            forced_panic("Invoke", &self.settings);
            let selection = selection(array.as_ref())?;
            let paths: Option<Vec<_>> = selection.into_iter().map(|s| s.path).collect();
            let paths = paths.filter(|p| !p.is_empty()).ok_or(E_INVALIDARG)?;
            log::line(|| format!("Item.Invoke {} n={}", self.item.id(), paths.len()));
            invoke::run(
                self.item,
                paths.into_iter().map(Into::into).collect(),
                &self.settings,
            )
            .inspect_err(|e| log::line(|| format!("Item.Invoke failed: {e}")))
        })
    }

    fn GetFlags(&self) -> Result<u32> {
        let separator = self.entry.as_ref().is_some_and(|e| e.separator_before);
        log::line(|| format!("Item.GetFlags {} -> separator={separator}", self.item.id()));
        Ok(if separator {
            ECF_SEPARATORBEFORE
        } else {
            ECF_DEFAULT
        }
        .0 as u32)
    }

    fn EnumSubCommands(&self) -> Result<IEnumExplorerCommand> {
        Err(E_NOTIMPL.into())
    }
}

/// The root's subcommands, handed out one `Next` at a time, as Explorer asks for them.
#[implement(IEnumExplorerCommand)]
pub struct Commands {
    commands: Vec<IExplorerCommand>,
    next: Cell<usize>,
    _live: Live,
}

impl Commands {
    fn new(commands: Vec<IExplorerCommand>) -> Self {
        Self {
            commands,
            next: Cell::new(0),
            _live: Live::new(),
        }
    }
}

impl IEnumExplorerCommand_Impl for Commands_Impl {
    fn Next(&self, celt: u32, out: *mut Option<IExplorerCommand>, fetched: *mut u32) -> HRESULT {
        guard_hr("Commands.Next", || {
            if out.is_null() {
                return E_POINTER;
            }
            let start = self.next.get();
            let n = (celt as usize).min(self.commands.len().saturating_sub(start));
            for (i, command) in self.commands[start..start + n].iter().enumerate() {
                // SAFETY: the caller's array holds `celt` slots, and `i < n <= celt`. A slot
                // is uninitialised, so it is written without dropping what was there.
                unsafe { out.add(i).write(Some(command.clone())) };
            }
            self.next.set(start + n);
            if !fetched.is_null() {
                // SAFETY: a non-null `fetched` points at the caller's count.
                unsafe { fetched.write(n as u32) };
            }
            if n == celt as usize { S_OK } else { S_FALSE }
        })
    }

    fn Skip(&self, celt: u32) -> Result<()> {
        let next = self.next.get().saturating_add(celt as usize);
        self.next.set(next.min(self.commands.len()));
        Ok(())
    }

    fn Reset(&self) -> Result<()> {
        self.next.set(0);
        Ok(())
    }

    fn Clone(&self) -> Result<IEnumExplorerCommand> {
        let copy = Commands::new(self.commands.clone());
        copy.next.set(self.next.get());
        Ok(copy.into())
    }
}
