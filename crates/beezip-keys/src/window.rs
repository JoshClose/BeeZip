//! The window Windows' own dialogs belong to when a command runs in a terminal
//! ([`crate::console_window`]). The choice is made here, over [`Desktop`]'s answers, so the tests
//! need no windows; `webauthn::ffi` asks Windows.

/// What [`dialog_window`] asks about the desktop's windows. Window handles are HWNDs.
pub(crate) trait Desktop {
    /// `GetConsoleWindow`: the window of this process's console, or `None` without one.
    fn console(&self) -> Option<isize>;
    /// On the screen: `IsWindowVisible`, and a rectangle with some size. Windows Terminal's
    /// pseudo console window is "visible" at 0,0 with no size (wave 2), which doesn't count.
    fn visible(&self, window: isize) -> bool;
    /// `GetAncestor(GA_ROOTOWNER)`: the top of the window's chain of parents and owners, which
    /// is the window itself when it has neither.
    fn root_owner(&self, window: isize) -> Option<isize>;
    /// `GetForegroundWindow`.
    fn foreground(&self) -> Option<isize>;
}

/// The window a dialog should come up over for a process in a console:
/// - **conhost:** the console window, the terminal's own visible window;
/// - **Windows Terminal:** the console window is ConPTY's pseudo console window: marked visible,
///   but with no size, at 0,0, so a dialog it owns comes up in the screen's corner. The
///   terminal's window owns it: that one;
/// - **VS Code's terminal and others:** an invisible console window with no visible owner. The
///   window in front, where the command was just typed.
///
/// `None` without a console, or when nothing better than an invisible window is found: Windows'
/// dialogs then come up over the window in front when they show.
pub(crate) fn dialog_window(desktop: &impl Desktop) -> Option<isize> {
    let console = desktop.console()?;
    if desktop.visible(console) {
        return Some(console);
    }
    if let Some(owner) = desktop
        .root_owner(console)
        .filter(|&owner| owner != console && desktop.visible(owner))
    {
        return Some(owner);
    }
    desktop.foreground().filter(|&front| front != console)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const CONSOLE: isize = 0x10;
    const TERMINAL: isize = 0x20;
    const EDITOR: isize = 0x30;

    /// A made-up desktop: the console window, which windows are visible, who owns whom, and
    /// the window in front.
    #[derive(Default)]
    struct Fake {
        console: Option<isize>,
        visible: Vec<isize>,
        owners: HashMap<isize, isize>,
        foreground: Option<isize>,
    }

    impl Desktop for Fake {
        fn console(&self) -> Option<isize> {
            self.console
        }
        fn visible(&self, window: isize) -> bool {
            self.visible.contains(&window)
        }
        fn root_owner(&self, window: isize) -> Option<isize> {
            let mut top = window;
            while let Some(&owner) = self.owners.get(&top) {
                top = owner;
            }
            Some(top)
        }
        fn foreground(&self) -> Option<isize> {
            self.foreground
        }
    }

    #[test]
    fn conhost_keeps_its_console_window() {
        let desktop = Fake {
            console: Some(CONSOLE),
            visible: vec![CONSOLE, EDITOR],
            foreground: Some(EDITOR),
            ..Fake::default()
        };
        assert_eq!(dialog_window(&desktop), Some(CONSOLE));
    }

    #[test]
    fn windows_terminal_gives_the_window_that_owns_its_pseudo_console() {
        let desktop = Fake {
            console: Some(CONSOLE),
            visible: vec![TERMINAL, EDITOR],
            owners: HashMap::from([(CONSOLE, TERMINAL)]),
            foreground: Some(EDITOR),
        };
        assert_eq!(dialog_window(&desktop), Some(TERMINAL));

        // Owned through another window, as GA_ROOTOWNER walks the chain.
        let desktop = Fake {
            owners: HashMap::from([(CONSOLE, 0x15), (0x15, TERMINAL)]),
            ..desktop
        };
        assert_eq!(dialog_window(&desktop), Some(TERMINAL));
    }

    #[test]
    fn a_hidden_console_without_a_visible_owner_gives_the_window_in_front() {
        // VS Code's terminal: nothing owns the pseudo console.
        let alone = Fake {
            console: Some(CONSOLE),
            visible: vec![EDITOR],
            foreground: Some(EDITOR),
            ..Fake::default()
        };
        assert_eq!(dialog_window(&alone), Some(EDITOR));

        // An owner that is itself hidden is no better.
        let hidden_owner = Fake {
            owners: HashMap::from([(CONSOLE, TERMINAL)]),
            ..alone
        };
        assert_eq!(dialog_window(&hidden_owner), Some(EDITOR));

        // Nothing in front: none, rather than the hidden window in the screen's corner.
        let nothing = Fake {
            foreground: None,
            ..hidden_owner
        };
        assert_eq!(dialog_window(&nothing), None);
        let itself = Fake {
            foreground: Some(CONSOLE),
            ..nothing
        };
        assert_eq!(dialog_window(&itself), None);
    }

    #[test]
    fn no_console_gives_none() {
        let desktop = Fake {
            visible: vec![EDITOR],
            foreground: Some(EDITOR),
            ..Fake::default()
        };
        assert_eq!(dialog_window(&desktop), None);
    }
}
