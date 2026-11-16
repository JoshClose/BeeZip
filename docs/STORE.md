# Microsoft Store: having Microsoft sign BeeZip

Researched 2026-11-14 while Azure Artifact Signing's identity check for Close Consulting, Inc was
pending (docs/M6.md §9.2, the release runbook).

- **2026-11-14:** wait for Artifact Signing; nothing here planned yet.
- **2026-11-16:** the Partner Center company account is set up (Close Consulting, Inc, verified
  through its D-U-N-S number). New direction:
  - **the Store gets an MSIX** that Microsoft signs, built now;
  - **the Artifact-signed NSIS setup comes later**, for GitHub and winget, outside the Store.

  The two don't depend on each other. The MSIX route below applies. The EXE route is kept for
  reference only, since the Store name goes to the MSIX product.
- **2026-11-16, later:** the spikes passed (below). "BeeZip" is reserved as an MSIX product
  (Store ID 9P9HHSVMM3M3; its identity is in docs/M12.md). The plan, docs/M12.md, waits for
  approval.

## Who signs what

- **MSIX package submitted to the Store:** Microsoft re-signs it after certification. Signing is
  free and there's no certificate to buy or renew, and Store installs show no SmartScreen warning.
- **MSI or EXE installer submitted to the Store** (what Tauri's Store guide describes, and what
  BeeZip's NSIS `setup.exe` would be): Microsoft does **not** sign it. The installer and every
  program in it must be signed with a certificate that chains to a CA in Microsoft's Trusted Root
  Program, the same kind of certificate Artifact Signing gives. So this route saves no time.

So "Microsoft signs it" means shipping BeeZip to the Store as an MSIX.

## What it takes in Partner Center

- **A company developer account:** free since 2026-05-07 (it was $99). A D-U-N-S number speeds up
  business verification. Without one, upload company formation documents, a business licence,
  registry records or tax filings, which are reviewed by hand. Use an email on the company's
  domain, or verification asks for more documents later. Signing up with an Entra ID work account
  is optional. Start at https://storedeveloper.microsoft.com.
- **Reserve the name** "BeeZip" (a new "MSIX or PWA app" product, or "EXE or MSI app" for the
  route below). The account and the name are separate steps: sign up any time, but reserve the
  name only once the route is chosen and a submission is under three months away.
  - **The product type is picked when the name is reserved** and doesn't look convertible
    afterwards. A Microsoft Q&A thread found EXE/MSI offered only when creating a new product
    (not an official statement).
  - **A reservation lapses after three months** if it isn't used.
- **The listing:** description, screenshots, the age-rating questionnaire, and a justification for
  each restricted capability the manifest declares (`runFullTrust` at least).
- **Certification:** every submission, updates included, is certified before it ships.
- **Identity:** Partner Center assigns the package's Identity `Name` and `Publisher`
  (`CN=<GUID>`). The manifest must use those, and `PublisherDisplayName` must match the account's
  publisher name.

## What it takes in BeeZip

Tauri builds only EXE and MSI installers (`bundle.targets` is `["nsis"]`), so the MSIX is
BeeZip's own: `xtask` already packs and signs `beezip-sparse.msix` with `makeappx` and
`signtool` (`xtask/src/sparse.rs`, `packaging/windows/sparse/AppxManifest.xml`). The work is a
full-package manifest, an `xtask dist` target that lays out the install folder and packs it, and
a "running as a package" mode in the app (`GetCurrentPackageFullName` succeeds) that turns off the
parts of the NSIS install that don't apply:

| NSIS install today | Store package |
|---|---|
| Explorer menu: the sparse package on Windows 11 and registry verbs in HKCU (`shell.install`) | The package's own manifest declares the `windows.comServer` and `desktop4:FileExplorerContextMenus` entries the sparse manifest has now; `shell.install` does nothing |
| File associations written by `packaging/windows/hooks.nsh`, with the old default backed up and restored | `uap:FileTypeAssociation` entries in the manifest, generated from `formats.list`; Windows lets the user choose the default |
| `bin\` added to the user's PATH by `hooks.nsh` | A `uap5:AppExecutionAlias` named `beezip.exe` (console) in `%LOCALAPPDATA%\Microsoft\WindowsApps`, which is on PATH. Not until Microsoft grants the HeadlessAppBypass waiver: from 0.7.1 the package has no command line (M12.md §14) |
| `tauri-plugin-updater` | Off: the install folder under `WindowsApps` is read-only and the Store delivers updates |
| `config.toml`, partial files and WebView2 data in the usual AppData folders | New AppData folders go to the package's private folder; `%TEMP%` and folders that already exist aren't redirected (spike results below) |
| NSIS installs WebView2 when it's missing | Uses the WebView2 runtime already there: always on Windows 11, almost always on Windows 10 |
| MCP clients run `...\bin\beezip.exe` | MCP clients run the alias, since programs under `WindowsApps` aren't meant to be started by their own path (once there is one: M12.md §14) |

### Spike results (2026-11-16, on the host)

The spike package was the 0.6.0 debug portable build plus a full manifest:
- the app, and the CLI as a second `Application` with a console alias;
- the 56 file associations from `formats.list`;
- the menu DLL as a `windows.comServer` surrogate with `desktop4:FileExplorerContextMenus`.

It was registered unpacked under Developer Mode (`Add-AppxPackage -Register`) as `BeeZipSpike`,
published by `CN=BeeZip Dev`. Scripts and data: `target/m12-spikes/`. The host was cleaned up
afterwards.

- **The manifest:** makeappx validates it. A console alias requires
  `desktop4:SupportsMultipleInstances="true"` on its `Application` (makeappx error 80080204
  without it).
- **The package identity:** the app has it however it starts, through its alias, from Start
  (`shell:AppsFolder`), through a file association, or from the menu (DllHost starts
  `BeeZip.exe --job`). So do the CLI and the DLL. All of them see the same AppData and registry.
- **The command line:** the alias runs `bin\beezip.exe` from any terminal, with console output,
  pipes and exit codes (3 for `NotFound`) unchanged. `beezip mcp` over stdio through the alias
  answers `initialize` and `tools/list`.
- **The Explorer menu:** the classic menu builder (`menu_dump`) lists the whole "BeeZip" cascade,
  served by DllHost from the package's own DLL, with no sparse package. "Extract here" through it
  extracted the archive.
- **File associations:** each type gets an `AppX…` ProgID in its `OpenWithProgids`. Opening a
  `.zip` through that ProgID starts the packaged `BeeZip.exe "<path>"`.
- **Virtualization, with no extra capability** (`unvirtualizedResources` isn't needed):
  - **`%TEMP%` isn't redirected,** even for new folders, so `beezip open`, drag-out, the menu's
    job files and `shell.log` land in the real temp folder where other programs see them;
  - **new folders elsewhere in AppData are redirected** to
    `%LOCALAPPDATA%\Packages\<family>\LocalCache\{Roaming,Local}`: `config.toml` on a machine
    that never had BeeZip, and WebView2's data;
  - **folders that already exist in AppData are written in place:** where an NSIS or portable
    BeeZip left `%APPDATA%\BeeZip\config.toml`, the Store copy reads and writes that file, so the
    settings carry over;
  - **HKCU writes are redirected** to the package's private hive. `settings set
    shell.items.add-7z=false` hid "Add to …7z" in the menu, so the DLL in DllHost reads that hive.
  - **Extraction through the alias** (`msix/appdata_probe.ps1`, looking from outside the
    package):
    - **in place** into a folder that exists in `AppData\Local`, and into a new subfolder of one;
    - **redirected to `LocalCache`** only into a brand-new folder directly under
      `AppData\Local`.

    Variant B (`unvirtualizedResources`, both virtualizations disabled) put all three in place.
    But Microsoft's capability list says it "is designed for certain types of desktop PC games …
    not intended to be used for other scenarios", so the plan keeps variant A (docs/M12.md
    decision 1).
- **What has to change in BeeZip** (found here):
  - **`shell status` says "not installed"** inside the package. Settings > Explorer menu would
    offer an Install whose registry writes go to the private hive, where Explorer never looks.
    In the package it should say the package provides the menu, and offer no install or remove;
  - **the updater:** `update.rs` sees no installer beside `BeeZip.exe` and treats the package as a
    portable copy, so it would offer the new zip. It must stay off and leave updates to the Store;
  - **"Copy as CLI"** points at `bin\beezip.exe`. In the package it should use the alias.
- **The certification kit** (`appcert.exe`) needs an elevated prompt, so it wasn't run.

### Spike results (2026-11-16, on the Windows 10 VM)

Windows 10 22H2 (build 19045), in BeeZip-Win10 from checkpoint `before-m12`, restored afterwards.
The same package, with the CLI alias named `beezip.exe`, was packed and signed with a throwaway
`CN=BeeZip Dev` certificate trusted only in the VM, then installed with `Add-AppxPackage` like a
Store install. Scripts: `target/m12-spikes/vm/` (`run.ps1` on the host, `menu.ps1` reads Explorer's
real context menu).

- **Installed from a signed `.msix`:** the files land in
  `C:\Program Files\WindowsApps\BeeZipSpike_0.6.0.0_x64__…`, read-only (a write is refused, and
  the `WindowsApps` folder can't be listed). Everything still runs:
  - **the command line:** the `beezip` alias for `--version`, `list` and exit code 3. So does
    `bin\beezip.exe` by its full path;
  - **the app:** it starts from Start and through the `.zip` ProgID, with package identity;
  - **settings and WebView2 data:** where the AppData folder already existed
    (`%LOCALAPPDATA%\app.beezip.desktop` here), the app wrote into it.
- **The updater runs inside the package:** the app wrote `update-check.json` on its first start.
  This confirms it has to be switched off there.
- **Windows 10's menu shows the package's menu.** The classic menu has "BeeZip >" for files and
  folders, from the package alone. The cascade has the 9 archive items on a `.zip` and the 4 "Add
  to" items on a folder. "Extract here" extracted the archive, served by DllHost (`Root(Modern)`
  in the DLL log). "Open with" lists the package once. So the Store build needs no registry
  verbs on Windows 10.
- **NSIS and Store installs on one machine** (NSIS 0.6.0 `/S` after the package):
  - **two identical "BeeZip >" cascades** on files and folders. One is NSIS's classic menu in
    `explorer.exe` (`Root(Classic)`), the other the package's in DllHost;
  - **two "BeeZip" entries under "Open with".** NSIS also made itself the `.zip` default
    (`HKCR\.zip` = `BeeZip.zip`), so "Open with BeeZip" is the top item;
  - **`beezip` runs the Store copy:** Windows 10's user PATH starts with
    `%LOCALAPPDATA%\Microsoft\WindowsApps`, and NSIS appends `bin\` after it;
  - **`shell status` from the Store CLI reports NSIS's menu** (classic, the DLL in
    `%LOCALAPPDATA%\BeeZip`), because the package sees the real HKCU as well as its private hive.
- **Removing the package** (`Remove-AppxPackage`) took a second, even after Explorer had used its
  menu. It took the aliases, the menu, the "Open with" entry, the install folder and
  `%LOCALAPPDATA%\Packages\<family>`, so settings kept only in the package's `LocalCache` go with
  it. NSIS's menu and association stayed.

**What M12 has to decide about both installs on one machine** (not built yet):
- **leave it:** duplicates for the few people who install both;
- **one side notices the other:** NSIS skips its menu and associations when the Store package is
  installed, or the package's Settings page says an NSIS copy is also installed and how to remove
  it.

**Not checked: both installs on Windows 11.** By inference, the flyout shows two BeeZip entries
when NSIS installed its sparse package. With the classic menu instead, the flyout shows only the
Store copy, and "Show more options" shows both.

### Certification kit (2026-11-16, on the host)

The user ran it elevated on the registered spike package (debug build, the host package above):
`appcert.exe test -packagefullname BeeZipSpike_0.6.0.0_x64__9vzn3qywa4gqa`. The kit is 10.0.26100
on Windows 11 and treats the package as a Desktop Bridge app. The overall result is **WARNING: no
required test failed.** The report is in `target/m12-spikes/wack/report.xml`. Microsoft's page
says optional tests are "informational only and will not be used to evaluate your app during
Microsoft Store onboarding".

- **Passed (21 tests):**
  - the manifest, including `runFullTrust`;
  - file association verbs, registry checks, special-use capabilities, branding and app
    resources;
  - the debug configuration, even for this debug build (the C runtime is linked statically);
  - the banned-file and private-key checks, and platform-appropriate files.
- **Application count: FAIL, optional.** "The Microsoft Store does not support a package
  containing more than one applications defined in the manifest." Python's Store package
  declares two to four applications (`python`, `pythonw`, `pip`, `idle`, each with its own
  alias; CPython's `PC/layout/support/appxmanifest.py`), so the Store accepts it. Confirm on the
  first submission. **It didn't:** Python's hidden apps (`AppListEntry="none"`) have Microsoft's
  HeadlessAppBypass waiver, and Partner Center refused 0.7.0's package for its hidden CLI app
  (M12.md §14).
- **Blocked executables: FAIL, optional.** It checks for Windows 10 S mode. It flags
  `CreateProcessW` and `ShellExecute(Ex)W` in all three binaries, and the strings `cmd.exe`,
  `powershell` and `bash` in `BeeZip.exe` and the DLL. Two of the matches, `cDb` and `dnX`, are
  random bytes. Microsoft: "If the flagged file(s) is part of your application, you may ignore
  the warning." BeeZip starts its own programs, plus the downloaded installer when the updater
  runs (the updater is off in the Store build), and opens files with their default apps.
- **DPI awareness: WARNING, required test.** "The app … is not DPI Aware": `BeeZip.exe` sets its
  DPI awareness at run time (tao), but its embedded manifest doesn't declare it. Fix in M12: give
  tauri-build a manifest with `<dpiAwareness>PerMonitorV2</dpiAwareness>`, keeping the Common
  Controls 6 dependency (`WindowsAttributes::app_manifest`). The kit also couldn't process
  `bin\beezip.exe`, a console program with no manifest.

## The other route: the Artifact-signed NSIS setup in the Store

Once Artifact Signing works, the existing `setup.exe` can go into the Store as an "EXE or MSI app"
with no MSIX work. Microsoft doesn't sign it; ours does. What that route asks for (Microsoft's
MSI/EXE package requirements, Tauri's Store guide):

- **Every program in the installer signed** with a certificate that chains to a CA in the Trusted
  Root Program. `xtask dist` already signs all 13 (docs/M6.md §16, item 12). Artifact Signing's
  certificates chain to Microsoft's own root. Microsoft's comparison table marks Artifact Signing
  "not Store eligible", which reads as "meant for outside the Store"; confirm on the first
  submission.
- **A versioned HTTPS URL that never changes:** the tag's release asset
  (`/releases/download/v0.6.0/...-setup.exe`), not `/releases/latest/`. Each release gives
  Partner Center a new URL and goes through certification again.
- **A silent install:** installer parameters `/S`.
- **A standalone installer, with no downloads during setup.** Tauri's default WebView2 mode,
  `downloadBootstrapper`, breaks this rule. The Store build needs `webviewInstallMode`
  `offlineInstaller`, which makes it much larger, so it would be a separate Store-only config,
  as Tauri suggests.
- **Updates stay BeeZip's own:** `tauri-plugin-updater` keeps working, and the Store doesn't
  manage the version.
- **A publisher name that isn't the product name:** "Close Consulting, Inc" already.

## What the Store signature doesn't cover

It covers only copies installed from the Store. The GitHub release downloads (the NSIS `setup.exe`
and the portable zip), the winget manifest that points at them (`packaging/winget/`), and the
Linux and macOS bundles all stay unsigned until a certificate exists. A Store app also shows up in
winget's `msstore` source on its own, so winget users could install the Store copy instead.

## Sources

- [Code signing options for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options) (Microsoft Learn, updated 2026-11-10)
- [Publish to Microsoft Store as a company: free registration and faster onboarding](https://blogs.windows.com/windowsdeveloper/2026/05/07/publish-to-microsoft-store-as-a-company-now-with-free-registration-and-faster-onboarding/) (Windows Developer Blog, 2026-05-07)
- [How to distribute your Win32 app through the Microsoft Store](https://learn.microsoft.com/en-us/windows/apps/distribute-through-store/how-to-distribute-your-win32-app-through-microsoft-store)
- [Tauri: Microsoft Store](https://v2.tauri.app/distribute/microsoft-store/) (the EXE/MSI route only)
- [App package requirements for MSI/EXE app](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/app-package-requirements) (Microsoft Learn, updated 2026-08-24)
- [Reserve your MSI/EXE app's name](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/reserve-your-apps-name) (Microsoft Learn, updated 2026-10-07)
- [Windows Store: change existing MSIX or PWA app to EXE or MSI](https://learn.microsoft.com/en-us/answers/questions/1244248/windows-store-change-existing-msix-or-pwa-app-to-e) (Microsoft Q&A)
