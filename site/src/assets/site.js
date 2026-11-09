// BeeZip's website: the newest release's files, from GitHub, for the download buttons; copy
// buttons on command lines; the menu on wide screens; and the hero's scale.
(() => {
  const REPO = "JoshClose/BeeZip";
  const API = `https://api.github.com/repos/${REPO}/releases/latest`;
  const RELEASES = `https://github.com/${REPO}/releases`;
  const CACHE = "beezip.latest";

  /** The release's files, by what they are. */
  const FILES = {
    "windows-setup": { match: /_x64-setup\.exe$/, what: "installer" },
    "windows-portable": { match: /_x64-portable\.zip$/, what: "portable zip" },
    "linux-deb": { match: /_amd64\.deb$/, what: "Debian and Ubuntu package" },
    "linux-rpm": { match: /\.x86_64\.rpm$/, what: "Fedora and openSUSE package" },
    "linux-appimage": { match: /\.AppImage$/, what: "AppImage" },
    "mac-dmg": { match: /_aarch64\.dmg$/, what: "disk image, Apple silicon" },
  };
  /** What each platform's main button downloads, in order of preference. */
  const PREFER = {
    windows: ["windows-setup", "windows-portable"],
    linux: ["linux-deb", "linux-appimage", "linux-rpm"],
    mac: ["mac-dmg"],
  };
  const NAMES = { windows: "Windows", linux: "Linux", mac: "macOS" };

  function platform() {
    const p = `${navigator.userAgentData?.platform ?? ""} ${navigator.platform ?? ""} ${navigator.userAgent}`;
    if (/Win/i.test(p)) return "windows";
    if (/Mac|iPhone|iPad/i.test(p)) return "mac";
    if (/Linux|X11|CrOS/i.test(p) && !/Android/i.test(p)) return "linux";
    return "windows";
  }

  const size = (bytes) => (bytes >= 1 << 20 ? `${(bytes / (1 << 20)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`);
  const date = (iso) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });

  /** The newest release, `null` before the first one, or `undefined` when GitHub can't be asked. */
  async function latest() {
    try {
      const kept = JSON.parse(sessionStorage.getItem(CACHE) ?? "null");
      if (kept && Date.now() - kept.at < 10 * 60 * 1000) return kept.release;
    } catch {}
    let release;
    try {
      const r = await fetch(API, { headers: { Accept: "application/vnd.github+json" } });
      if (r.status === 404) release = null;
      else if (r.ok) release = await r.json();
      else return undefined;
    } catch {
      return undefined;
    }
    try {
      sessionStorage.setItem(CACHE, JSON.stringify({ at: Date.now(), release }));
    } catch {}
    return release;
  }

  function files(release) {
    const found = {};
    for (const asset of release.assets ?? []) {
      for (const [key, f] of Object.entries(FILES)) {
        if (f.match.test(asset.name)) found[key] = { url: asset.browser_download_url, name: asset.name, size: asset.size, what: f.what };
      }
    }
    return found;
  }

  async function downloads() {
    const boxes = document.querySelectorAll("[data-state]");
    if (!boxes.length) return;
    const release = await latest();
    const os = platform();
    for (const el of document.querySelectorAll("[data-os-name]")) el.textContent = NAMES[os];

    if (!release) {
      // Before the first release, or GitHub out of reach: the releases page has whatever there is.
      for (const box of boxes) box.dataset.state = release === null ? "none" : "ready";
      for (const a of document.querySelectorAll("[data-download]")) a.href = RELEASES;
      for (const el of document.querySelectorAll("[data-download-meta]")) {
        el.textContent = release === null ? "" : "The newest version is on GitHub.";
      }
      return;
    }

    const version = release.tag_name.replace(/^v/, "");
    const found = files(release);
    for (const el of document.querySelectorAll('[data-release="version"]')) el.textContent = version;
    for (const el of document.querySelectorAll('[data-release="date"]')) el.textContent = date(release.published_at);
    for (const a of document.querySelectorAll('[data-release="page"]')) a.href = release.html_url;

    const main = PREFER[os].map((k) => found[k]).find(Boolean);
    for (const a of document.querySelectorAll('[data-download="auto"]')) a.href = main?.url ?? release.html_url;
    for (const el of document.querySelectorAll("[data-download-meta]")) {
      el.textContent = main ? `Version ${version}, ${main.what}, ${size(main.size)}` : `Version ${version}`;
    }
    for (const li of document.querySelectorAll("[data-file]")) {
      const f = found[li.dataset.file];
      li.hidden = !f;
      if (!f) continue;
      const a = li.querySelector("a");
      a.href = f.url;
      li.querySelector("[data-name]").textContent = f.name;
      li.querySelector("[data-size]").textContent = size(f.size);
    }
    for (const box of boxes) box.dataset.state = "ready";
  }

  /** A Copy button on each command line. */
  function copyButtons() {
    for (const pre of document.querySelectorAll("pre")) {
      const code = pre.querySelector("code");
      if (!code || !navigator.clipboard) continue;
      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy";
      button.textContent = "Copy";
      button.addEventListener("click", async () => {
        // Comments after `#` are explanations, not part of the command.
        const text = code.innerText
          .split("\n")
          .map((l) => l.replace(/\s+#\s.*$/, "").replace(/^#\s.*$/, ""))
          .filter((l, i, all) => l.trim() || (i > 0 && i < all.length - 1))
          .join("\n")
          .trim();
        try {
          await navigator.clipboard.writeText(text);
          button.textContent = "Copied";
        } catch {
          button.textContent = "Select and copy";
        }
        setTimeout(() => (button.textContent = "Copy"), 2000);
      });
      pre.append(button);
    }
  }

  /** Comments in command lines, dimmed. */
  function dimComments() {
    for (const code of document.querySelectorAll("pre code")) {
      if (code.closest(".usage")) continue;
      code.innerHTML = code.innerHTML
        .split("\n")
        .map((l) => l.replace(/(^|\s)(#\s.*)$/, '$1<span class="c">$2</span>'))
        .join("\n");
    }
  }

  /** On wide screens the header's menu is simply open. */
  function menu() {
    const details = document.querySelector(".menu");
    const sideNav = document.querySelector(".docs-nav details");
    const wide = matchMedia("(min-width: 761px)");
    const docsWide = matchMedia("(min-width: 821px)");
    const sync = () => {
      if (details) details.open = wide.matches;
      if (sideNav) sideNav.open = docsWide.matches;
    };
    sync();
    wide.addEventListener("change", sync);
    docsWide.addEventListener("change", sync);
  }

  /** The hero's menu is drawn at 580 px wide and scaled to its column. */
  function stage() {
    const desk = document.querySelector(".desk");
    if (!desk) return;
    const fit = () => desk.style.setProperty("--s", String(desk.clientWidth / 580));
    fit();
    new ResizeObserver(fit).observe(desk);
  }

  /** The formats' comb: as many cells as fit in a row, every other row half a cell in. */
  function comb() {
    for (const list of document.querySelectorAll(".comb")) {
      const cells = [...list.children];
      if (!cells.length) continue;
      const lay = () => {
        const margin = parseFloat(getComputedStyle(cells[0]).marginLeft);
        const cell = cells[0].offsetWidth + 2 * margin;
        const width = list.clientWidth;
        const full = Math.max(1, Math.floor(width / cell));
        const indented = Math.max(1, Math.floor((width - cell / 2) / cell));
        for (const c of cells) c.style.marginLeft = "";
        for (let i = 0, row = 0; i < cells.length; row++) {
          if (row % 2) cells[i].style.marginLeft = `${cell / 2 + margin}px`;
          i += row % 2 ? indented : full;
        }
        list.classList.add("laid");
      };
      lay();
      new ResizeObserver(lay).observe(list);
    }
  }

  menu();
  stage();
  comb();
  dimComments();
  copyButtons();
  void downloads();
})();
