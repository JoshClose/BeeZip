// BeeZip's website: site/src → site/dist, with Node's own modules only.
//
//   node site/build.mjs --cli <path to beezip> [--out <dir>] [--base /BeeZip/]
//
// Pages are HTML fragments under site/src (names starting with `_` are not pages), each opening
// with a JSON comment: {"title", "description", "layout": "home" | "page" | "docs"}. The build:
// - wraps each in the layout: the header, the footer and, for docs, the sidebar
//   (site/src/docs/_nav.json), an "On this page" list of its h2s, and the next and previous page;
// - fills the `<!-- beezip:… -->` slots from what the CLI itself says, so they can't go stale:
//   the command reference (every command's --help), the formats (`beezip formats`), and the
//   honeycomb on the home page; and renders CHANGELOG.md into the releases page;
// - fails when the settings page leaves out a setting `beezip settings get` lists;
// - copies site/src/assets, and the brand marks from packaging/brand;
// - fails when a relative link or #anchor leads nowhere.

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..");
const src = join(here, "src");
const GITHUB = "https://github.com/JoshClose/BeeZip";

const args = process.argv.slice(2);
const arg = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const cliPath = arg("--cli");
const out = resolve(arg("--out") ?? join(here, "dist"));
// Where the site is served from: the 404 page, shown at any address, links from there.
const base = arg("--base") ?? "/BeeZip/";
if (!cliPath) {
  console.error("usage: node site/build.mjs --cli <path to beezip> [--out <dir>]");
  process.exit(2);
}

// ---------------------------------------------------------------------------------------------
// The CLI, run with an empty config so nothing on this machine changes what it says.

const emptyConfig = join(tmpdir(), `beezip-site-${process.pid}.toml`);
function cli(...argv) {
  return execFileSync(resolve(cliPath), argv, {
    encoding: "utf8",
    env: { ...process.env, BEEZIP_CONFIG: emptyConfig, NO_COLOR: "1", COLUMNS: "100" },
    maxBuffer: 64 << 20,
  });
}
const cliJson = (...argv) => JSON.parse(cli(...argv, "--output", "json"));

const version = cliJson("version").version;
const commands = cliJson("commands");
const formats = cliJson("formats");
const settings = cliJson("settings", "get").settings;

// ---------------------------------------------------------------------------------------------
// Small helpers.

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/** Escaped text with `code` spans. */
const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
const slug = (s) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

// ---------------------------------------------------------------------------------------------
// The command reference, from each command's --help.

/** The top-level help's commands, with their aliases: { name: [alias…] }. */
function aliases() {
  const found = {};
  let name;
  for (const line of cli("--help").split(/\r?\n/)) {
    const m = /^ {2}(\S+)\s{2,}/.exec(line);
    if (m) name = m[1];
    const a = /\[aliases?: ([^\]]+)\]/.exec(line);
    if (a && name) found[name] = a[1].split(/,\s*/);
  }
  return found;
}

/** clap's long help, in parts: about, usage, and sections of items (term, description lines). */
function parseHelp(text) {
  const about = [];
  let usage = "";
  const sections = [];
  let section;
  for (const line of text.replace(/\r/g, "").split("\n")) {
    if (line.startsWith("Usage: ")) {
      usage = line.slice(7).trim();
      section = undefined;
      continue;
    }
    const head = /^([A-Z][A-Za-z ]+):$/.exec(line);
    if (head) {
      section = { name: head[1], items: [] };
      sections.push(section);
      continue;
    }
    if (!section) {
      if (!usage) about.push(line);
      continue;
    }
    const item = /^ {2,6}(\S.*)$/.exec(line);
    if (item) {
      // A short help puts the description on the term's line, after two or more spaces.
      const [term, ...rest] = item[1].split(/\s{2,}/);
      section.items.push({ term: term.trim(), desc: rest.length ? [rest.join(" ")] : [] });
    } else if (section.items.length) {
      section.items.at(-1).desc.push(line.replace(/^ {6,10}/, ""));
    }
  }
  return { about: about.join("\n").trim(), usage, sections };
}

/** Description lines as HTML: paragraphs, `- ` lists, [default: …] notes. */
function describe(lines) {
  const blocks = [];
  let para = [];
  let list;
  const flush = () => {
    if (para.length) blocks.push(`<p>${inline(para.join(" "))}</p>`);
    para = [];
  };
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (!line.trim()) {
      flush();
      if (list) blocks.push(`<ul>${list.map((i) => `<li>${inline(i)}</li>`).join("")}</ul>`);
      list = undefined;
      continue;
    }
    const bullet = /^- (.*)$/.exec(line.trim());
    if (bullet && (list || !para.length || /:$/.test(para.at(-1) ?? ""))) {
      flush();
      (list ??= []).push(bullet[1]);
    } else if (list) {
      list[list.length - 1] += ` ${line.trim()}`;
    } else {
      para.push(line.trim());
    }
  }
  flush();
  if (list) blocks.push(`<ul>${list.map((i) => `<li>${inline(i)}</li>`).join("")}</ul>`);
  return blocks
    .join("\n")
    .replace(/\[(default|possible values|aliases?): ([^\]]+)\]/g, (_, k, v) => `<span class="meta">${k}: ${v}</span>`);
}

/** The reference's groups, in order; a command missing from them is added under "More". */
const GROUPS = [
  ["Looking inside", ["info", "list", "read", "test", "detect", "formats"]],
  ["Extracting and opening", ["extract", "open"]],
  ["Creating and changing archives", ["create", "add", "remove", "rename", "convert"]],
  ["Single files", ["compress", "decompress"]],
  ["Settings, Explorer's menu and 7-Zip", ["settings get", "settings set", "shell status", "shell install", "shell uninstall", "shell plan", "7zip install"]],
  ["Everything else", ["bench", "version", "mcp", "commands", "schema", "run"]],
];

function reference() {
  const alias = aliases();
  const known = new Set([...commands.filter((c) => c.cli && c.surfaces.cli).map((c) => c.cli), "mcp", "commands", "schema", "run"]);
  const grouped = new Set(GROUPS.flatMap(([, names]) => names));
  const groups = GROUPS.map(([title, names]) => [title, names.filter((n) => known.has(n))]);
  const more = [...known].filter((n) => !grouped.has(n)).sort();
  if (more.length) groups.push(["More", more]);

  const global = parseHelp(cli("list", "--help")).sections.find((s) => s.name === "Global options");
  const parts = [];
  parts.push(`<h2 id="global-options">Global options</h2>
<p>Every command takes these, before or after its own arguments.</p>
<dl class="opts">${global.items.map((i) => `<dt><code>${esc(i.term)}</code></dt><dd>${describe(i.desc)}</dd>`).join("\n")}</dl>`);
  for (const [title, names] of groups) {
    parts.push(`<h2 id="${slug(title)}">${esc(title)}</h2>`);
    for (const name of names) {
      const help = parseHelp(cli(...name.split(" "), "--help"));
      const id = slug(name);
      const al = alias[name]?.length ? ` <span class="alias">alias ${alias[name].map((a) => `<code>${esc(a)}</code>`).join(", ")}</span>` : "";
      const sections = help.sections
        .filter((s) => s.name !== "Global options")
        .map((s) => {
          const items = s.items.filter((i) => !/^-h, --help$/.test(i.term));
          if (!items.length) return "";
          return `<h4>${esc(s.name)}</h4>
<dl class="opts">${items.map((i) => `<dt><code>${esc(i.term)}</code></dt><dd>${describe(i.desc)}</dd>`).join("\n")}</dl>`;
        })
        .join("\n");
      parts.push(`<section class="cmd">
<h3 id="${id}"><code>beezip ${esc(name)}</code>${al}</h3>
${describe(help.about.split("\n"))}
<pre class="usage"><code>${esc(help.usage)}</code></pre>
${sections}
</section>`);
    }
  }
  return parts.join("\n\n");
}

// ---------------------------------------------------------------------------------------------
// Formats: the table, and the home page's honeycomb.

const viaSevenZip = (f) => !!f.backend;
const archiveFormats = () => formats.formats.filter((f) => f.id !== "stream");
const kind = (f) => (viaSevenZip(f) ? "seven" : f.caps.create ? "rw" : "ro");

function formatsTable() {
  const yes = (b, what) => (b ? `<span class="yes">${what}</span>` : `<span class="no">–</span>`);
  const rows = archiveFormats().map((f) => {
    const edit = f.caps.append && f.caps.delete && f.caps.rename;
    const ext = f.extensions.slice(0, 8).map((e) => `<code>${esc(e)}</code>`).join(" ") + (f.extensions.length > 8 ? " …" : "");
    return `<tr class="${kind(f)}"><th scope="row">${esc(f.name)}</th><td>${ext}</td><td>${yes(true, "Reads")}</td><td>${yes(
      f.caps.create,
      "Writes",
    )}</td><td>${yes(edit, "Edits")}</td><td>${yes(f.caps.encrypt, "Encrypts")}</td><td>${yes(f.caps.volumes, "Splits")}</td><td>${
      viaSevenZip(f) ? "Through 7-Zip" : ""
    }</td></tr>`;
  });
  const codecs = formats.codecs
    .filter((c) => c.extensions.length)
    .map(
      (c) =>
        `<tr><th scope="row">${esc(c.name)}</th><td>${c.extensions.map((e) => `<code>${esc(e)}</code>`).join(" ")}</td><td>${
          c.levels ? `${c.levels.min} to ${c.levels.max} (default ${c.levels.default})` : "–"
        }</td><td>${c.threads ? "Yes" : "–"}</td></tr>`,
    );
  return `<div class="table-wrap"><table class="formats">
<thead><tr><th scope="col">Format</th><th scope="col">Extensions</th><th scope="col">Read</th><th scope="col">Create</th><th scope="col">Edit</th><th scope="col">Encrypt</th><th scope="col">Split</th><th scope="col"></th></tr></thead>
<tbody>
${rows.join("\n")}
</tbody></table></div>
<h2 id="compressors">Compressors</h2>
<p>Each of these compresses one file on its own (<code>beezip compress</code>), and tar and cpio archives under it (<code>.tar.zst</code>, <code>.cpio.gz</code>). BeeZip finds them by their content, whatever the file is called.</p>
<div class="table-wrap"><table class="codecs">
<thead><tr><th scope="col">Compressor</th><th scope="col">Extensions</th><th scope="col">Levels</th><th scope="col">Uses every core</th></tr></thead>
<tbody>
${codecs.join("\n")}
</tbody></table></div>`;
}

/** The formats as comb cells: amber when BeeZip writes them, outlined when it reads them, deep amber through 7-Zip. */
function honeycomb() {
  const order = { rw: 0, ro: 1, seven: 2 };
  const cells = archiveFormats()
    .slice()
    .sort((a, b) => order[kind(a)] - order[kind(b)])
    .map((f) => `<li class="cell ${kind(f)}"><span>${esc(f.name)}</span></li>`);
  const codecs = formats.codecs.filter((c) => c.extensions.length).map((c) => `<li class="cell codec"><span>${esc(c.name)}</span></li>`);
  return `<div class="comb-wrap"><ul class="comb" aria-label="Formats BeeZip opens">${cells.join("")}${codecs.join("")}</ul></div>`;
}

// ---------------------------------------------------------------------------------------------
// The changelog: CHANGELOG.md's few Markdown forms (##, ###, -, paragraphs, **, `, links).

function markdownInline(s) {
  return esc(s)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, t, u) => `<a href="${u}">${t}</a>`);
}

function changelog() {
  const text = readFileSync(join(repo, "CHANGELOG.md"), "utf8").replace(/\r/g, "");
  const html = [];
  let list;
  let para = [];
  let open = false;
  const flush = () => {
    if (para.length) html.push(`<p>${markdownInline(para.join(" "))}</p>`);
    para = [];
    if (list) html.push(`<ul>${list.map((i) => `<li>${markdownInline(i)}</li>`).join("\n")}</ul>`);
    list = undefined;
  };
  // What comes before the first version is for whoever keeps the file.
  for (const line of text.slice(text.search(/^## /m)).split("\n")) {
    let m;
    if ((m = /^## (\S+)(?: \(([^)]+)\))?\s*$/.exec(line))) {
      flush();
      if (open) html.push("</section>");
      const [, v, date] = m;
      if (!/^\d+\.\d+\.\d+/.test(v)) throw new Error(`CHANGELOG.md: "## ${v}" isn't a version`);
      html.push(`<section class="release"><h2 id="v${slug(v)}">BeeZip ${esc(v)}</h2><p class="released">${date ? `Released ${esc(date)}` : "Not released yet"}</p>`);
      open = true;
    } else if ((m = /^### (.+)$/.exec(line))) {
      flush();
      html.push(`<h3>${markdownInline(m[1])}</h3>`);
    } else if ((m = /^- (.*)$/.exec(line))) {
      if (para.length) flush();
      (list ??= []).push(m[1]);
    } else if (/^\s{2,}\S/.test(line) && list) {
      list[list.length - 1] += ` ${line.trim()}`;
    } else if (!line.trim()) {
      flush();
    } else {
      if (list) flush();
      para.push(line.trim());
    }
  }
  flush();
  if (open) html.push("</section>");
  return html.join("\n");
}

// ---------------------------------------------------------------------------------------------
// The brand marks, inline: their colours become the theme's, so the ink cells show on a dark page,
// and comb-lifted's lifted cell can move.

const COLOURS = { "#E0A21A": "var(--amber-fill)", "#9A6700": "var(--deep)", "#1F2023": "var(--ink)" };
function mark(name, cls = "") {
  let svg = readFileSync(join(repo, "packaging", "brand", `${name}.svg`), "utf8")
    .replace(/<title>[^<]*<\/title>\s*/, "")
    .replace(/\s(width|height)="[^"]*"/g, "")
    .replace(/\sid="[^"]*"/g, "")
    .replace(/fill="(#[0-9A-Fa-f]{6})"/g, (m, c) => (COLOURS[c.toUpperCase()] ? `style="fill:${COLOURS[c.toUpperCase()]}"` : m));
  if (name === "comb-lifted") svg = svg.replace(/(<polygon[^>]*fill:var\(--ink\)[^>]*\/>)/, '<g class="lifted">$1</g>');
  return svg.replace("<svg ", `<svg class="mark ${name}${cls ? ` ${cls}` : ""}" aria-hidden="true" focusable="false" `).trim();
}

// ---------------------------------------------------------------------------------------------
// The layout.

const NAV = [
  ["features", "features.html", "Features"],
  ["docs", "docs/index.html", "Docs"],
  ["releases", "releases.html", "Releases"],
];
const docsNav = JSON.parse(readFileSync(join(src, "docs", "_nav.json"), "utf8"));

function readPage(file) {
  const text = readFileSync(file, "utf8").replace(/\r/g, "");
  const m = /^<!--\s*(\{[\s\S]*?\})\s*-->\n?/.exec(text);
  if (!m) throw new Error(`${relative(repo, file)} has no front matter`);
  return { meta: JSON.parse(m[1]), body: text.slice(m[0].length) };
}

/** Links on h2 and h3 with ids, and the h2s for "On this page". */
function anchors(body) {
  const toc = [];
  const html = body.replace(/<(h[23]) id="([^"]+)">([\s\S]*?)<\/\1>/g, (_, h, id, inner) => {
    if (h === "h2") toc.push([id, inner.replace(/<[^>]+>/g, "")]);
    return `<${h} id="${id}">${inner}<a class="anchor" href="#${id}" aria-label="Link to this section"></a></${h}>`;
  });
  return { html, toc };
}

function layout({ meta, body, path }) {
  const depth = path.split("/").length - 1;
  const root = meta.absolute ? base : "../".repeat(depth);
  const section = meta.section ?? (path.startsWith("docs/") ? "docs" : path.replace(/\.html$/, ""));
  const title = path === "index.html" ? "BeeZip: archives from the right-click menu" : `${meta.title} | BeeZip`;
  const nav = NAV.map(([id, href, label]) => `<a href="${root}${href}"${id === section ? ' aria-current="page"' : ""}>${label}</a>`).join("");

  let main;
  if (meta.layout === "docs") {
    const { html, toc } = anchors(body);
    const here = docsNav.findIndex((d) => d.href === path.slice(5));
    const prev = docsNav[here - 1];
    const next = docsNav[here + 1];
    const side = docsNav
      .map((d) => `<li><a href="${d.href}"${d.href === path.slice(5) ? ' aria-current="page"' : ""}>${esc(d.title)}</a></li>`)
      .join("");
    const pager = [
      prev ? `<a class="prev" href="${prev.href}"><span>Previous</span>${esc(prev.title)}</a>` : "<span></span>",
      next ? `<a class="next" href="${next.href}"><span>Next</span>${esc(next.title)}</a>` : "<span></span>",
    ].join("");
    main = `<div class="docs">
<nav class="docs-nav" aria-label="Documentation"><details open><summary>Documentation</summary><ul>${side}</ul></details></nav>
<article class="prose">
${html}
<nav class="pager" aria-label="Next and previous">${pager}</nav>
</article>
${
  toc.length > 1
    ? `<aside class="toc" aria-label="On this page"><p>On this page</p><ol>${toc.map(([id, t]) => `<li><a href="#${id}">${esc(t)}</a></li>`).join("")}</ol></aside>`
    : ""
}
</div>`;
  } else if (meta.layout === "page") {
    main = `<div class="page prose${meta.wide ? " wide" : ""}">${anchors(body).html}</div>`;
  } else {
    main = body;
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(meta.description)}">
<meta name="color-scheme" content="light dark">
<meta property="og:title" content="${esc(meta.title)}">
<meta property="og:description" content="${esc(meta.description)}">
<meta property="og:type" content="website">
<link rel="icon" href="${root}assets/brand/app-icon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Recursive:slnt,wght,CASL,CRSV,MONO@-15..0,300..1000,0..1,0..1,0..1&display=swap">
<link rel="stylesheet" href="${root}assets/site.css">
<script src="${root}assets/site.js" defer></script>
</head>
<body class="layout-${meta.layout}">
<a class="skip" href="#main">Skip to the content</a>
<header class="masthead">
<div class="masthead-inner">
<a class="brand" href="${root}index.html"><img src="${root}assets/brand/logo.svg" alt="" width="36" height="36"><span>BeeZip</span></a>
<details class="menu" open><summary aria-label="Menu"><span></span></summary>
<nav aria-label="Site">${nav}<a href="${GITHUB}">GitHub</a></nav>
</details>
<a class="button primary small" href="${root}download.html">Download</a>
</div>
</header>
<main id="main">
${main}
</main>
<footer class="foot">
<div class="foot-inner">
${mark("comb-rosette", "foot-mark")}
<p>BeeZip is free and open source, under the MIT or Apache 2.0 license. It reads RAR with UnRAR, which has its own license.</p>
<nav aria-label="More">
<a href="${root}download.html">Download</a><a href="${root}docs/index.html">Docs</a><a href="${root}releases.html">Releases</a><a href="${GITHUB}">Source code</a><a href="${GITHUB}/issues">Report a problem</a><a href="${GITHUB}/blob/master/THIRD_PARTY_NOTICES.md">Third-party notices</a>
</nav>
</div>
</footer>
</body>
</html>
`;
}

// ---------------------------------------------------------------------------------------------
// Build.

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

const slots = {
  reference: () => reference(),
  formats: () => formatsTable(),
  honeycomb: () => honeycomb(),
  changelog: () => changelog(),
  version: () => esc(version),
  base: () => base,
  mark: (name, cls) => mark(name, cls),
  "format-count": () => String(archiveFormats().length),
};

const pages = walk(src).filter((f) => f.endsWith(".html") && !f.split(sep).some((p) => p.startsWith("_")));
for (const file of pages) {
  const path = relative(src, file).split(sep).join("/");
  const page = readPage(file);
  page.path = path;
  page.body = page.body.replace(/<!-- beezip:([a-z-]+)((?: [a-z0-9-]+)*) -->/g, (_, name, rest) => {
    if (!slots[name]) throw new Error(`${path}: no slot "${name}"`);
    return slots[name](...rest.trim().split(/\s+/).filter(Boolean));
  });
  const dest = join(out, path);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, layout(page));
}

for (const name of readdirSync(join(src, "assets"))) cpSync(join(src, "assets", name), join(out, "assets", name), { recursive: true });
mkdirSync(join(out, "assets", "brand"), { recursive: true });
for (const name of readdirSync(join(repo, "packaging", "brand")).filter((n) => n.endsWith(".svg"))) {
  cpSync(join(repo, "packaging", "brand", name), join(out, "assets", "brand", name));
}
writeFileSync(join(out, ".nojekyll"), "");

// ---------------------------------------------------------------------------------------------
// Checks.

const problems = [];

// Every setting is on the settings page.
const settingsFile = join(out, "docs", "settings.html");
const settingsPage = existsSync(settingsFile) ? readFileSync(settingsFile, "utf8") : "";
const flat = (o, prefix = "") =>
  Object.entries(o).flatMap(([k, v]) => (v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length ? flat(v, `${prefix}${k}.`) : [`${prefix}${k}`]));
for (const key of flat(settings)) {
  if (!settingsPage.includes(`<code>${key}</code>`)) problems.push(`docs/settings.html doesn't describe the setting ${key}`);
}

// Every relative link and anchor resolves.
const built = walk(out).filter((f) => f.endsWith(".html"));
const ids = new Map(built.map((f) => [f, new Set([...readFileSync(f, "utf8").matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]))]));
for (const file of built) {
  const html = readFileSync(file, "utf8");
  for (const [, url] of html.matchAll(/\s(?:href|src)="([^"]+)"/g)) {
    if (/^(https?:|mailto:|data:)/.test(url)) continue;
    const [path, hash] = url.split("#");
    let target = !path ? file : path.startsWith(base) ? join(out, path.slice(base.length)) : resolve(dirname(file), path);
    if (path && existsSync(target) && statSync(target).isDirectory()) target = join(target, "index.html");
    const where = relative(out, file).split(sep).join(posix.sep);
    if (!existsSync(target)) problems.push(`${where}: ${url} leads nowhere`);
    else if (hash && target.endsWith(".html") && !ids.get(target)?.has(hash)) problems.push(`${where}: ${url} has no #${hash}`);
  }
}

rmSync(emptyConfig, { force: true });
if (problems.length) {
  console.error(problems.map((p) => `site: ${p}`).join("\n"));
  process.exit(1);
}
console.log(`site: ${built.length} pages for BeeZip ${version} in ${relative(process.cwd(), out) || "."}`);
