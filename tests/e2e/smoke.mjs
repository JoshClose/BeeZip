// BeeZip's end-to-end smoke test (docs/M6.md §10): W3C WebDriver calls through tauri-driver, with
// Node's own fetch and no dependencies. Every input goes through WebDriver, inside the page;
// nothing touches the machine's mouse or keyboard.
//
//   node tests/e2e/smoke.mjs <BeeZip exe> <archive> <entry the archive lists>...
//
// WD_URL is tauri-driver's address (default http://127.0.0.1:4444). The caller sets BEEZIP_CONFIG
// and a scratch WebView2 profile (.github/scripts/e2e.ps1).
//
// 1. BeeZip starts on its own.
// 2. A second BeeZip.exe started right away hands it the archive, as Explorer does when several
//    archives are opened at once. With msedgedriver, `args` can't carry the archive: it turns
//    each into a lowercased Chromium switch (`--c:\users\…`). The second launch is also what the
//    early-launch fix (§8.1) is about: it may arrive before the page listens, and must not be lost.
// 3. The archive's entries show; Ctrl+K opens the palette; typing `app.version` filters it to
//    that command; Escape closes it; deleting the session closes BeeZip.
import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";

const [exe, archive, ...expected] = process.argv.slice(2);
if (!exe || !archive || expected.length === 0) {
  console.error("usage: node tests/e2e/smoke.mjs <exe> <archive> <entry>...");
  process.exit(2);
}
const base = process.env.WD_URL ?? "http://127.0.0.1:4444";
const ELEMENT = "element-6066-11e4-a52e-4f735466cecf"; // the W3C web element identifier
const t0 = performance.now();
const log = (...a) => console.log(`[${Math.round(performance.now() - t0)} ms]`, ...a);

async function wd(method, path, body) {
  const r = await fetch(base + path, {
    method,
    headers: { "content-type": "application/json; charset=utf-8" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(`${method} ${path}: HTTP ${r.status} ${JSON.stringify(j.value)}`);
  return j.value;
}

let sid;
const s = (p) => `/session/${sid}${p}`;
const exec = (script, args = []) => wd("POST", s("/execute/sync"), { script, args });
const find = async (css) => (await wd("POST", s("/elements"), { using: "css selector", value: css })).map((e) => e[ELEMENT] ?? e.ELEMENT);
// Get Element Text, or innerText when the driver says "" (WebKitWebDriver does for the grid's
// virtualised rows).
const text = async (id) => (await wd("GET", s(`/element/${id}/text`))) || exec("return arguments[0].innerText", [{ [ELEMENT]: id }]);

/** Polls `fn` until it returns something truthy, or throws after `timeout` ms. */
async function until(what, fn, timeout) {
  const end = performance.now() + timeout;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (performance.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

let failed = false;
try {
  sid = (await wd("POST", "/session", { capabilities: { alwaysMatch: { "tauri:options": { application: exe } } } })).sessionId;
  log("session", sid, "page:", await exec("return document.readyState"));

  // Straight away, without waiting for the page.
  const r = spawnSync(exe, [archive], { timeout: 15000 });
  log(`the second BeeZip.exe exited ${r.status}`);
  assert.equal(r.status, 0, "the second launch should hand over its archive and exit");

  // The archive's entries: rows of the Entries grid (EntryTable.tsx), past the header row.
  const rows = await until(
    "the archive's entries",
    async () => {
      const found = await find("[role=grid][aria-label=Entries] [role=row][aria-rowindex]");
      return found.length ? found : null;
    },
    20000,
  );
  const names = [];
  for (const row of rows) names.push((await text(row)).trim().split("\n")[0].trim());
  log(`${rows.length} rows:`, names.join(" | "));
  for (const e of expected) assert.ok(names.some((n) => n.startsWith(e)), `${e} isn't among the entries: ${names}`);
  const tabs = await exec("return [...document.querySelectorAll('[role=tab]')].map((t) => t.textContent.trim())");
  assert.equal(tabs.length, 1, `one tab, not ${JSON.stringify(tabs)}`);

  // Ctrl+K through WebDriver's key actions.
  await wd("POST", s("/actions"), {
    actions: [
      {
        type: "key",
        id: "keyboard",
        actions: [
          { type: "keyDown", value: "\uE009" },
          { type: "keyDown", value: "k" },
          { type: "keyUp", value: "k" },
          { type: "keyUp", value: "\uE009" },
        ],
      },
    ],
  });
  await wd("DELETE", s("/actions"));
  const [input] = await until("the palette", async () => {
    const found = await find("[cmdk-input]");
    return found.length ? found : null;
  }, 5000);
  const all = await until("the palette's items", async () => {
    const items = await find("[cmdk-item]");
    return items.length > 6 ? items : null; // BeeZip's actions, then the registry's commands
  }, 5000);
  log(`the palette offers ${all.length} items`);

  await wd("POST", s(`/element/${input}/value`), { text: "app.version" });
  const left = await until("the filtered list", async () => {
    const items = await find("[cmdk-item]");
    return items.length && items.length < all.length ? items : null;
  }, 5000);
  const offered = [];
  for (const item of left) offered.push((await text(item)).replace(/\s+/g, " "));
  log("after typing app.version:", offered.join(" | "));
  assert.ok(offered.some((t) => t.startsWith("app.version")), "app.version isn't offered");

  await wd("POST", s(`/element/${input}/value`), { text: "\uE00C" }); // Escape
  await until("the palette to close", async () => (await find("[cmdk-input]")).length === 0, 5000);
  log("the palette closed");
} catch (e) {
  failed = true;
  console.error("FAIL:", e.message);
  if (sid) {
    try {
      console.error("page text:", JSON.stringify((await exec("return document.body.innerText")).slice(0, 800)));
    } catch (e2) {
      console.error("no page text:", e2.message);
    }
  }
} finally {
  if (sid) {
    try {
      await wd("DELETE", `/session/${sid}`);
      log("session deleted");
    } catch (e) {
      console.error("deleting the session:", e.message);
    }
  }
}
log(failed ? "FAILED" : "PASSED");
process.exit(failed ? 1 : 0);
