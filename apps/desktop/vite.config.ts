import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
// @ts-expect-error type error without @types/node package
import fs from "node:fs";
// @ts-expect-error type error without @types/node package
import path from "node:path";
// @ts-expect-error type error without @types/node package
import process from "node:process";
const host = process.env.TAURI_DEV_HOST;

// The licenses an npm package in the bundle may be under (docs/M6.md §9.1).
const LICENSES = ["MIT", "ISC", "Apache-2.0", "0BSD", "BSD-2-Clause", "BSD-3-Clause"];

// An SPDX expression BeeZip can take: one of LICENSES among `A OR B`, all of them in `A AND B`.
function licenseOk(expr: unknown): boolean {
  if (typeof expr !== "string") return false;
  const ids = expr.replace(/[()]/g, " ").split(/\s+/).filter((t) => t && t !== "OR" && t !== "AND");
  return / AND /.test(expr) ? ids.every((id) => LICENSES.includes(id)) : ids.some((id) => LICENSES.includes(id));
}

// Lists the npm packages whose code is in the bundle, with their license files, for
// `cargo xtask notices`: every package a chunk has modules from, plus tailwindcss, whose code is
// generated into the CSS. Fails the build on a license outside LICENSES.
function bundledPackages(): Plugin {
  let root = "";
  return {
    name: "beezip-bundled-packages",
    apply: "build",
    configResolved(config) {
      root = config.root;
    },
    generateBundle(_options, bundle) {
      const dirs = new Set([path.join(root, "node_modules", "tailwindcss")]);
      for (const chunk of Object.values(bundle)) {
        for (const id of chunk.type === "chunk" ? Object.keys(chunk.modules) : []) {
          const p = id.replace(/\\/g, "/");
          const at = p.lastIndexOf("/node_modules/");
          if (at < 0) continue;
          const [scope, name] = p.slice(at + "/node_modules/".length).split("/");
          dirs.add(p.slice(0, at) + "/node_modules/" + (scope.startsWith("@") ? `${scope}/${name}` : scope));
        }
      }
      const list = new Map<string, object>();
      for (const dir of dirs) {
        const pj = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
        if (!licenseOk(pj.license)) this.error(`${pj.name}@${pj.version} is under ${pj.license}, not one of ${LICENSES.join(", ")} (docs/M6.md §9.1)`);
        const files = fs.readdirSync(dir).filter((f: string) => /^(licen[cs]e|copying)/i.test(f) && !/\.spdx$/i.test(f)).sort();
        const licenseFiles = Object.fromEntries(files.map((f: string) => [f, fs.readFileSync(path.join(dir, f), "utf8")]));
        list.set(`${pj.name}@${pj.version}`, { name: pj.name, version: pj.version, license: pj.license, licenseFiles });
      }
      const out = path.resolve(root, "../../target/notices/npm-packages.json");
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, JSON.stringify([...list.keys()].sort().map((k) => list.get(k)), null, 2) + "\n");
    },
  };
}

// https://vite.dev/config/
export default defineConfig(() => ({
  plugins: [react(), tailwindcss(), bundledPackages()],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
    // The About page imports THIRD_PARTY_NOTICES.md from the repository root.
    fs: { allow: ["../.."] },
  },
}));
