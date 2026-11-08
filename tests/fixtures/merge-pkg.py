"""Merges make-pkg.yml's artifact into the fixtures (docs/M6.md §10).

    gh run download <run> -n pkg-fixtures -D <dir>
    python -I tests/fixtures/merge-pkg.py <dir> <run>

The packages go to thirdparty/pkg/macos/, and their records replace every `pkg/macos/` record in
manifest.json, where they were (at its end the first time); make-xar.sh owns the rest of `pkg/`.
Each record's entries are the package as BeeZip lists it (docs/M6.md §5), from the artifact's
pkg-manifest.json: `pkgutil --expand-full`'s layout, where a Payload or Scripts of cpio (gzip'd
or pbzx) is a folder of its contents, but an Apple Archive one (or any other BeeZip doesn't
expand) stays one file, as `pkgutil --expand` leaves it. Files have no `mtime`. Each record gains
the run's id and what `7z t` (7-Zip 26.00) says of the package. The manifest's record count
changes: crates/beezip-core/tests/fixtures.rs asserts it, and this prints the new one.

--fixtures DIR writes to another copy of tests/fixtures (DIR/manifest.json and
DIR/thirdparty/pkg/macos/), as the script's own test does.
"""

import json
import os
import re
import shutil
import subprocess
import sys

SEVEN = r"C:\Program Files\7-Zip\7z.exe"
REPO = "https://github.com/JoshClose/BeeZip"
CPIO = ("cpio (odc)", "cpio (newc)")


def seven_t(path):
    """What `7z t` said, as make-7z.sh records it."""
    r = subprocess.run([SEVEN, "t", "-sccUTF-8", path], capture_output=True)
    lines = [l.strip() for l in (r.stdout + r.stderr).decode("utf-8", "backslashreplace").splitlines()]
    if any(re.match(r"^(Open ERROR: )?Can(no|')t open the file as (\[\w+\] )?archive$", l) for l in lines):
        return "can't open it"
    msgs = []
    for l in lines:
        l = re.sub(r"^(ERROR|Open ERROR|WARNING):\s*", "", l.replace(path, "")).strip()
        if re.search(r"(Error|There are (some )?data after|Unexpected end|Unsupported Method|CRC Failed|Is not archive)", l) \
                and not re.match(r"^(ERRORS?:|Archives with Errors|Sub items Errors|Open Errors)", l) and l not in msgs:
            msgs.append(l)
    if r.returncode == 0 and not msgs:
        return "ok"
    return ("ok, with warnings: " if r.returncode == 0 else "errors: ") + "; ".join(msgs)


def layout(p):
    """The package as BeeZip lists it, and what each Payload and Scripts is."""
    full, flat, members = p["full"], p["flat"], p["members"]
    kept = sorted(rel for rel, m in members.items() if m["inner"] not in CPIO)
    under = lambda path: any(path == k or path.startswith(k + "/") for k in kept)
    order = lambda path: (path.count("/"), path)
    files = {path: v for path, v in full["files"].items() if not under(path)}
    for k in kept:
        files[k] = flat["files"][k]
    for rel in members:
        if rel not in kept and rel in full["files"]:
            raise SystemExit(f"{p['file']}: pkgutil --expand-full left {rel} as a file")
    entries = [{"path": path, "kind": "file", "size": v["size"], "sha256": v["sha256"]} for path, v in sorted(files.items(), key=lambda x: order(x[0]))]
    links = {path: t for path, t in full["links"].items() if not under(path)}
    entries += [{"path": path, "kind": "symlink", "target": t} for path, t in sorted(links.items(), key=lambda x: order(x[0]))]
    entries += [{"path": path, "kind": "folder"} for path in full["empty"] if not under(path)]
    what = []
    for rel, m in sorted(members.items()):
        wrap = {"none": "", "gzip": "gzip'd ", "pbzx": "pbzx "}.get(m["wrapping"], m["wrapping"] + " ")
        what.append(f"{rel} is {wrap}{m['inner']}" + ("" if rel not in kept else " (kept as one file)"))
    return entries, len(links), what


def main():
    args = sys.argv[1:]
    here = os.path.dirname(os.path.abspath(__file__))
    if "--fixtures" in args:
        i = args.index("--fixtures")
        here = os.path.abspath(args[i + 1])
        del args[i:i + 2]
    src, run = args
    out = os.path.join(here, "thirdparty", "pkg", "macos")
    m = json.load(open(os.path.join(src, "pkg-manifest.json"), encoding="utf-8"))
    tools = open(os.path.join(src, "tools.txt"), encoding="utf-8").read() if os.path.exists(os.path.join(src, "tools.txt")) else ""
    version = re.search(r"ProductVersion:\s*(\S+)", tools)
    macos = f"macOS {version.group(1)}" if version else m.get("platform", "macOS")
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        if f.endswith(".pkg"):
            os.remove(os.path.join(out, f))
    records, rows = [], []
    for p in m["packages"]:
        name = p["file"]
        if p["full"] is None:
            print(f"{name}: left out, pkgutil --expand-full couldn't expand it (tools.txt says why)")
            continue
        dest = os.path.join(out, name)
        shutil.copyfile(os.path.join(src, "pkg", name), dest)
        entries, symlinks, what = layout(p)
        tool = "productbuild" if p["command"].startswith("productbuild") else "pkgbuild"
        records.append({
            "file": f"pkg/macos/{name}",
            "producer": f"{tool} ({macos}), make-pkg.yml run {run} ({REPO}/actions/runs/{run})",
            "command": p["command"],
            "chain": "pkg",
            "password": None,
            "utc_mtimes": False,
            "hardlinks": 0,
            "symlinks": symlinks,
            "note": ("Entries are the package as BeeZip lists it: `pkgutil --expand-full`'s layout on the Mac that made "
                     "it, where a Payload or Scripts of cpio is a folder of its contents, but an Apple Archive one stays "
                     "one file, as `pkgutil --expand` leaves it (BeeZip doesn't expand Apple Archive, docs/M6.md §5). "
                     "Files have no `mtime`. " + "; ".join(what) + "."),
            "7z_test": seven_t(dest),
            "entries": entries,
        })
        rows.append(f"| `{name}` | {os.path.getsize(dest)} | `{p['command']}` | {'; '.join(what)} |")
    lines = ["# macOS package fixtures, made on a Mac", "",
             f"Made by pkgbuild and productbuild on GitHub's macos-latest ({macos}), `make-pkg.yml` run {run}",
             f"({REPO}/actions/runs/{run}), from BeeZip's fixture tree (`tests/fixtures/make-pkg.sh` says",
             "what it holds). `merge-pkg.py` writes this folder and the `pkg/macos/` records in `manifest.json`.",
             "The packages aren't signed.", "",
             "| File | Bytes | Command | Payload and Scripts |", "|---|---|---|---|"] + rows
    with open(os.path.join(out, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    path = os.path.join(here, "manifest.json")
    manifest = json.load(open(path, encoding="utf-8"))
    old = manifest["fixtures"]
    mine = lambda r: r["file"].startswith("pkg/macos/")
    # The new records go where the old ones were, so a rerun leaves the order alone.
    at = next((i for i, r in enumerate(old) if mine(r)), len(old))
    manifest["fixtures"] = old[:at] + records + [r for r in old[at:] if not mine(r)]
    if "merge-pkg.py" not in manifest["note"]:
        manifest["note"] = manifest["note"].replace(" and make-xar.sh", ", make-xar.sh and merge-pkg.py")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(manifest, indent=2, ensure_ascii=False))
    for r in records:
        print(f"{r['file']}: {len(r['entries'])} entries; 7z t {r['7z_test']}")
    print(f"{len(records)} records; the manifest now has {len(manifest['fixtures'])}: set that in "
          "crates/beezip-core/tests/fixtures.rs")


if __name__ == "__main__":
    main()
