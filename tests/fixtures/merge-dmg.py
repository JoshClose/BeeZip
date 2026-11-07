"""Merges make-dmg.yml's artifact into the fixtures (docs/M5.md §10).

    gh run download <run> -n dmg-fixtures -D <dir>
    python -I tests/fixtures/merge-dmg.py <dir> <run>

The images go to thirdparty/dmg/ (or thirdparty/dmg/broken/, for those listed in BROKEN, which
aren't in the manifest), and their records from dmg-manifest.json replace every `dmg/` record in
manifest.json, where they were (at its end the first time). Each record gains the run's id, what `7z t` (7-Zip 26.00) says of
the image, and the counts BeeZip's listing has: HFS+ and APFS hard links are listed as files
holding their data, so `hardlinks` is 0. Entries keep their path, kind, size, SHA-256 or target,
and the decmpfs type of an Apple-compressed file.
"""

import json
import os
import shutil
import subprocess
import sys

SEVEN = r"C:\Program Files\7-Zip\7z.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "thirdparty", "dmg")
REPO = "https://github.com/JoshClose/BeeZip"
# Images BeeZip reads only in part, with why; the broken/README.md says so.
BROKEN = {
    "apfs-decmpfs-udzo.dmg": (
        "UnsupportedOperation",
        "APFS files compressed into a resource fork (decmpfs types 4, 8 and 12) can't be read: "
        "fstool 0.5.2 doesn't reach APFS resource forks. The image lists, and its other files "
        "(the inline types 3, 7 and 11, and the plain ones) extract.",
    ),
}


def seven_t(path):
    r = subprocess.run([SEVEN, "t", "-sccUTF-8", path], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if "Can't open the file as archive" in r.stdout + r.stderr:
        return "can't open it"
    errors = [l.strip() for l in (r.stdout + r.stderr).splitlines()
              if "Error" in l and not l.startswith(("Archives with Errors", "Sub items Errors"))]
    if r.returncode == 0 and not errors:
        return "ok"
    return ("ok, with warnings: " if r.returncode == 0 else "errors: ") + "; ".join(dict.fromkeys(errors))


def entry(e):
    out = {"path": e["path"], "kind": e["kind"]}
    if e["kind"] == "symlink":
        out["target"] = e["target"]
    else:
        out["size"] = e["size"]
        out["sha256"] = e["sha256"]
    if e.get("decmpfs"):
        out["decmpfs"] = e["decmpfs"]["type"]
    return out


def main():
    src, run = sys.argv[1], sys.argv[2]
    frag = json.load(open(os.path.join(src, "dmg-manifest.json"), encoding="utf-8"))["fixtures"]
    for d in (OUT, os.path.join(OUT, "broken")):
        os.makedirs(d, exist_ok=True)
        for f in os.listdir(d):
            if f.endswith(".dmg"):
                os.remove(os.path.join(d, f))
    records = []
    for r in frag:
        name = os.path.basename(r["file"])
        broken = name in BROKEN
        dest = os.path.join(OUT, "broken" if broken else "", name)
        shutil.copyfile(os.path.join(src, "dmg", name), dest)
        if broken:
            continue
        records.append({
            "file": f"dmg/{name}",
            "producer": f"{r['producer']}, make-dmg.yml run {run} ({REPO}/actions/runs/{run})",
            "command": r["command"],
            "chain": "dmg",
            "password": None,
            "utc_mtimes": r["utc_mtimes"],
            "hardlinks": 0,
            "symlinks": r["symlinks"],
            "filesystem": r["filesystem"],
            "note": r["note"] + " Hard links are listed as files with their data, as fstool reads them.",
            "7z_test": seven_t(dest),
            "entries": [entry(e) for e in r["entries"]],
        })
    lines = ["# Broken DMG fixtures", "",
             f"Made by hdiutil on GitHub's macos-latest (make-dmg.yml run {run}). They aren't in",
             "manifest.json: each must fail as below. merge-dmg.py writes this file.", "",
             "| File | Expected | Why |", "|---|---|---|"]
    for name, (want, why) in BROKEN.items():
        lines.append(f"| `{name}` | {want} | {why} |")
    with open(os.path.join(OUT, "broken", "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    path = os.path.join(HERE, "manifest.json")
    manifest = json.load(open(path, encoding="utf-8"))
    old = manifest["fixtures"]
    mine = lambda r: r["file"].startswith("dmg/")
    # The new records go where the old ones were, so a rerun leaves the order alone.
    at = next((i for i, r in enumerate(old) if mine(r)), len(old))
    manifest["fixtures"] = old[:at] + records + [r for r in old[at:] if not mine(r)]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"{len(records)} records, {len(BROKEN)} broken")


if __name__ == "__main__":
    main()
