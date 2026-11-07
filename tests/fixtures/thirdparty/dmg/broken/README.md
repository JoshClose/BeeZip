# Broken DMG fixtures

Made by hdiutil on GitHub's macos-latest (make-dmg.yml run 42362026482). They aren't in
manifest.json: each must fail as below. merge-dmg.py writes this file.

| File | Expected | Why |
|---|---|---|
| `apfs-decmpfs-udzo.dmg` | UnsupportedOperation | APFS files compressed into a resource fork (decmpfs types 4, 8 and 12) can't be read: fstool 0.5.2 doesn't reach APFS resource forks. The image lists, and its other files (the inline types 3, 7 and 11, and the plain ones) extract. |
