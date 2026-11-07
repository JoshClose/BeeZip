# Broken fixtures

Made by make-linux.sh. They aren't in manifest.json: each must fail as below, without a panic, a
hang or a large allocation.

| File | Expected | Why |
|---|---|---|
| `ar-thin.a` | UnsupportedFormat | A GNU thin archive (`ar rcT`): it starts `!<thin>` and its members are names of other files, not data. |
