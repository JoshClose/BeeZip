# unarc-rs test archives

From unarc-rs 0.8.1 (https://github.com/mkrueger/unarc-rs, the crate's `tests/` folder), MIT OR
Apache-2.0: LICENSE-MIT and LICENSE-APACHE here. The crate ships only the Apache text; the MIT
text names its author, Mike Krüger. BeeZip reads ARJ, ACE and ZOO with code taken in from
unarc-rs (docs/M6.md §4); these are its samples, copied unchanged, the PAK ones in `arc/`, the
volume sets beside the rest. `broken/` holds the ones whose CRCs are wrong on purpose.
`make-retro.sh` writes this file and their records in `manifest.json`, from what arj, zoo, arc
and acefile extract (checked against each entry's CRC, unar 1.10.1 and an ARC decoder in the
script); unarc-rs's tests compare most of them with its LICENSE, the Apache-2.0 text.

Seven files aren't in the manifest, but in `broken_fixtures_fail_as_they_should`: the three in
`broken/`, `zoo/high_per.zoo` and `zoo/store.zoo` (whose file is `../license`), and the PAK
archives in methods BeeZip refuses (`arc/license.pak`, `arc/license_crushed.pak`).

| File | Made by | What it holds |
|---|---|---|
| `arj/stored.arj` | ARJ 3.10 on Unix (method 0) | `LICENSE` |
| `arj/method1.arj` | ARJ 3.10 on Unix (method 1) | `LICENSE` |
| `arj/method2.arj` | ARJ 3.10 on Unix (method 2) | `LICENSE` |
| `arj/method3.arj` | ARJ 3.10 on Unix (method 3) | `LICENSE` |
| `arj/method4.arj` | ARJ 3.10 on Unix (method 4) | `LICENSE` |
| `arj/license_crypted.arj` | ARJ on MS-DOS (method 1, garbled) | `LICENSE` (password `secret`) |
| `arj/test_file.arj` | ARJ on MS-DOS (method 1, three volumes) | `TEST.ICY` |
| `ace/license1.ace` | ACE 2.0 for Win32, ACE 1.0 methods | `LICENSE` |
| `ace/license2.ace` | ACE 2.0 for Win32, ACE 2.0 methods | `LICENSE` |
| `ace/unarc.ace` | ACE for MS-DOS (three volumes) | `UNARC` |
| `zoo/default.zoo` | zoo (LZW) | `license` |
| `zoo/high_per.zoo` | zoo (LH5) | `../license`: its folder is stored as `..`. In the broken list, not the manifest: it lists and tests, and extraction must refuse it (Unsafe). zoo writes it to ../license. |
| `zoo/store.zoo` | zoo (stored) | `../license`: its folder is stored as `..`. In the broken list, not the manifest: it lists and tests, and extraction must refuse it (Unsafe). zoo writes it to ../license. |
| `arc/cpm.arc` | ARC (CP/M programs, squeezed and packed) | `DDTZ.COM`; `READ.COM` |
| `arc/crunch.arc` | ARC (crunched) | `LICENSE` |
| `arc/crunch2.arc` | ARC (crunched) | `LICENSE` |
| `arc/crunch_clear.arc` | ARC 5.21q `arc aw` (crunched, the table cleared) | `SHIFT1.TXT` |
| `arc/squashed.arc` | ARC (squashed) | `LICENSE` |
| `arc/squash_clear.arc` | ARC 5.21q `arc awq` (squashed, the table full) | `SHIFT1.TXT` |
| `arc/store.arc` | ARC (stored) | `LICENSE` |
| `arc/license_cypted.arc` | ARC (crunched, encrypted) | `LICENSE` (password `SECRET`) |
| `arc/license_crunched.pak` | PAK (crunched) | `LICENSE` |
| `arc/license_squashed.pak` | PAK (squashed) | `LICENSE` |
| `arc/license.pak` | PAK (distilled) | `LICENSE`, distilled, a PAK method BeeZip refuses (docs/M6.md §4.1). In the broken list, not the manifest: it lists, and reading LICENSE must fail as unsupported. |
| `arc/license_crushed.pak` | PAK (crushed) | `LICENSE`, crushed, a PAK method BeeZip refuses (docs/M6.md §4.1). In the broken list, not the manifest: it lists, and reading LICENSE must fail as unsupported. |
| `broken/wrongcrc32.arj` | unarc-rs's tests | stored.arj with a wrong CRC-32: testing it must fail (Corrupt). |
| `broken/wrongcrc16.zoo` | unarc-rs's tests | store.zoo with a wrong CRC-16: testing it must fail (Corrupt). |
| `broken/wrongcrc16.arc` | unarc-rs's tests | store.arc with a wrong CRC-16: testing it must fail (Corrupt). |
