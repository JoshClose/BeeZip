# MSI fixtures

Windows Installer files BeeZip reads itself (docs/M8.md §7, docs/M11.md §8). `make-msi-extras.ps1`
makes all but `span-small.msi` and writes their records in `manifest.json`; it runs on Windows,
with msi.dll, makecab.exe, the Windows SDK's MsiTran.exe and MsiMsp.exe, wixl in the fixtures
image and 7-Zip for the records. These tools write GUIDs and times, so the files differ on every
run: the records come from the run that made the committed files.

| File | Made by | What it is |
|---|---|---|
| `span-small.msi` | the M8 CAB spike's `mkmsi` (msi crate) and makecab | a cabinet folder running on from one embedded cabinet into the next (`tests/msi.rs`) |
| `module.msm` | msi.dll, makecab (MSZIP) | a merge module: no Media table, its files in `MergeModule.CABinet`, at the merge point and in modularized and standard folders, short and long names, a Latin-1 name, two files at one path, MsiFileHash rows, a custom action |
| `module-lzx.msm` | the same, LZX:21 | |
| `patch.msp` | MsiMsp.exe (patchwiz.dll) | a patch from version 1 of a small wixl product to version 2: a delta, two whole files, both transforms, its cabinet, MsiPatchMetadata |
| `v1-to-v2.mst` | MsiTran.exe -g | the transform from version 1 to 2 |
| `v2-to-v1.mst` | msi.dll's GenerateTransform | back again, with a summary from CreateTransformSummaryInfo |

A merge module's record is where BeeZip lists each file and the bytes it was made from; a patch's
or transform's is what 7-Zip 26.00 extracts, under its names, with `.cab` added to the cabinet's.
