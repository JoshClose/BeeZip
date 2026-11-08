# macOS package fixtures, made on a Mac

Made by pkgbuild and productbuild on GitHub's macos-latest (macOS 26.7.2), `make-pkg.yml` run 42443319495
(https://github.com/JoshClose/BeeZip/actions/runs/42443319495), from BeeZip's fixture tree (`tests/fixtures/make-pkg.sh` says
what it holds). `merge-pkg.py` writes this folder and the `pkg/macos/` records in `manifest.json`.
The packages aren't signed.

| File | Bytes | Command | Payload and Scripts |
|---|---|---|---|
| `component-large.pkg` | 7266 | `pkgbuild --root tree --identifier org.beezip.fixture --version 1.0 --install-location /usr/local/beezip-fixture --scripts scripts --compression latest --min-os-version 12.0 --large-payload component-large.pkg` | LargeSegmentedPayload is pbzx cpio (odc) |
| `component-latest.pkg` | 7241 | `pkgbuild --root tree --identifier org.beezip.fixture --version 1.0 --install-location /usr/local/beezip-fixture --scripts scripts --compression latest --min-os-version 12.0 component-latest.pkg` | Payload is pbzx cpio (odc) |
| `component-legacy.pkg` | 7472 | `pkgbuild --root tree --identifier org.beezip.fixture --version 1.0 --install-location /usr/local/beezip-fixture --scripts scripts --compression legacy component-legacy.pkg` | Payload is gzip'd cpio (odc) |
| `component.pkg` | 7467 | `pkgbuild --root tree --identifier org.beezip.fixture --version 1.0 --install-location /usr/local/beezip-fixture --scripts scripts component.pkg` | Payload is gzip'd cpio (odc) |
| `product-large.pkg` | 7857 | `productbuild --package component-large.pkg product-large.pkg` | component-large.pkg/LargeSegmentedPayload is pbzx cpio (odc) |
| `product-latest.pkg` | 7834 | `productbuild --package component-latest.pkg product-latest.pkg` | component-latest.pkg/Payload is pbzx cpio (odc) |
| `product.pkg` | 8006 | `productbuild --package component.pkg product.pkg` | component.pkg/Payload is gzip'd cpio (odc) |
