#!/usr/bin/env bash
# The Linux bundles that `cargo xtask dist` built (docs/M6.md §9.7), checked on the CI runner:
#
#   bash .github/scripts/linux-bundle.sh <step> [debug|release]     (the profile defaults to debug)
#
#   check    what's in the deb, the rpm and the AppImage: the package's name and dependencies,
#            the CLI, the desktop entry (desktop-file-validate, `%F`), the MIME package
#            (update-mime-database takes it), the notices, the files' modes;
#   install  `apt-get install` of the deb; `beezip --version`; the MIME database types BeeZip's
#            files as its desktop entry expects (gio, through xdg-mime), and the desktop database
#            offers BeeZip for every type it claims;
#   e2e      the end-to-end test against the installed /usr/bin/beezip-desktop (e2e.sh);
#   remove   `apt-get remove`, and nothing of BeeZip's left in /usr or the databases;
#   all      the four in that order.
#
# Needs (apt): desktop-file-utils, shared-mime-info, xdg-utils, libglib2.0-bin, rpm, file; for
# e2e also webkit2gtk-driver, xvfb, dbus, and tauri-driver 2.1.0. `install` and `remove` use
# sudo unless run as root.
set -euo pipefail
fail() { echo "::error::$1"; exit 1; }

root=$(cd "$(dirname "$0")/../.." && pwd)
step=${1:-all}
profile=${2:-debug}
bundle=$root/target/dist/$profile/bundle
sudo=sudo
[ "$(id -u)" = 0 ] && sudo=

# The one bundle matching a pattern, into $found.
one() {
  local matches=("$bundle"/$1)
  [ ${#matches[@]} = 1 ] && [ -f "${matches[0]}" ] || fail "want one $bundle/$1, found: ${matches[*]}"
  found=${matches[0]}
}

# The installed files, beside the app and the CLI, and their modes in the packages.
FILES=(
  "-rwxr-xr-x /usr/bin/beezip-desktop"
  "-rwxr-xr-x /usr/bin/beezip"
  "-rw-r--r-- /usr/share/applications/beezip.desktop"
  "-rw-r--r-- /usr/share/mime/packages/beezip.xml"
  "-rw-r--r-- /usr/share/doc/beezip/THIRD_PARTY_NOTICES.md"
)

# The desktop entry's MIME types, one a line.
claimed() { sed -n 's/^MimeType=//p' "$1" | tr ';' '\n' | sed '/^$/d'; }

# Whether a listing ($1, from dpkg-deb -c or rpm -qplv) has each of FILES with its mode. The
# paths there may start with `./`, `/` or neither.
has_files() {
  local listing=$1 what=$2 f mode path
  for f in "${FILES[@]}"; do
    mode=${f%% *} path=${f#* }
    awk -v m="$mode" -v p="${path#/}" '{ q = $NF; sub(/^\.?\//, "", q) } $1 == m && q == p { found = 1 } END { exit !found }' <<< "$listing" ||
      fail "the $what has no $path with mode $mode: $(grep -F "${path#/}" <<< "$listing" || echo none)"
  done
}

check() {
  local deb rpm app x
  one 'deb/beezip_*_amd64.deb'; deb=$found
  one 'rpm/beezip-*.x86_64.rpm'; rpm=$found
  one 'appimage/beezip_*_amd64.AppImage'; app=$found
  for f in "$deb" "$rpm" "$app"; do echo "$f: $(stat -c %s "$f") bytes"; done

  echo "== the deb"
  dpkg-deb -f "$deb"
  [ "$(dpkg-deb -f "$deb" Package)" = beezip ] || fail "the deb's package isn't beezip"
  local depends
  depends=$(dpkg-deb -f "$deb" Depends)
  for d in libwebkit2gtk-4.1-0 libgtk-3-0; do
    [[ ", $depends," == *", $d,"* ]] || fail "the deb doesn't depend on $d: $depends"
  done
  has_files "$(dpkg-deb -c "$deb")" deb

  x=$(mktemp -d)
  dpkg-deb -x "$deb" "$x"
  local desktop=$x/usr/share/applications/beezip.desktop types
  echo "== its desktop entry"
  cat "$desktop"
  desktop-file-validate "$desktop" || fail "desktop-file-validate refused the desktop entry"
  grep -qx 'Exec=beezip-desktop %F' "$desktop" || fail "the desktop entry's Exec doesn't pass the files (%F)"
  grep -qx 'Name=BeeZip' "$desktop" || fail "the desktop entry isn't named BeeZip"
  types=$(claimed "$desktop")
  [ "$(wc -l <<< "$types")" -gt 30 ] || fail "the desktop entry claims too few MIME types"
  [ -z "$(sort <<< "$types" | uniq -d)" ] || fail "the desktop entry claims a type twice"

  echo "== its MIME package, with shared-mime-info's own"
  local mime=$x/mime out
  mkdir -p "$mime/packages"
  cp /usr/share/mime/packages/freedesktop.org.xml "$x/usr/share/mime/packages/beezip.xml" "$mime/packages/"
  out=$(update-mime-database -V "$mime" 2>&1) || fail "update-mime-database failed: $out"
  if grep -iE 'warn|error|invalid' <<< "$out"; then fail "update-mime-database complained about beezip.xml"; fi
  for t in application/x-brotli application/x-snappy-framed application/x-cba; do
    grep -qxF "$t" "$mime/types" || fail "$t isn't in a MIME database built with beezip.xml"
  done
  for g in br sz cba zstd zlib sqfs squashfs arc mpkg; do
    grep -qE ":application/[^:]+:\*\.$g(:|$)" "$mime/globs2" || fail "no glob *.$g in a MIME database built with beezip.xml"
  done

  echo "== the rpm"
  rpm -qpi "$rpm"
  [ "$(rpm -qp --qf '%{NAME}' "$rpm")" = beezip ] || fail "the rpm's package isn't beezip"
  echo "requires:"; rpm -qpR "$rpm"
  local rpmlist
  rpmlist=$(rpm -qplv "$rpm")
  echo "$rpmlist"
  has_files "$rpmlist" rpm
  # Tauri's rpm doesn't own /usr/share/doc/beezip; its %postun removes it.
  grep -q 'rmdir /usr/share/doc/beezip' <<< "$(rpm -qp --scripts "$rpm")" ||
    fail "the rpm's %postun doesn't remove /usr/share/doc/beezip"

  echo "== the AppImage"
  [ -x "$app" ] || fail "the AppImage isn't executable"
  file "$app" | grep -q 'ELF 64-bit' || fail "the AppImage isn't an ELF executable: $(file "$app")"
  (cd "$x" && "$app" --appimage-extract > /dev/null) || fail "the AppImage doesn't extract"
  for f in usr/bin/beezip-desktop usr/bin/beezip usr/share/applications/beezip.desktop \
    usr/share/mime/packages/beezip.xml usr/share/doc/beezip/THIRD_PARTY_NOTICES.md; do
    [ -f "$x/squashfs-root/$f" ] || fail "the AppImage has no $f"
  done
  cmp -s "$x/squashfs-root/usr/share/applications/beezip.desktop" "$desktop" ||
    fail "the AppImage's desktop entry isn't the deb's"
  "$x/squashfs-root/usr/bin/beezip" --version || fail "the AppImage's CLI doesn't run"
  rm -rf "$x"
  echo "the bundles are as they should be"
}

# Fixtures under the names whose types matter, and the type each should get (`a|b`: shared-mime-info
# before 2.3 names bzip2 files differently). The content doesn't decide a type that a single glob
# names; a file must only not be empty (that's x-zerosize).
TYPES=(
  "thirdparty/7z-deflate.zip x.zip application/zip"
  "thirdparty/7z-deflate.7z x.7z application/x-7z-compressed"
  "thirdparty/bsdtar.tar.gz x.tar.gz application/x-compressed-tar"
  "thirdparty/bsdtar.tar.gz x.tgz application/x-compressed-tar"
  "thirdparty/bsdtar.tar.gz x.bz2 application/x-bzip2|application/x-bzip"
  "thirdparty/bsdtar.tar.gz x.tar.bz2 application/x-bzip2-compressed-tar|application/x-bzip-compressed-tar"
  "thirdparty/bsdtar.tar.zst x.tar.zst application/x-zstd-compressed-tar"
  "thirdparty/bsdtar.tar.zst x.zstd application/zstd"
  "thirdparty/bsdtar.tar.zst x.tlz application/x-lzma-compressed-tar"
  "thirdparty/bsdtar.tar.zst x.tar.lz application/x-lzip-compressed-tar"
  "thirdparty/bsdtar.tar.zst x.br application/x-brotli"
  "thirdparty/bsdtar.tar.zst x.sz application/x-snappy-framed"
  "thirdparty/bsdtar.tar.zst x.cba application/x-cba"
  "malicious/traversal.squashfs x.sqfs application/vnd.squashfs"
  "thirdparty/arc/crunched.arc x.arc application/x-arc"
  "malicious/traversal.xar x.mpkg application/x-xar"
  "malicious/traversal.lzh x.LZH application/x-lha"
)

install() {
  local deb
  one 'deb/beezip_*_amd64.deb'; deb=$found
  $sudo apt-get install -y -q "$deb"
  dpkg-query -W -f '${Package} ${Version} ${Status}\n' beezip
  [ "$(command -v beezip)" = /usr/bin/beezip ] || fail "beezip isn't /usr/bin/beezip"
  beezip --version || fail "beezip --version failed"
  [ -x /usr/bin/beezip-desktop ] || fail "no /usr/bin/beezip-desktop"

  echo "== the MIME database (gio, through xdg-mime) and the desktop database"
  local desktop=/usr/share/applications/beezip.desktop d types from name want got t line
  types=$(claimed "$desktop")
  d=$(mktemp -d)
  for t in "${TYPES[@]}"; do
    read -r from name want <<< "$t"
    cp "$root/tests/fixtures/$from" "$d/$name"
    # xdg-mime asks gio, which reads shared-mime-info, only on GNOME; elsewhere it asks `file`.
    got=$(XDG_CURRENT_DESKTOP=GNOME xdg-mime query filetype "$d/$name")
    echo "$name: $got"
    [[ "|$want|" == *"|$got|"* ]] || fail "$name is $got, not $want"
    grep -qxF "$got" <<< "$types" || fail "BeeZip's desktop entry doesn't claim $got ($name)"
  done
  rm -rf "$d"
  for t in $types; do
    line=$(awk -F= -v t="$t" '$1 == t' /usr/share/applications/mimeinfo.cache)
    [[ "$line" == *beezip.desktop* ]] || fail "the desktop database doesn't offer BeeZip for $t: ${line:-nothing}"
  done
  echo "the desktop database offers BeeZip for all $(wc -l <<< "$types") of its types"
  echo "xdg-mime's default for application/zip: $(xdg-mime query default application/zip)"
}

remove() {
  $sudo apt-get remove -y -q beezip
  [ "$(dpkg-query -W -f '${Status}' beezip 2> /dev/null || true)" != "install ok installed" ] ||
    fail "beezip is still installed"
  local f path
  for f in "${FILES[@]}"; do
    path=${f#* }
    [ ! -e "$path" ] || fail "$path is still there"
  done
  [ ! -e /usr/share/doc/beezip ] || fail "/usr/share/doc/beezip is still there"
  ! grep -qF 'beezip.desktop' /usr/share/applications/mimeinfo.cache || fail "the desktop database still has BeeZip"
  ! grep -qxF 'application/x-brotli' /usr/share/mime/types || fail "the MIME database still has BeeZip's types"
  echo "removed, and nothing left"
}

case "$step" in
  check) check ;;
  install) install ;;
  e2e) bash "$root/.github/scripts/e2e.sh" /usr/bin/beezip-desktop ;;
  remove) remove ;;
  all)
    check
    install
    bash "$root/.github/scripts/e2e.sh" /usr/bin/beezip-desktop
    remove
    ;;
  *) fail "unknown step $step (check, install, e2e, remove or all)" ;;
esac
