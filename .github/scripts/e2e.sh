#!/usr/bin/env bash
# The end-to-end smoke test on Linux (docs/M6.md §10), e2e.ps1's twin: tauri-driver 2.1.0 with
# WebKitWebDriver (webkit2gtk-driver), then tests/e2e/smoke.mjs against beezip-desktop, under Xvfb
# and a D-Bus session of their own (the single-instance plugin hands the second launch's archive
# over D-Bus), with a scratch config and HOME.
#
#   bash .github/scripts/e2e.sh [beezip-desktop]
#
# The default is what `cargo xtask dist --debug` built, target/dist/debug/beezip-desktop; the
# bundle job passes the installed /usr/bin/beezip-desktop. Everything runs in a session of its
# own (setsid), and only that session's process group is stopped afterwards, never anything by
# name. On a failure it prints tauri-driver's log, which has WebKitWebDriver's and BeeZip's output.
set -euo pipefail
fail() { echo "::error::$1"; exit 1; }

root=$(cd "$(dirname "$0")/../.." && pwd)
exe=${1:-$root/target/dist/debug/beezip-desktop}
archive=$root/tests/fixtures/thirdparty/7z-deflate.zip
[ -x "$exe" ] || fail "$exe is missing"
[ -f "$archive" ] || fail "$archive is missing"
command -v tauri-driver >/dev/null || fail 'tauri-driver is missing (cargo install --locked tauri-driver --version 2.1.0)'
command -v WebKitWebDriver >/dev/null || fail 'WebKitWebDriver is missing (apt-get install webkit2gtk-driver)'
for tool in xvfb-run dbus-run-session node curl setsid; do
  command -v "$tool" >/dev/null || fail "$tool is missing"
done

work=$(mktemp -d "${RUNNER_TEMP:-/tmp}/beezip-e2e.XXXXXX")
# The app's surroundings: a config that never looks for updates, and a home of its own.
printf '[updates]\ncheck = false\n' > "$work/config.toml"
mkdir -p "$work/home"
export BEEZIP_CONFIG=$work/config.toml HOME=$work/home
export XDG_CONFIG_HOME=$work/home/.config XDG_DATA_HOME=$work/home/.local/share \
  XDG_CACHE_HOME=$work/home/.cache XDG_STATE_HOME=$work/home/.local/state
export WEBKIT_DISABLE_DMABUF_RENDERER=1   # no GPU: WebKitGTK's DMA-BUF renderer shows nothing
port=4444
export WD_URL=http://127.0.0.1:$port

# Inside Xvfb and the D-Bus session: tauri-driver, then the test. The first line records the
# session's process group, which is all this script ever stops.
cat > "$work/inner.sh" <<'EOF'
set -u
exe=$1 archive=$2 work=$3 root=$4 port=$5
ps -o pgid= -p $$ | tr -d ' ' > "$work/pgid"
tauri-driver --port "$port" --native-port $((port + 1)) > "$work/tauri-driver.log" 2>&1 &
td=$!
up=
for _ in $(seq 1 150); do
  curl -fs -m 1 "http://127.0.0.1:$port/status" > /dev/null && { up=1; break; }
  kill -0 $td 2> /dev/null || { echo "tauri-driver exited"; exit 1; }
  sleep 0.2
done
[ -n "$up" ] || { echo "tauri-driver never answered on port $port"; exit 1; }
timeout 120 node "$root/tests/e2e/smoke.mjs" "$exe" "$archive" tree
code=$?
kill -TERM $td 2> /dev/null
wait $td 2> /dev/null
exit $code
EOF

# What's left of the session (Xvfb on its way out, a BeeZip the test didn't close): TERM, up to
# 5 s to go, then KILL.
stop() {
  [ -s "$work/pgid" ] || return 0
  local group
  group=$(cat "$work/pgid")
  kill -TERM -- "-$group" 2> /dev/null || return 0
  for _ in $(seq 1 25); do
    kill -0 -- "-$group" 2> /dev/null || return 0
    sleep 0.2
  done
  echo "still running after TERM:"
  ps -o pid,args -g "$group" || true
  kill -KILL -- "-$group" 2> /dev/null || true
}
trap stop EXIT

code=0
setsid -w xvfb-run -a -s "-screen 0 1280x800x24" \
  dbus-run-session -- bash "$work/inner.sh" "$exe" "$archive" "$work" "$root" "$port" || code=$?
if [ "$code" -ne 0 ]; then
  echo "tauri-driver said (last 80 lines):"
  tail -n 80 "$work/tauri-driver.log" 2> /dev/null || echo "(no log)"
  fail "the smoke test failed: exit $code (its files: $work)"
fi
stop
rm -rf "$work"
