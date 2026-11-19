#!/usr/bin/env bash
# End-to-end test of the self-updater on this system, against a local
# stand-in for GitHub Releases: a debug build of HappyIP updates itself to
# a pretend version 9.9.9, and must refuse a download whose checksum is wrong.
# Runs on macOS, Linux and Windows (Git Bash); CI runs it on all three.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --locked
PY=$(command -v python3 || command -v python)
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

T=$(mktemp -d)
SRV="$T/srv"
mkdir -p "$SRV/latest/download" "$SRV/download/v9.9.9" "$T/inst" "$T/home"
# (On Windows the stopped server can keep its folder busy for a moment;
# leftovers in the temp folder don't matter.)
trap 'kill "$SERVER" 2>/dev/null || true; rm -rf "$T" 2>/dev/null || true' EXIT

# A "new version": the same program with a few bytes added, so that it is a
# different file that still runs.
newer() { cp "$1" "$2"; printf 'happyip-update-test' >> "$2"; }

case "$(uname -s)" in
  Darwin)
    ASSET=HappyIP-macOS.dmg
    INSTALLED="$T/inst/HappyIP.app/Contents/MacOS/HappyIP"
    mkdir -p "$(dirname "$INSTALLED")" "$T/new/HappyIP.app/Contents/MacOS"
    cp target/debug/happyip "$INSTALLED"
    newer target/debug/happyip "$T/new/HappyIP.app/Contents/MacOS/HappyIP"
    WANT=$(sha "$T/new/HappyIP.app/Contents/MacOS/HappyIP")
    hdiutil create -volname "HappyIP test" -srcfolder "$T/new" -ov -format UDZO "$SRV/download/v9.9.9/$ASSET" >/dev/null
    export HOME="$T/home"
    ;;
  Linux)
    case "$(uname -m)" in x86_64) ASSET=HappyIP-Linux-x64.tar.gz ;; aarch64) ASSET=HappyIP-Linux-arm64.tar.gz ;; esac
    INSTALLED="$T/inst/happyip"
    cp target/debug/happyip "$INSTALLED"
    mkdir -p "$T/new/HappyIP"
    newer target/debug/happyip "$T/new/HappyIP/happyip"
    WANT=$(sha "$T/new/HappyIP/happyip")
    tar -C "$T/new" -czf "$SRV/download/v9.9.9/$ASSET" HappyIP
    export HOME="$T/home" XDG_CONFIG_HOME="$T/home/.config"
    ;;
  MINGW* | MSYS* | CYGWIN*)
    ASSET=HappyIP-Windows-x64.exe
    INSTALLED="$T/inst/HappyIP.exe"
    cp target/debug/happyip.exe "$INSTALLED"
    newer target/debug/happyip.exe "$SRV/download/v9.9.9/$ASSET"
    WANT=$(sha "$SRV/download/v9.9.9/$ASSET")
    APPDATA=$(cygpath -w "$T/home")
    export APPDATA
    ;;
  *) echo "unsupported system"; exit 1 ;;
esac

PORT=48123
(cd "$SRV" && exec "$PY" -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
SERVER=$!
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.2; done
export HAPPYIP_UPDATE_BASE="http://127.0.0.1:$PORT"
BEFORE=$(sha "$INSTALLED")

echo "== A download with the wrong checksum must not be installed"
printf 'version=9.9.9\n%s=%064d\n' "$ASSET" 0 > "$SRV/latest/download/update.txt"
if "$INSTALLED" --update; then echo "FAIL: installed a file with the wrong checksum"; exit 1; fi
[ "$(sha "$INSTALLED")" = "$BEFORE" ] || { echo "FAIL: the program changed"; exit 1; }

echo "== The same version is not an update"
printf 'version=%s\n' "$("$INSTALLED" --version | cut -d' ' -f2)" > "$SRV/latest/download/update.txt"
"$INSTALLED" --update
[ "$(sha "$INSTALLED")" = "$BEFORE" ] || { echo "FAIL: the program changed"; exit 1; }

echo "== A newer version is downloaded, verified and swapped in"
printf 'version=9.9.9\n%s=%s\n' "$ASSET" "$(sha "$SRV/download/v9.9.9/$ASSET")" > "$SRV/latest/download/update.txt"
"$INSTALLED" --update
[ "$(sha "$INSTALLED")" = "$WANT" ] || { echo "FAIL: the new version is not in place"; exit 1; }

echo "== The new copy runs, and tidies up after the update"
"$INSTALLED" --version
LEFT=$(find "$T/inst" -name '*.old' -o -name '*.new' -o -name '.HappyIP-*' | head -5)
[ -z "$LEFT" ] || { echo "FAIL: left behind: $LEFT"; exit 1; }
echo "Updater test passed"
