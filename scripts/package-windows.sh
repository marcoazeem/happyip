#!/usr/bin/env bash
# Cross-compile HappyIP.exe from macOS/Linux. Uses Rust's tier-3 win7 target so
# the binary also runs on Windows 7/8 and Server 2008 R2/2012 (and 10/11).
# Requires: mingw-w64 (brew install mingw-w64).
# Usage: scripts/package-windows.sh   → dist/HappyIP-Windows-x64.exe
#
# Signing (optional, needs `brew install osslsigncode`). An unsigned exe that
# starts PowerShell is what antivirus and SmartScreen distrust most.
#   WINDOWS_SIGN_PFX       path to a code-signing certificate (.pfx / .p12)
#   WINDOWS_SIGN_PASSWORD  its password (read from the environment, never
#                          put on a command line)
set -euo pipefail
cd "$(dirname "$0")/.."

# Pinned: the win7 std in later nightlies was broken at the time of writing.
NIGHTLY=nightly-2026-09-01
rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src >/dev/null

CARGO_TARGET_X86_64_WIN7_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
  cargo +"$NIGHTLY" build --release -Zbuild-std=std,panic_abort --target x86_64-win7-windows-gnu

mkdir -p dist
EXE=dist/HappyIP-Windows-x64.exe
if [ -n "${WINDOWS_SIGN_PFX:-}" ]; then
  export WINDOWS_SIGN_PASSWORD="${WINDOWS_SIGN_PASSWORD:-}"
  rm -f "$EXE"
  osslsigncode sign -pkcs12 "$WINDOWS_SIGN_PFX" -readpass <(printf '%s' "$WINDOWS_SIGN_PASSWORD") \
    -n "HappyIP" -i "https://github.com/marcoazeem/happyip" \
    -h sha256 -ts http://timestamp.digicert.com \
    -in target/x86_64-win7-windows-gnu/release/happyip.exe -out "$EXE"
  osslsigncode verify -in "$EXE" >/dev/null && echo "Signed $EXE"
else
  cp target/x86_64-win7-windows-gnu/release/happyip.exe "$EXE"
  echo "Not signed (set WINDOWS_SIGN_PFX to sign)."
fi
echo "Built dist/HappyIP-Windows-x64.exe"
