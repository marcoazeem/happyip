#!/usr/bin/env bash
# Cross-compile HappyIP.exe from macOS/Linux. Uses Rust's tier-3 win7 target so
# the binary also runs on Windows 7/8 and Server 2008 R2/2012 (and 10/11).
# Requires: mingw-w64 (brew install mingw-w64).
# Usage: scripts/package-windows.sh   → dist/HappyIP-Windows-x64.exe
set -euo pipefail
cd "$(dirname "$0")/.."

# Pinned: the win7 std in later nightlies was broken at the time of writing.
NIGHTLY=nightly-2026-09-01
rustup toolchain install "$NIGHTLY" --profile minimal --component rust-src >/dev/null

CARGO_TARGET_X86_64_WIN7_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
  cargo +"$NIGHTLY" build --release -Zbuild-std=std,panic_abort --target x86_64-win7-windows-gnu

mkdir -p dist
cp target/x86_64-win7-windows-gnu/release/happyip.exe dist/HappyIP-Windows-x64.exe
echo "Built dist/HappyIP-Windows-x64.exe"
