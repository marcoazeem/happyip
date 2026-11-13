#!/usr/bin/env bash
# Build a universal (Apple Silicon + Intel) HappyIP.app and wrap it in a DMG.
# Usage: scripts/package-macos.sh   → dist/HappyIP-macOS.dmg
#
# Signing (optional). Without these the app gets an ad-hoc signature, and
# macOS asks users to approve it by hand the first time.
#   MACOS_SIGN_IDENTITY   "Developer ID Application: Your Name (TEAMID)"
#   MACOS_NOTARY_PROFILE  a keychain profile made with
#                         `xcrun notarytool store-credentials`; when set, the
#                         DMG is also notarized and stapled.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
OUT=dist
APP="$OUT/HappyIP.app"

rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

rm -rf "$APP" "$OUT/dmg" && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo -create -output "$APP/Contents/MacOS/HappyIP" \
  target/aarch64-apple-darwin/release/happyip target/x86_64-apple-darwin/release/happyip

# App icon from assets/icon.png (1024×1024).
ICONSET=$(mktemp -d)/HappyIP.iconset && mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s assets/icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  sips -z $((s * 2)) $((s * 2)) assets/icon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/HappyIP.icns"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>HappyIP</string>
  <key>CFBundleDisplayName</key><string>HappyIP</string>
  <key>CFBundleIdentifier</key><string>io.github.marcoazeem.happyip</string>
  <key>CFBundleExecutable</key><string>HappyIP</string>
  <key>CFBundleIconFile</key><string>HappyIP</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSLocalNetworkUsageDescription</key><string>HappyIP scans your local network to list devices.</string>
</dict></plist>
EOF

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  # Developer ID signature with the hardened runtime, as notarization requires.
  codesign --force --deep --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$APP"
  codesign --verify --strict "$APP"
else
  # Ad-hoc signature (no Apple Developer ID): required for Apple Silicon.
  codesign --force --deep --sign - "$APP"
fi

mkdir -p "$OUT/dmg" && cp -R "$APP" "$OUT/dmg/" && ln -s /Applications "$OUT/dmg/Applications"
rm -f "$OUT/HappyIP-macOS.dmg"
hdiutil create -volname "HappyIP $VERSION" -srcfolder "$OUT/dmg" -ov -format UDZO "$OUT/HappyIP-macOS.dmg" >/dev/null
rm -rf "$OUT/dmg"

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  codesign --force --timestamp --sign "$MACOS_SIGN_IDENTITY" "$OUT/HappyIP-macOS.dmg"
  if [ -n "${MACOS_NOTARY_PROFILE:-}" ]; then
    xcrun notarytool submit "$OUT/HappyIP-macOS.dmg" --keychain-profile "$MACOS_NOTARY_PROFILE" --wait
    xcrun stapler staple "$OUT/HappyIP-macOS.dmg"
  else
    echo "Signed but not notarized (set MACOS_NOTARY_PROFILE to notarize)."
  fi
else
  echo "Not signed with a Developer ID (set MACOS_SIGN_IDENTITY to sign)."
fi
echo "Built $OUT/HappyIP-macOS.dmg"
