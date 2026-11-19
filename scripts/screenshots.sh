#!/usr/bin/env bash
# Regenerate the README screenshots from the built-in demo data:
#   docs/app.png           the main window (drawn off-screen, no window opens)
#   docs/report-light.png  the HTML report
#   docs/report-dark.png   ...in dark mode
# Requires: python3 with Pillow, and Google Chrome for the report pictures.
set -euo pipefail
cd "$(dirname "$0")/.."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cargo build --locked
target/debug/happyip --screenshot "$TMP/app.rgba"
python3 - "$TMP/app.rgba" docs/app.png <<'PY'
import sys
from PIL import Image
data = open(sys.argv[1], 'rb').read()
header, pixels = data.split(b'\n', 1)
width, height = map(int, header.split())
Image.frombytes('RGBA', (width, height), pixels).convert('RGB').save(sys.argv[2], optimize=True)
PY

CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
# The report follows the system theme; force each one for its picture.
target/debug/happyip --demo-report "$TMP/report.html" 2>/dev/null
sed 's/@media (prefers-color-scheme:dark)/@media not all/' "$TMP/report.html" > "$TMP/light.html"
sed 's/@media (prefers-color-scheme:dark)/@media all/' "$TMP/report.html" > "$TMP/dark.html"
for theme in light dark; do
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 \
    --window-size=1800,1080 --screenshot="$TMP/$theme.png" "file://$TMP/$theme.html" >/dev/null 2>&1
  python3 -c "import sys; from PIL import Image; Image.open(sys.argv[1]).convert('RGB').save(sys.argv[2], optimize=True)" \
    "$TMP/$theme.png" "docs/report-$theme.png"
done
ls -la docs/*.png
