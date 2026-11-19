#!/bin/sh
# Install HappyIP for the current user (no root needed):
#   ~/.local/bin/happyip, plus a menu entry and icon.
# Installing in your home folder also lets HappyIP update itself.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin="$HOME/.local/bin"
apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
icons="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/256x256/apps"
mkdir -p "$bin" "$apps" "$icons"
install -m 755 "$here/happyip" "$bin/happyip"
install -m 644 "$here/happyip.png" "$icons/happyip.png"
sed "s|^Exec=happyip|Exec=$bin/happyip|" "$here/happyip.desktop" > "$apps/happyip.desktop"
echo "Installed $bin/happyip"
case ":$PATH:" in *":$bin:"*) ;; *) echo "Note: $bin is not on your PATH; start HappyIP from the applications menu or run $bin/happyip" ;; esac
