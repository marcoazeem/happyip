#!/usr/bin/env bash
# Build every download, write the update manifest and publish a GitHub
# release for the version in Cargo.toml.
#
# Usage: scripts/release.sh [--prerelease] [--skip-build] [--notes FILE]
#
#   --prerelease   publish as a pre-release. Copies of HappyIP already
#                  installed only update to the *latest* full release, so a
#                  pre-release is never offered to them: use it to try a
#                  build before everyone gets it. Promote it later with
#                    gh release edit vX.Y.Z --prerelease=false --latest
#   --skip-build   publish the files already in dist/
#   --notes FILE   release notes (default: generated from the commits)
#
# To ship an update: bump `version` in Cargo.toml, commit, push, run this.
# Requires: gh (signed in), Docker, mingw-w64, and macOS for the .dmg.
set -euo pipefail
cd "$(dirname "$0")/.."

PRERELEASE=() SKIP_BUILD=0 NOTES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --prerelease) PRERELEASE=(--prerelease) ;;
    --skip-build) SKIP_BUILD=1 ;;
    --notes) NOTES=(--notes-file "$2"); shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
[ ${#NOTES[@]} -eq 0 ] && NOTES=(--generate-notes)

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
TAG="v$VERSION"
FILES=(HappyIP-Windows-x64.exe HappyIP-macOS.dmg HappyIP-Linux-x64.tar.gz HappyIP-Linux-arm64.tar.gz)

# The release is cut from what is on GitHub, so that must be what was built.
if [ -n "$(git status --porcelain)" ]; then
  echo "There are uncommitted changes; commit them first." >&2; exit 1
fi
git fetch -q origin
if [ -z "$(git branch -r --contains HEAD)" ]; then
  echo "This commit hasn't been pushed; push it first." >&2; exit 1
fi
if gh release view "$TAG" >/dev/null 2>&1; then
  echo "Release $TAG already exists. Bump the version in Cargo.toml for a new release." >&2; exit 1
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
  scripts/package-macos.sh
  scripts/package-windows.sh
  scripts/package-linux.sh
fi

# The manifest installed copies read to find out about this version, with
# the checksum each download must have.
{
  echo "version=$VERSION"
  for f in "${FILES[@]}"; do
    [ -f "dist/$f" ] || { echo "dist/$f is missing" >&2; exit 1; }
    echo "$f=$(shasum -a 256 "dist/$f" | cut -d' ' -f1)"
  done
} > dist/update.txt
cat dist/update.txt

gh release create "$TAG" --target "$(git rev-parse HEAD)" --title "HappyIP $VERSION" \
  "${NOTES[@]}" ${PRERELEASE[@]+"${PRERELEASE[@]}"} \
  "${FILES[@]/#/dist/}" dist/update.txt
echo "Published $TAG"
