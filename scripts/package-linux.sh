#!/usr/bin/env bash
# Build HappyIP for Linux inside an Ubuntu 22.04 Docker container, so the
# result runs on Ubuntu 22.04 / Debian 12 and anything newer (glibc 2.35+).
# Requires Docker. Works from macOS, Linux or Windows hosts.
#
# Usage: scripts/package-linux.sh [x64] [arm64]     (default: both)
#   → dist/HappyIP-Linux-x64.tar.gz, dist/HappyIP-Linux-arm64.tar.gz
#
# Each is compiled natively when it matches the container's architecture
# and cross-compiled otherwise (no emulation); the unit tests are run for
# the native one and must pass. Build caches are kept in Docker volumes
# (happyip-linux-cargo, happyip-linux-target) to make later builds quick.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCHES=("$@")
[ ${#ARCHES[@]} -eq 0 ] && ARCHES=(x64 arm64)
for a in "${ARCHES[@]}"; do
  case "$a" in x64 | arm64) ;; *) echo "unknown architecture '$a' (use x64 or arm64)" >&2; exit 2 ;; esac
done
mkdir -p dist

docker run --rm \
  -v "$PWD":/src:ro \
  -v "$PWD/dist":/out \
  -v happyip-linux-cargo:/root/.cargo \
  -v happyip-linux-rustup:/root/.rustup \
  -v happyip-linux-target:/target \
  -e ARCHES="${ARCHES[*]}" -e CARGO_BUILD_JOBS \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  ubuntu:22.04 bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl build-essential pkg-config \
      gcc-x86-64-linux-gnu libc6-dev-amd64-cross gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      iputils-ping iproute2 >/dev/null
    export PATH="/root/.cargo/bin:$PATH"
    command -v cargo >/dev/null || curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
    rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu >/dev/null
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export CARGO_TARGET_DIR=/target
    # The optimized build of a few large crates needs a lot of memory each;
    # a handful at a time fits in the 4 GB Docker Desktop gives containers.
    export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}

    # Build from a copy: the source is mounted read-only.
    rm -rf /build && mkdir /build
    cd /src && tar --exclude=./target --exclude=./dist --exclude=./.git -cf - . | tar -xf - -C /build
    cd /build
    native=$(uname -m)
    for arch in $ARCHES; do
      case "$arch" in
        x64) triple=x86_64-unknown-linux-gnu; machine=x86_64 ;;
        arm64) triple=aarch64-unknown-linux-gnu; machine=aarch64 ;;
      esac
      if [ "$machine" = "$native" ]; then
        echo "== Testing ($arch)"
        cargo test --locked --target "$triple"
      fi
      echo "== Building $arch"
      cargo build --release --locked --target "$triple"
      pkg=/tmp/pkg-$arch/HappyIP
      rm -rf "/tmp/pkg-$arch" && mkdir -p "$pkg"
      cp "/target/$triple/release/happyip" "$pkg/happyip"
      cp assets/icon.png "$pkg/happyip.png"
      cp LICENSE "$pkg/"
      cp scripts/linux/happyip.desktop scripts/linux/install.sh scripts/linux/README.txt "$pkg/"
      chmod 755 "$pkg/happyip" "$pkg/install.sh"
      tar -C "/tmp/pkg-$arch" --owner=0 --group=0 -czf "/out/HappyIP-Linux-$arch.tar.gz" HappyIP
      chown "$HOST_UID:$HOST_GID" "/out/HappyIP-Linux-$arch.tar.gz"
      echo "Built dist/HappyIP-Linux-$arch.tar.gz"
    done
  '
