#!/usr/bin/env bash
# Build a static musl `nas` binary inside a rust:alpine container and bake it
# into the `nas-node` image (docker/Dockerfile, FROM scratch).
#
# ARCH=arm64|amd64 (default arm64). A second rust container / `--platform`
# selects the musl target so amd64 is no longer missing. The out-of-repo path
# deps (../rust-secure-memory, ../simple-network) resolve because the whole
# parent tree is mounted at /work. Cargo registry and the musl target dir live
# on named volumes, so rebuilds are incremental.
#
# This compiles. It does not run tests. ci.sh is the gate.
# Needs Docker (locally: `colima start --cpu 4 --memory 6`).
set -euo pipefail
[ -S "$HOME/.colima/default/docker.sock" ] && export DOCKER_HOST=${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}
ARCH=${ARCH:-arm64}
case "$ARCH" in
  arm64) PLATFORM=linux/arm64 ;;
  amd64) PLATFORM=linux/amd64 ;;
  *)
    echo "ARCH must be arm64 or amd64, got ${ARCH:?}" >&2
    exit 1
    ;;
esac
cd "$(dirname "$0")/.."
REPO=$PWD; WORK=$(cd .. && pwd); OUT=$REPO/docker/out
mkdir -p "$OUT"
docker run --rm --platform "$PLATFORM" \
  -v "$WORK":/work -v "$OUT":/out \
  -v "nas-cargo-registry-${ARCH}":/usr/local/cargo/registry \
  -v "nas-musl-target-${ARCH}":/target \
  -w /work/"$(basename "$REPO")" \
  -e CARGO_TARGET_DIR=/target -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
  rust:1-alpine sh -euc '
    apk add --no-cache build-base cmake perl linux-headers >/dev/null
    cargo build --locked --release -p nas-cli
    cp /target/release/nas /out/nas
    file /out/nas 2>/dev/null || true
    ls -la /out/nas'
docker build --platform "$PLATFORM" -t nas-node -t "nas-node:${ARCH}" docker/
docker run --rm --platform "$PLATFORM" "nas-node:${ARCH}" --version 2>/dev/null \
  || docker run --rm --platform "$PLATFORM" "nas-node:${ARCH}" 2>&1 | head -3
