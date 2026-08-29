#!/usr/bin/env bash
# Build the static arm64 musl `nas` binary inside a native rust:alpine container and bake it
# into the `nas-node` image (docker/Dockerfile, FROM scratch). The out-of-repo path deps
# (../rust-secure-memory, ../simple-network) resolve because the whole ~/work tree is mounted
# at /work. Cargo registry and the musl target dir live on named volumes, so rebuilds are
# incremental. Needs the colima VM up (`colima start --cpu 4 --memory 6`).
set -euo pipefail
[ -S "$HOME/.colima/default/docker.sock" ] && export DOCKER_HOST=${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}
cd "$(dirname "$0")/.."
REPO=$PWD; WORK=$(cd .. && pwd); OUT=$REPO/docker/out
mkdir -p "$OUT"
docker run --rm \
  -v "$WORK":/work -v "$OUT":/out \
  -v nas-cargo-registry:/usr/local/cargo/registry \
  -v nas-musl-target:/target \
  -w /work/"$(basename "$REPO")" \
  -e CARGO_TARGET_DIR=/target -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
  rust:1-alpine sh -euc '
    apk add --no-cache build-base cmake perl linux-headers >/dev/null
    cargo build --locked --release -p nas-cli
    cp /target/release/nas /out/nas
    file /out/nas 2>/dev/null || true
    ls -la /out/nas'
docker build -t nas-node docker/
docker run --rm nas-node --version 2>/dev/null || docker run --rm nas-node 2>&1 | head -3
