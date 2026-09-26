#!/usr/bin/env bash
# Run ./ci.sh inside a Linux container. Host ./ci.sh remains the macOS gate.
#
# ARCH=amd64|arm64 (default amd64). The parent work tree is mounted at /work so
# the path deps (../rust-secure-memory-public, ../simple-network) resolve.
# This runs the tests and the acceptance suite. docker/build.sh is the musl
# compile, and it is not a substitute for this. uc11 stays manual.
#
# Needs Docker (locally: `colima start --cpu 4 --memory 6`).
set -euo pipefail
[ -S "$HOME/.colima/default/docker.sock" ] && export DOCKER_HOST=${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}
ARCH=${ARCH:-amd64}
case "$ARCH" in
  arm64) PLATFORM=linux/arm64 ;;
  amd64) PLATFORM=linux/amd64 ;;
  *)
    echo "ARCH must be arm64 or amd64, got ${ARCH:?}" >&2
    exit 1
    ;;
esac
cd "$(dirname "$0")/.."
REPO=$PWD
WORK=$(cd .. && pwd)
docker run --rm --platform "$PLATFORM" \
  -v "$WORK":/work \
  -w /work/"$(basename "$REPO")" \
  -e CI_MILESTONE="${CI_MILESTONE:-M6}" \
  rust:1-bookworm \
  bash -euc '
    apt-get update -qq
    apt-get install -y -qq build-essential pkg-config libssl-dev curl openjdk-17-jre-headless ca-certificates >/dev/null
    rustup component add rustfmt clippy
    curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh \
      | sh -s -- -y --default-toolchain leanprover/lean4:v4.28.0
    export PATH="$HOME/.elan/bin:$PATH"
    ./ci.sh
  '
