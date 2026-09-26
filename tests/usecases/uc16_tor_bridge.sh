#!/usr/bin/env bash
# Manual drill: live arti circuits via the simple-network tor-bridge sidecar.
# Not run by run.sh (no uc_summary) — needs the public Tor network and
# `cargo build -p simple_network --features tor --bin tor-bridge`.
# NAS-tools stays on TcpStream + onion-map; do not add arti to nas-cli.
set -u
cd "$(dirname "$0")/../.."
ROOT=$PWD
WORK=$(cd .. && pwd)
BRIDGE=$WORK/simple-network/target/release/tor-bridge
NAS=${NAS_BIN:-$ROOT/target/release/nas}
[ -x "$BRIDGE" ] || { echo "build the sidecar first:"; echo "  cargo build --release -p simple_network --features tor --bin tor-bridge"; exit 1; }
[ -x "$NAS" ] || { echo "need a release nas"; exit 1; }

T=$(mktemp -d "${TMPDIR:-/tmp}/nas-tor-bridge.XXXXXX")
export NAS_HOME=$T/home
MAP=$NAS_HOME/state/onion-map
mkdir -p "$(dirname "$MAP")"
echo "DRILL=$T"

# 1. Ordinary loopback peer. The bridge forwards the onion onto this port.
$NAS ns create demo --mode e2ee >/dev/null
$NAS peer init "$T/peer" >/dev/null
$NAS ns export-pub demo "$T/pub" >/dev/null
$NAS peer allow "$T/peer" laptop "$T/pub/transport.pub" >/dev/null
$NAS peer writer "$T/peer" "$T/pub/slot.pub" >/dev/null
$NAS peer serve "$T/peer" --listen 127.0.0.1:47441 --once &
sleep 0.3

# 2. Sidecar: real v3 (or fail if Tor is unreachable) written into onion-map.
#    Keep the synthetic cookbook name as an alias if you already have one.
echo "starting tor-bridge (bootstraps Tor; tens of seconds)…"
"$BRIDGE" serve --forward 127.0.0.1:47441 --map "$MAP" --alias home-nas.onion &
echo "when the map has a real .onion, nas peer sync --peer <v3>.onion still dials TCP after resolve_onion"
echo "map: $MAP"
echo "this script does not assert against the public Tor network."
