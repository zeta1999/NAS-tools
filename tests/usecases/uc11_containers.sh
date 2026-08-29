#!/usr/bin/env bash
# uc11: uc10 with the three nodes as containers (docker/compose.yaml, image from
# docker/build.sh, colima arm64 VM) — honest peer restarted as --hostile rollback, a
# --hostile withhold peer, a --witness node; the three devices are the host CLI talking to
# the published ports. Manual drill; documented in MANUAL-TESTING.md §13. Not run by run.sh.
# Needs: `cargo build -p nas-cli --release` (host devices), `docker/build.sh` (nas-node image).
set -u
[ -S "$HOME/.colima/default/docker.sock" ] && export DOCKER_HOST=${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}
cd "$(dirname "$0")/../.."
N=$PWD/target/release/nas; C="docker compose -f docker/compose.yaml"
export DRILL=$PWD/target/uc11-drill; rm -rf "$DRILL"; mkdir -p "$DRILL"; T=$DRILL; echo "DRILL=$DRILL"
export NAS_PASSPHRASE=correct-horse NAS_HOME=$T/home
PUB=$T/pub; PP=47341; WP=47342; HP=47343
step(){ echo; echo "### $*"; }
waitport(){ for _ in $(seq 1 50); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.2; done; echo "port $1 never came up"; return 1; }
$C --profile hostile down --remove-orphans >/dev/null 2>&1
$N ns create demo --mode passphrase >/dev/null; mkdir -p $T/src; echo hello > $T/src/a.txt
$N test roundtrip demo $T/src | tail -1 | cut -c1-60; $N ns export-pub demo $PUB >/dev/null
for d in peer peer2 wit; do $N peer init $T/$d >/dev/null; $N peer allow $T/$d laptop $PUB/transport.pub >/dev/null; $N peer writer $T/$d $PUB/slot.pub >/dev/null; done
$N peer grant $T/peer laptop write >/dev/null; $N peer grant $T/peer2 laptop write >/dev/null
step "nodes up: peer (honest), withhold, witness"
$C up -d peer withhold witness 2>&1 | grep -v '^$' | tail -3; waitport $PP; waitport $WP; waitport $HP
$C logs --no-color --no-log-prefix peer witness withhold 2>/dev/null | cut -c1-120
SYNC="$N peer sync demo --peer 127.0.0.1:$PP --peer-pub $T/peer/transport.pub"
WIT="--witness 127.0.0.1:$WP --witness-pub $T/wit/transport.pub"
step "device 1: sync #1 (seq 0) and #2 (seq 1), both witnessed"
$SYNC $WIT | grep -E 'head|witness'; echo more > $T/src/b.txt; $N test roundtrip demo $T/src >/dev/null; $SYNC $WIT | grep -E 'head|witness'; echo "exit=${PIPESTATUS[0]}"
step "device 2 joins: copy config+wraps, open by passphrase"
mkdir -p $T/home2/demo; cp -R $T/home/demo/config $T/home/demo/wraps $T/home2/demo/; NAS_HOME=$T/home2 $N ns open demo | head -1
step "device 2 against the HONEST peer, with witness (expect: accept seq 1, pin it, witness it)"
NAS_HOME=$T/home2 $SYNC $WIT | grep -E 'head|witness'; echo "exit=${PIPESTATUS[0]}"
step "restart the peer container as --hostile rollback (same repo, same port)"
$C stop peer >/dev/null 2>&1; $C --profile hostile up -d peer-hostile >/dev/null 2>&1; waitport $PP
$C logs --no-color --no-log-prefix peer-hostile 2>/dev/null | head -1 | cut -c1-120
step "device 1 (pin from publishing) — no witness needed"; $SYNC | tail -1; echo "exit=${PIPESTATUS[0]}"
step "device 2 (pin from having seen seq 1) — no witness needed either now"; NAS_HOME=$T/home2 $SYNC | tail -1; echo "exit=${PIPESTATUS[0]}"
step "device 3: brand new, no pin, WITHOUT witness (the blind spot)"
mkdir -p $T/home3/demo; cp -R $T/home/demo/config $T/home/demo/wraps $T/home3/demo/; NAS_HOME=$T/home3 $SYNC | tail -1; echo "exit=${PIPESTATUS[0]}"
step "device 3: brand new, no pin, WITH witness (expect: refused, rollback)"
rm -f $T/home3/demo/state/peer-seq; NAS_HOME=$T/home3 $SYNC $WIT | tail -1; echo "exit=${PIPESTATUS[0]}"
step "device 3 against the WITHHOLDING node (never had the data, claims none), with witness"
rm -f $T/home3/demo/state/peer-seq; NAS_HOME=$T/home3 $N peer sync demo --peer 127.0.0.1:$HP --peer-pub $T/peer2/transport.pub $WIT | tail -1; echo "exit=${PIPESTATUS[0]}"
echo; echo "--- witness node log"; $C logs --no-color --no-log-prefix witness 2>/dev/null | cut -c1-120
echo "--- containers"; $C --profile hostile ps --format '{{.Service}}\t{{.Status}}' 2>/dev/null
$C --profile hostile down >/dev/null 2>&1
