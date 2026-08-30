#!/usr/bin/env bash
# uc13: the skip-chain ladder over the socket (SPECS §5.5). Two real processes on
# localhost. Shows that a writer publishes a signed rung, that a device which only
# *verified* a ladder pins it too, and that a peer which drops the ladder or serves
# a different one is refused — the rung pin being to the ladder what `state/peer-seq`
# is to the record chain. Manual drill (fixed port 47345, needs
# `cargo build -p nas-cli --release`); MANUAL-TESTING.md §14. Not run by run.sh.
set -u
T=$(mktemp -d /tmp/nas-e2e.XXXX); N=$PWD/target/release/nas; echo "T=$T"
export NAS_PASSPHRASE=correct-horse NAS_HOME=$T/home
PUB=$T/pub; PP=47345
step(){ echo; echo "### $*"; }
$N ns create demo --mode passphrase >/dev/null; mkdir -p $T/src; echo hello > $T/src/a.txt
$N test roundtrip demo $T/src | tail -1 | cut -c1-60; $N ns export-pub demo $PUB >/dev/null
$N peer init $T/peer >/dev/null
$N peer allow $T/peer laptop $PUB/transport.pub >/dev/null
$N peer writer $T/peer $PUB/slot.pub >/dev/null
$N peer grant $T/peer laptop write >/dev/null
serve(){ $N peer serve $T/peer --listen 127.0.0.1:$PP > $T/peer.$1.log 2>&1 & echo $!; }
P1=$(serve a); sleep 1; head -1 $T/peer.a.log
SYNC="$N peer sync demo --peer 127.0.0.1:$PP --peer-pub $T/peer/transport.pub"
S2="env NAS_HOME=$T/home2 $SYNC"
write(){ echo "$2" > $T/$1/$2.txt; }

step "device 1: first sync publishes seq 0 and checkpoints it (seq 0 is a rung under the default interval of 256)"
$SYNC | grep -E 'head|checkpoint|ladder'; echo "exit=${PIPESTATUS[0]}"
echo "device 1 rung pin: $(cat $T/home/demo/state/peer-checkpoint)"

step "device 1: second sync verifies the ladder it published against its own pin"
write src b; $N test roundtrip demo $T/src >/dev/null
$SYNC | grep -E 'head|checkpoint|ladder'; echo "exit=${PIPESTATUS[0]}"

step "device 2 joins by copy — no rung pin of its own, so it anchors at genesis, and pins what it verified"
mkdir -p $T/home2/demo; cp -R $T/home/demo/config $T/home/demo/wraps $T/home2/demo/
$S2 | grep -E 'head|checkpoint|ladder'; echo "exit=${PIPESTATUS[0]}"
echo "device 2 rung pin: $(cat $T/home2/demo/state/peer-checkpoint 2>/dev/null || echo '(none)')"

step "the peer loses its ladder (rungs deleted, records kept) and restarts"
kill $P1 2>/dev/null; wait $P1 2>/dev/null; rm -rf $T/peer/data/checkpoints
P2=$(serve b); sleep 1; head -1 $T/peer.b.log

step "device 1 (expect: refused — a rung was pinned here and the peer serves none)"
$SYNC | tail -1; echo "exit=${PIPESTATUS[0]}"

step "device 2, which only ever verified the ladder rather than publishing it (expect: refused too — seeing it is enough to pin it)"
$S2 | tail -1; echo "exit=${PIPESTATUS[0]}"

step "a device with no memory at all still syncs: nothing was pinned, so nothing is contradicted (SPECS §5.4 — this is the blind spot, not a claim)"
mkdir -p $T/home3/demo; cp -R $T/home/demo/config $T/home/demo/wraps $T/home3/demo/
env NAS_HOME=$T/home3 $SYNC | grep -E 'head|ladder'; echo "exit=${PIPESTATUS[0]}"

kill $P2 2>/dev/null; wait 2>/dev/null
