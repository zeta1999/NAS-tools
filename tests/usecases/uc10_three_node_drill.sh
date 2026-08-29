#!/usr/bin/env bash
# uc10: three real processes on localhost — honest peer restarted as --hostile rollback,
# a --witness node, three devices of one namespace. Manual drill (fixed ports 47341/47342,
# needs `cargo build -p nas-cli --release`); documented in MANUAL-TESTING.md §12.
# Not run by run.sh.
set -u
T=$(mktemp -d /tmp/nas-e2e.XXXX); N=$PWD/target/release/nas; echo "T=$T"
export NAS_PASSPHRASE=correct-horse NAS_HOME=$T/home
PUB=$T/pub; PP=47341; WP=47342
step(){ echo; echo "### $*"; }
$N ns create demo --mode passphrase >/dev/null; mkdir -p $T/src; echo hello > $T/src/a.txt
$N test roundtrip demo $T/src | tail -1 | cut -c1-60; $N ns export-pub demo $PUB >/dev/null
for d in peer wit; do $N peer init $T/$d >/dev/null; $N peer allow $T/$d laptop $PUB/transport.pub >/dev/null; $N peer writer $T/$d $PUB/slot.pub >/dev/null; done
$N peer grant $T/peer laptop write >/dev/null
$N peer serve $T/peer --listen 127.0.0.1:$PP > $T/peer.log 2>&1 & P1=$!
$N peer serve $T/wit --listen 127.0.0.1:$WP --witness > $T/wit.log 2>&1 & P2=$!
sleep 1; head -1 $T/peer.log; head -1 $T/wit.log
SYNC="$N peer sync demo --peer 127.0.0.1:$PP --peer-pub $T/peer/transport.pub"
WIT="--witness 127.0.0.1:$WP --witness-pub $T/wit/transport.pub"
step "device 1: sync #1 (seq 0) and #2 (seq 1), both witnessed"
$SYNC $WIT | grep -E 'head|witness'; echo more > $T/src/b.txt; $N test roundtrip demo $T/src >/dev/null; $SYNC $WIT | grep -E 'head|witness'; echo "exit=${PIPESTATUS[0]}"
step "device 2 joins: copy config+wraps, open by passphrase"
mkdir -p $T/home2/demo; cp -R $T/home/demo/config $T/home/demo/wraps $T/home2/demo/; NAS_HOME=$T/home2 $N ns open demo | head -1
step "device 2 against the HONEST peer, with witness (expect: accept seq 1, pin it, witness it)"
NAS_HOME=$T/home2 $SYNC $WIT | grep -E 'head|witness'; echo "exit=${PIPESTATUS[0]}"; echo "device 2 pin: $(cat $T/home2/demo/state/peer-seq 2>/dev/null || find $T/home2 -name 'pin*' -exec cat {} \;)"
step "restart the peer as --hostile rollback"; kill $P1; wait $P1 2>/dev/null
$N peer serve $T/peer --listen 127.0.0.1:$PP --hostile rollback > $T/peer2.log 2>&1 & P1=$!; sleep 1; head -1 $T/peer2.log | cut -c1-120
step "device 1 (pin from publishing) — no witness needed"; $SYNC | tail -1; echo "exit=${PIPESTATUS[0]}"
step "device 2 (pin from having seen seq 1) — no witness needed either now"; NAS_HOME=$T/home2 $SYNC | tail -1; echo "exit=${PIPESTATUS[0]}"
step "device 3: brand new, no pin, WITHOUT witness (the blind spot)"
mkdir -p $T/home3/demo; cp -R $T/home/demo/config $T/home/demo/wraps $T/home3/demo/; NAS_HOME=$T/home3 $SYNC | tail -1; echo "exit=${PIPESTATUS[0]}"
step "device 3: brand new, no pin, WITH witness (expect: refused, rollback)"
rm -f $T/home3/demo/state/pin; NAS_HOME=$T/home3 $SYNC $WIT | tail -1; echo "exit=${PIPESTATUS[0]}"
step "device 3 against a WITHHOLDING peer, with witness"; kill $P1; wait $P1 2>/dev/null
$N peer serve $T/peer --listen 127.0.0.1:$PP --hostile withhold > $T/peer3.log 2>&1 & P1=$!; sleep 1
rm -f $T/home3/demo/state/pin; NAS_HOME=$T/home3 $SYNC $WIT | tail -1; echo "exit=${PIPESTATUS[0]}"
kill $P1 $P2 2>/dev/null; wait 2>/dev/null; echo; echo "--- witness node log"; cut -c1-120 $T/wit.log
