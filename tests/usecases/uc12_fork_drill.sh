#!/usr/bin/env bash
# uc12: a live FORKING peer over the socket — three real processes on localhost:
# `nas peer serve --hostile fork`, a --witness node, three devices of one namespace.
# The forking peer cannot tell the devices apart (one transport key), so it equivocates
# blindly: even-numbered connections see branch 0 (main), odd-numbered see branch 1
# (private). Every record on both branches is genuinely signed. Manual drill (fixed
# ports 47343/47344, needs `cargo build -p nas-cli --release`); MANUAL-TESTING.md §13.
# Not run by run.sh.
set -u
T=$(mktemp -d /tmp/nas-e2e.XXXX); N=$PWD/target/release/nas; echo "T=$T"
export NAS_PASSPHRASE=correct-horse NAS_HOME=$T/home
PUB=$T/pub; PP=47343; WP=47344
step(){ echo; echo "### $*"; }
$N ns create demo --mode passphrase >/dev/null; mkdir -p $T/src; echo hello > $T/src/a.txt
$N test roundtrip demo $T/src | tail -1 | cut -c1-60; $N ns export-pub demo $PUB >/dev/null
for d in peer wit; do $N peer init $T/$d >/dev/null; $N peer allow $T/$d laptop $PUB/transport.pub >/dev/null; $N peer writer $T/$d $PUB/slot.pub >/dev/null; done
$N peer grant $T/peer laptop write >/dev/null
$N peer serve $T/peer --listen 127.0.0.1:$PP --hostile fork > $T/peer.log 2>&1 & P1=$!
$N peer serve $T/wit --listen 127.0.0.1:$WP --witness > $T/wit.log 2>&1 & P2=$!
sleep 1; head -1 $T/peer.log; head -1 $T/wit.log
SYNC="$N peer sync demo --peer 127.0.0.1:$PP --peer-pub $T/peer/transport.pub"
WIT="--witness 127.0.0.1:$WP --witness-pub $T/wit/transport.pub"
S1="$SYNC"; S2="env NAS_HOME=$T/home2 $SYNC"; S3="env NAS_HOME=$T/home3 $SYNC"
join(){ mkdir -p $T/$1/demo; cp -R $T/home/demo/config $T/home/demo/wraps $T/$1/demo/; }
write(){ echo "$2" > $T/$1/$2.txt; }

step "conn 0 = main: device 1 publishes seq 0, witnessed"
$S1 $WIT | grep -E 'head|chain|witness'; echo "exit=${PIPESTATUS[0]}"

step "conn 1 = private: device 2 joins by copy, builds on seq 0, publishes seq 1 (kept on the fork), witnessed"
join home2; mkdir -p $T/src2; write src2 b; NAS_HOME=$T/home2 $N test roundtrip demo $T/src2 >/dev/null
$S2 $WIT | grep -E 'head|chain|witness'; echo "exit=${PIPESTATUS[0]}"

step "conn 2 = main: device 1 still sees seq 0 (device 2's write is invisible here), publishes seq 1 on main — no witness node"
write src c; $N test roundtrip demo $T/src >/dev/null; $S1 | grep -E 'head|chain'; echo "exit=${PIPESTATUS[0]}"

step "conn 3 = private: device 2 sees its own seq 1, publishes seq 2 there — no witness node"
write src2 d; NAS_HOME=$T/home2 $N test roundtrip demo $T/src2 >/dev/null; $S2 | grep -E 'head|chain'; echo "exit=${PIPESTATUS[0]}"

step "conn 4 = main: device 1 publishes seq 2 on main — no witness node"
write src e; $N test roundtrip demo $T/src >/dev/null; $S1 | grep -E 'head|chain'; echo "exit=${PIPESTATUS[0]}"

step "conn 5 = private: device 2, nothing new (keeps the parity)"
$S2 | grep -E 'head|chain'; echo "exit=${PIPESTATUS[0]}"

step "conn 6 = main: device 1 WITH the witness node. Head is seq 2; the relay holds device 2's witness of seq 1 on the OTHER branch (expect: refused, fork at a sequence below the head)"
$S1 $WIT | tail -1; echo "exit=${PIPESTATUS[0]}"

step "conn 7 = private: device 2 WITH the witness node (expect: accepted — no witness from main has reached the relay, device 1 was refused before it could witness; SPECS §5.4 converges once witnesses propagate)"
$S2 $WIT | grep -E 'head|chain|witness'; echo "exit=${PIPESTATUS[0]}"

step "conn 8 = main: device 3, brand new, no pin, no witness node — accepts seq 2 on main and pins it (seq + record hash)"
join home3; $S3 | grep -E 'head|chain'; echo "exit=${PIPESTATUS[0]}"; echo "device 3 pin: $(cat $T/home3/demo/state/peer-seq | cut -c1-24)..."

step "conn 9 = private: device 3 again, no witness node. Same seq 2, different record (expect: refused by the pin's hash alone)"
$S3 | tail -1; echo "exit=${PIPESTATUS[0]}"

step "conn 10 = main: device 3 WITH the witness node (expect: refused — device 2's witnesses of seq 1 and 2 contradict main's chain)"
$S3 $WIT | tail -1; echo "exit=${PIPESTATUS[0]}"

kill $P1 $P2 2>/dev/null; wait 2>/dev/null; echo; echo "--- forking peer log (view per connection)"; cut -c1-100 $T/peer.log
