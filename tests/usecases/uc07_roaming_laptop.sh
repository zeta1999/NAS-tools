#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC07 "Laptop moving between home, office and cafés" "SPECS §19.7, §5.6" "M2"
check M3      "peer is reachable over a Tor onion carrier"       $NAS peer status home-nas
check M3      "writes are accepted with no peer reachable"       $NAS test offline-write work
check M3      "the outbox replays and re-merges on reconnect"    $NAS test outbox-replay work
check M3      "a CAS conflict on replay merges, not errors"      $NAS test outbox-conflict-merges work
check         "witness exchange is opportunistic, not scheduled" $NAS test witness-opportunistic
check         "a 30-day absence loses nothing (90d expiry)"      $NAS test offline-30d work
check         "returning client is warned of would-be sweeps"    $NAS test sweep-warning work
# The whole reason the witness node exists (SPECS §5.3).
check         "two devices that never meet still detect a fork"  $NAS test fork-detect-via-witness
check         "witness-only node holds no blobs and no caps"     $NAS test witness-node-holds-nothing
uc_summary
