#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC09 "A hostile peer" "SPECS §12.4, §5.3, §4.5" "M2"
# One named test per attack, per SPECS §12 criterion 4.
check "tampered blob is detected"                    $NAS test attack tamper
check "rolled-back slot is detected"                 $NAS test attack rollback
check "withheld blob is detected"                    $NAS test attack withhold
check "dedup lie is caught by proof-of-possession"   $NAS test attack dedup-lie
check "CAS non-enforcement is detected"              $NAS test attack cas-non-enforcement
check "lease griefing is bounded by per-holder quota" $NAS test attack lease-griefing
check "withheld witnesses are detected over time"    $NAS test attack witness-withholding
# The bootstrapping case: a fresh client with only a capability.
check "a cold client with only a cap resists all of the above" $NAS test attack all --cold-start
uc_summary
