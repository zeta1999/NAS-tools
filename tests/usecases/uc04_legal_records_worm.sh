#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC04 "Legal records that must never be deleted" "SPECS §19.4, §16" "M2"
check         "namespace created with object-lock compliance"    $NAS ns create records --mode e2ee --object-lock compliance --retention 7y
check         "the laptop holds append rights only"              $NAS acl check records --subject laptop --right append
check         "appending a new key succeeds"                     $NAS put records/new-scan.pdf ./fixtures/scan.pdf
check_refuses "overwriting an existing key is refused"           $NAS put records/new-scan.pdf ./fixtures/other.pdf
check_refuses "the laptop cannot delete"                         $NAS rm records/new-scan.pdf
check_refuses "a delete with no approvals does not execute"      $NAS delete-request execute records/new-scan.pdf
check_refuses "quorum cannot be reached with one approver"       $NAS test delete-quorum records --approvers 1 --scope namespace
check_refuses "cooling-off cannot be short-circuited"            $NAS test cooling-off-bypass records
# Review finding C9: N object-scope deletes must not add up to a namespace delete.
check_refuses "quorum survives decomposition into N object deletes" $NAS test quorum-decomposition-attack records
# Review finding: the cheapest attack on WORM is silence, not deletion (§16.3).
check         "going silent does NOT destroy data (retention > leases)" $NAS test attack go-silent records
check         "an approval cannot be replayed against another request"  $NAS test approval-replay records
uc_summary
