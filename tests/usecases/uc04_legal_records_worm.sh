#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC04 "Legal records that must never be deleted" "SPECS §19.4, §16" "M2"
# `--device laptop` names this namespace's everyday device. Under object-lock
# that device is seeded APPEND ONLY, because §16's whole ransomware defence is
# "add, never overwrite or delete" and a posture nobody remembers to configure
# is not a defence. Naming it is deliberate: an ACL entry is only meaningful
# against a subject the operator actually binds a key to.
check         "namespace created with object-lock compliance"    $NAS ns create records --mode e2ee --object-lock compliance --retention 7y --device laptop
check         "the laptop holds append rights only"              $NAS acl check records --subject laptop --right append
# The other half of "only": append is not write. `write` subsumes overwrite and
# delete, so a laptop holding it would make the line above decorative.
check_refuses "and the laptop does NOT hold write"               $NAS acl check records --subject laptop --right write
check_refuses "nor any delete authority"                         $NAS acl check records --subject laptop --right delete-approve
# The object verbs need the key -> object mapping the S3 face brings, so they
# are M3 (SPECS §7.1) and `nas put`/`nas rm` exit 3 until then. Gated rather
# than failing, because a specified-but-unbuilt command must never be scored as
# a refusal -- and PENDING is not success either.
check M3      "appending a new key succeeds"                     $NAS put records/new-scan.pdf ./fixtures/scan.pdf
# NOTE: in e2ee the peer CANNOT enforce semantic append-only (SPECS §2.2) --
# a slot update is an opaque root address. This proves the honest client
# refuses, which is theatre against ransomware. The load-bearing assertions
# are the retention-superset check and go-silent, below.
check_refuses M3 "overwriting an existing key is refused by the client" $NAS put records/new-scan.pdf ./fixtures/other.pdf
check_refuses M3 "the laptop cannot delete"                      $NAS rm records/new-scan.pdf
check_refuses "a delete with no approvals does not execute"      $NAS delete-request execute records/new-scan.pdf
check_refuses "quorum cannot be reached with one approver"       $NAS test delete-quorum records --approvers 1 --scope namespace
check_refuses "cooling-off cannot be short-circuited"            $NAS test cooling-off-bypass records
# Review finding C9: N object-scope deletes must not add up to a namespace delete.
check_refuses "quorum survives decomposition into N object deletes" $NAS test quorum-decomposition-attack records
# Review finding: the cheapest attack on WORM is silence, not deletion (§16.3).
check         "retention set is extend-only under the everyday key"     $NAS test retention-extend-only records
check_refuses "the everyday key cannot shrink the retention set"        $NAS test retention-shrink records --key everyday
check         "going silent does NOT destroy data (retention > leases)" $NAS test attack go-silent records
check         "an approval cannot be replayed against another request"  $NAS test approval-replay records
uc_summary
