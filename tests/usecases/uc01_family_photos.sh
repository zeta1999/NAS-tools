#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC01 "Family photos on the home NAS" "SPECS §19.1, §2.2.3" "M1"
# The inverse of every other test: here plaintext on the peer is CORRECT.
check         "namespace is created in transit-only mode"        $NAS ns create photos --mode transit-only
check         "peer stores plaintext — readable by the NAS"      $NAS test peer-holds-plaintext photos
check         "filenames are visible on the peer"                $NAS test peer-names-visible photos
check         "peer-side thumbnails work (impossible in e2ee)"   $NAS peer feature-check photos thumbnails
check         "family subject has read via a peer-enforced ACL"  $NAS acl check photos --subject family --right read
check_refuses "family subject cannot write"                      $NAS acl check photos --subject family --right write
# Confidentiality is traded away; NOTHING ELSE is (SPECS §2.2 table).
check         "slot updates are still ML-DSA signed"             $NAS test slot-signed photos
check         "rollback is still detected in transit-only"       $NAS test attack rollback photos
check         "leases and witnesses behave identically"          $NAS test lease-cycle photos
check         "loss of the vault does NOT lose the photos"       $NAS test recover-without-vault photos
uc_summary
