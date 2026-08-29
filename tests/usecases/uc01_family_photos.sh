#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC01 "Family photos on the home NAS" "SPECS §19.1, §2.2.3" "M1"
# The inverse of every other test: here plaintext on the peer is CORRECT.
check         "namespace is created in transit-only mode"        $NAS ns create photos --mode transit-only
# SETUP, not an assertion. SPECS §19.1 declares the access list as part of the
# namespace definition:
#     access:
#       - { subject: family,  rights: [read] }
#       - { subject: renaud,  rights: [read, write, admin] }
# `ns create` above does not carry it, so it is established here. The
# assertions that follow test that the peer EVALUATES this list -- granting
# read and denying write -- not that a namespace invents a family by itself.
[ -z "$NAS" ] || {
  $NAS acl grant photos --subject family --right read   >/dev/null 2>&1
  $NAS acl grant photos --subject renaud --right read   >/dev/null 2>&1
  $NAS acl grant photos --subject renaud --right write  >/dev/null 2>&1
  $NAS acl grant photos --subject renaud --right admin  >/dev/null 2>&1
}
check         "peer stores plaintext — readable by the NAS"      $NAS test peer-holds-plaintext photos
# The inverted expectation, checked by the harness itself: in transit-only,
# readable content and readable names on the peer are CORRECT (SPECS §2.2.3).
check_creates        "transit-only namespace actually stored blobs" "$NAS_HOME/photos/blobs"
check_present_under  "harness reads fixture text straight off disk" "$NAS_HOME/photos/blobs" "# work tree fixture"
check         "filenames are visible on the peer"                $NAS test peer-names-visible photos
check M6      "thumbnails are PERMITTED by the mode (feature deferred, §19.1)" $NAS peer feature-permitted photos thumbnails
check         "family subject has read via a peer-enforced ACL"  $NAS acl check photos --subject family --right read
check_refuses "family subject cannot write"                      $NAS acl check photos --subject family --right write
# Confidentiality is traded away; NOTHING ELSE is (SPECS §2.2 table).
check         "slot updates are still ML-DSA signed"             $NAS test slot-signed photos
check M2      "rollback is still detected in transit-only"       $NAS test attack rollback photos
check M2      "leases and witnesses behave identically"          $NAS test lease-cycle photos
check         "loss of the vault does NOT lose the photos"       $NAS test recover-without-vault photos
uc_summary
