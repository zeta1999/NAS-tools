#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC03 "Work source code, fully end-to-end encrypted" "SPECS §19.3" "M0"
check         "namespace created in e2ee mode"                   $NAS ns create work --mode e2ee
check         "round-trip is byte-identical"                     $NAS test roundtrip work ./fixtures/tree
check         "two trees sharing 90% transfer ~10% of bytes"     $NAS test dedup-ratio work --shared 90 --max-transfer 15
check         "peer disk contains no plaintext marker"           $NAS test peer-no-plaintext work
check         "path segments are encrypted on the peer"          $NAS test peer-names-encrypted work
check         "listing resolves locally, peer never sees prefix" $NAS test listing-is-local work
# The convergence secret must be load-bearing, not decorative (SPECS §12.5).
check         "confirmation attack succeeds WITH the secret"     $NAS test confirmation-attack work --with-cs
check_refuses "confirmation attack fails WITHOUT the secret"     $NAS test confirmation-attack work --without-cs
check_refuses "no dedup across tenants"                          $NAS test cross-tenant-dedup work other-tenant
uc_summary
