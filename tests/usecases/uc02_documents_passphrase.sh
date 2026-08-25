#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC02 "Important documents, locked by a passphrase" "SPECS §19.2, §2.2.2" "M1"
check         "namespace created in passphrase mode"             $NAS ns create documents --mode passphrase
check         "Argon2id floor is enforced in code, not docs"     $NAS test argon2-params documents --min-mem 256MiB --min-time 3
check         "peer holds NO plaintext"                          $NAS test peer-no-plaintext documents
check_refuses "wrong passphrase cannot open the namespace"       $NAS ns open documents --passphrase wrong-passphrase
check         "correct passphrase opens it"                      $NAS test open-with-passphrase documents
# The KEK/DEK split exists precisely so this is cheap (SPECS §2.2.2).
check         "passphrase change rewraps only the DEK"           $NAS test passphrase-change-is-rewrap documents
check         "no chunk is re-encrypted by a passphrase change"  $NAS test no-reencrypt-on-passphrase-change documents
# Known gap flagged by review C4 — must be closed before this ships.
check         "recovery from passphrase alone still has an anchor" $NAS test recovery-has-freshness-anchor documents
check         "superseded wraps are removed from the peer"       $NAS test old-wrap-deleted documents
uc_summary
