#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC06 "Public mirror, minus fixes/" "SPECS §19.6, §7.6" "M5"
check         "dry run is mandatory before a first publish"      $NAS mirror dry-run myproject
check_refuses "publishing without a dry run is refused"          $NAS test mirror-publish-without-dryrun myproject
check         "fixes/ appears in no published commit"            $NAS test mirror-excludes myproject 'fixes/**'
check         "internal/ appears in no published commit"         $NAS test mirror-excludes myproject 'internal/**'
check         "commits left empty by filtering are dropped"      $NAS test mirror-no-empty-commits myproject
# It is a DERIVED repo; without a persisted map you force-push forever (§7.6).
check         "the private→public SHA map is persisted"          $NAS test mirror-shamap-exists myproject
check         "re-publishing produces identical public SHAs"     $NAS test mirror-shamap-stable myproject
check         "the SHA map never leaves the encrypted namespace" $NAS test mirror-shamap-encrypted myproject
check_refuses "a malformed rule fails closed, publishing nothing" $NAS test mirror-failclosed myproject
check_refuses "a planted secret is caught by the scan gate"      $NAS test mirror-secret-scan myproject
uc_summary
