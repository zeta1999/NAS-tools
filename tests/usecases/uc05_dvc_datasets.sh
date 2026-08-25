#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC05 "ML datasets versioned with DVC" "SPECS §19.5, §17" "M3"
check         "gateway serves an S3 endpoint on loopback"        $NAS gateway status --face s3
check         "dvc push/pull round-trips through the gateway"    $NAS test dvc-roundtrip datasets
# DVC's whole-file cache is exactly what our CDC repairs (SPECS §17).
check         "one changed CSV row transfers KB, not GB"         $NAS test dvc-incremental datasets --rows 1 --max-transfer 5MiB
check         "DVC's MD5 is treated as a name, not integrity"    $NAS test dvc-md5-not-trusted datasets
check         "an unauthenticated local process is refused"      $NAS test gateway-auth-required
uc_summary
