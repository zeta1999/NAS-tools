#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC14 "read-only WebDAV mount" "SPECS §8, §12.9" "M4"
check "gateway advertises a WebDAV face on loopback"          $NAS gateway status --face webdav
check "an unauthenticated WebDAV client is challenged"        $NAS test webdav-auth-required
check "OPTIONS / PROPFIND / GET; PUT is refused"              $NAS test webdav-roundtrip share
check "a ranged GET fetches O(range), not O(file)"            $NAS test ranged-read share
check "the chunk cache is sealed under a per-boot key"        $NAS test cache-sealed share
uc_summary
