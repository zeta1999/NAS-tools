#!/usr/bin/env bash
. "$(dirname "$0")/lib.sh"
uc_begin UC15 "Shared notes, two writers" "SPECS §7, §7.2" "M6"
check         "a document round-trips through the op-log"        $NAS test doc-roundtrip notes
check         "concurrent inserts from two writers both survive" $NAS test doc-concurrent-merge notes
check         "the op-log never leaves the encrypted namespace"  $NAS test doc-oplog-encrypted notes
check         "compaction shrinks the log and keeps the text"    $NAS test doc-compact notes
check         "poll interval is sub-second while editing"        $NAS test doc-poll-active notes
check         "poll interval is minutes when idle"               $NAS test doc-poll-idle notes
uc_summary
