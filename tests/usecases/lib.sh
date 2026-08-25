# Shared harness for use-case acceptance tests.
#
# These encode SPECS.md §19's cookbook as EXECUTABLE acceptance criteria. They
# are written before the implementation deliberately: each one is the definition
# of done for a use case the user actually described, not a test invented to
# match whatever the code happens to do.
#
# A test that cannot run yet reports PENDING with the milestone that unblocks
# it. PENDING is never silently treated as success.
set -uo pipefail

NAS="${NAS_BIN:-$(command -v nas 2>/dev/null || echo "")}"
UC_ID=""; UC_TITLE=""; UC_REF=""; UC_NEED=""
PASS=0; FAIL=0; PEND=0
declare -a RESULTS=()

uc_begin() { UC_ID="$1"; UC_TITLE="$2"; UC_REF="$3"; UC_NEED="$4"
  printf '\n\033[1m%s — %s\033[0m  (%s, needs %s)\n' "$UC_ID" "$UC_TITLE" "$UC_REF" "$UC_NEED"; }

# Every assertion states WHAT is being proven, not just that a command exits 0.
check() {
  local desc="$1"; shift
  if [ -z "$NAS" ]; then
    printf '  \033[33m○ PENDING\033[0m %s\n    └ no nas binary; unblocked by %s\n' "$desc" "$UC_NEED"
    PEND=$((PEND+1)); RESULTS+=("PEND|$UC_ID|$desc"); return 0
  fi
  if "$@" >/dev/null 2>&1; then
    printf '  \033[32m✓\033[0m %s\n' "$desc"; PASS=$((PASS+1)); RESULTS+=("PASS|$UC_ID|$desc")
  else
    printf '  \033[31m✗ FAIL\033[0m %s\n' "$desc"; FAIL=$((FAIL+1)); RESULTS+=("FAIL|$UC_ID|$desc")
  fi
}

# For properties whose whole point is that something must NOT be possible.
check_refuses() {
  local desc="$1"; shift
  if [ -z "$NAS" ]; then
    printf '  \033[33m○ PENDING\033[0m %s\n    └ no nas binary; unblocked by %s\n' "$desc" "$UC_NEED"
    PEND=$((PEND+1)); RESULTS+=("PEND|$UC_ID|$desc"); return 0
  fi
  if "$@" >/dev/null 2>&1; then
    printf '  \033[31m✗ FAIL\033[0m %s  (it SUCCEEDED and must not)\n' "$desc"; FAIL=$((FAIL+1)); RESULTS+=("FAIL|$UC_ID|$desc")
  else
    printf '  \033[32m✓\033[0m %s  (correctly refused)\n' "$desc"; PASS=$((PASS+1)); RESULTS+=("PASS|$UC_ID|$desc")
  fi
}

uc_summary() { printf '\n  %d passed, %d failed, %d pending\n' "$PASS" "$FAIL" "$PEND"
  [ "$FAIL" -eq 0 ]; }
