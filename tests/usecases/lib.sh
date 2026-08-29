# Shared harness for use-case acceptance tests.
#
# These encode SPECS.md §19's cookbook as EXECUTABLE acceptance criteria,
# written before the implementation so it cannot quietly redefine success.
#
# Three properties this harness must have, each of which it lacked in its first
# version and each of which was a real defect:
#
#   1. MILESTONE GATING. Without it, the moment a `nas` binary exists every
#      assertion in every script runs -- including M5 ones -- so CI goes
#      permanently red and the gate gets disabled. Which is precisely the
#      failure the harness exists to prevent.
#   2. A REFUSAL CONTRACT. "Any non-zero exit means correctly refused" makes a
#      stub CLI that errors on everything pass all the security assertions.
#      A refusal is exit code 2, specifically. Anything else non-zero is BROKEN,
#      and is reported as such.
#   3. HONEST AGGREGATION. See run.sh: `$?` after an `echo` is echo's status.
set -uo pipefail

NAS="${NAS_BIN:-$(command -v nas 2>/dev/null || echo "")}"
# Highest milestone whose assertions should actually execute.
NAS_MILESTONE="${NAS_MILESTONE:-M0}"
# Exit code the CLI must use for "refused by policy", distinct from any other
# failure. Contract, not convention: nas-cli must honour it.
NAS_REFUSED_EXIT="${NAS_REFUSED_EXIT:-2}"

UC_ID=""; UC_TITLE=""; UC_REF=""; UC_DEFAULT_MS=""
PASS=0; FAIL=0; PEND=0

_ms_rank() { case "$1" in M0) echo 0;; M1) echo 1;; M2) echo 2;; M3) echo 3;;
                          M4) echo 4;; M5) echo 5;; M6) echo 6;; *) echo 9;; esac; }

uc_begin() { UC_ID="$1"; UC_TITLE="$2"; UC_REF="$3"; UC_DEFAULT_MS="$4"
  printf '\n\033[1m%s — %s\033[0m  (%s, default %s; running ≤%s)\n' \
    "$UC_ID" "$UC_TITLE" "$UC_REF" "$UC_DEFAULT_MS" "$NAS_MILESTONE"; }

# Pull an optional leading milestone token (M0..M6) off the argument list, so an
# individual assertion can be tagged above its script's default. UC01 is an M1
# use case that contains M2 rollback-detection work; per-script tagging alone
# would lie about that.
_take_ms() { if [[ "${1:-}" =~ ^M[0-6]$ ]]; then echo "$1"; else echo "$UC_DEFAULT_MS"; fi; }

_skip() { # $1=desc $2=milestone $3=reason
  printf '  \033[33m○ PENDING\033[0m %s\n    └ %s\n' "$1" "$3"; PEND=$((PEND+1)); }

_gate() { # $1=milestone -> 0 run, 1 skip
  [ -z "$NAS" ] && return 1
  [ "$(_ms_rank "$1")" -le "$(_ms_rank "$NAS_MILESTONE")" ] || return 1
  return 0
}

_reason() { [ -z "$NAS" ] && echo "no nas binary; unblocked by $1" \
            || echo "assertion is $1; harness running ≤$NAS_MILESTONE"; }

# Assert something must succeed.
check() {
  local ms; ms=$(_take_ms "$1"); [[ "${1:-}" =~ ^M[0-6]$ ]] && shift
  local desc="$1"; shift
  if ! _gate "$ms"; then _skip "$desc" "$ms" "$(_reason "$ms")"; return 0; fi
  if "$@" >/dev/null 2>&1; then
    printf '  \033[32m✓\033[0m %s\n' "$desc"; PASS=$((PASS+1))
  else
    printf '  \033[31m✗ FAIL\033[0m %s\n' "$desc"; FAIL=$((FAIL+1))
  fi
}

# Assert something must be REFUSED. Distinguishes refusal from breakage: a
# missing subcommand, a panic or a crash is a FAIL, not a pass.
check_refuses() {
  local ms; ms=$(_take_ms "$1"); [[ "${1:-}" =~ ^M[0-6]$ ]] && shift
  local desc="$1"; shift
  if ! _gate "$ms"; then _skip "$desc" "$ms" "$(_reason "$ms")"; return 0; fi
  "$@" >/dev/null 2>&1; local rc=$?
  case $rc in
    0) printf '  \033[31m✗ FAIL\033[0m %s\n    └ it SUCCEEDED and must not\n' "$desc"; FAIL=$((FAIL+1));;
    "$NAS_REFUSED_EXIT") printf '  \033[32m✓\033[0m %s  (refused, exit %s)\n' "$desc" "$rc"; PASS=$((PASS+1));;
    *) printf '  \033[31m✗ FAIL\033[0m %s\n    └ BROKEN, not refused: exit %d (a refusal is exit %s)\n' \
         "$desc" "$rc" "$NAS_REFUSED_EXIT"; FAIL=$((FAIL+1));;
  esac
}

# ── Harness-side verification ────────────────────────────────────────
#
# Everything above grades an EXIT CODE, and that is a weaker signal than it
# reads as: a review wrote an 8-line shell script that matched four substrings
# and scored 25 of 25. The substance of each assertion lives inside the
# `nas test ...` subcommands -- which is to say, inside the binary under test.
# The binary grades its own homework, and the harness cannot tell it from an
# oracle.
#
# These primitives are the harness doing its own verification: they look at the
# filesystem directly, so passing them requires actually storing something. They
# do not make the suite independent -- only rewriting the assertions as
# side-effect checks would -- but they close the "any binary that exits 0" hole
# for the assertions that matter most.

# Assert a path exists and is non-empty.
check_creates() { # $1=milestone? $2=desc $3=path
  local ms; ms=$(_take_ms "$1"); [[ "${1:-}" =~ ^M[0-6]$ ]] && shift
  local desc="$1" path="$2"
  if ! _gate "$ms"; then _skip "$desc" "$ms" "$(_reason "$ms")"; return 0; fi
  if [ -s "$path" ] || [ -n "$(ls -A "$path" 2>/dev/null)" ]; then
    printf '  \033[32m✓\033[0m %s\n' "$desc"; PASS=$((PASS+1))
  else
    printf '  \033[31m✗ FAIL\033[0m %s\n    └ nothing at %s\n' "$desc" "$path"
    FAIL=$((FAIL+1))
  fi
}

# Assert a byte string does NOT appear anywhere under a directory. The harness
# greps for itself rather than asking the binary whether it leaked.
check_absent_under() { # $1=milestone? $2=desc $3=dir $4=needle
  local ms; ms=$(_take_ms "$1"); [[ "${1:-}" =~ ^M[0-6]$ ]] && shift
  local desc="$1" dir="$2" needle="$3"
  if ! _gate "$ms"; then _skip "$desc" "$ms" "$(_reason "$ms")"; return 0; fi
  if [ ! -d "$dir" ]; then
    printf '  \033[31m✗ FAIL\033[0m %s\n    └ %s does not exist, so nothing was stored\n' \
      "$desc" "$dir"; FAIL=$((FAIL+1)); return 0
  fi
  if grep -rqa -- "$needle" "$dir" 2>/dev/null; then
    printf '  \033[31m✗ FAIL\033[0m %s\n    └ found %q under %s\n' "$desc" "$needle" "$dir"
    FAIL=$((FAIL+1))
  else
    printf '  \033[32m✓\033[0m %s\n' "$desc"; PASS=$((PASS+1))
  fi
}

# Assert a byte string DOES appear (transit-only: visible names are correct).
check_present_under() { # $1=milestone? $2=desc $3=dir $4=needle
  local ms; ms=$(_take_ms "$1"); [[ "${1:-}" =~ ^M[0-6]$ ]] && shift
  local desc="$1" dir="$2" needle="$3"
  if ! _gate "$ms"; then _skip "$desc" "$ms" "$(_reason "$ms")"; return 0; fi
  if grep -rqa -- "$needle" "$dir" 2>/dev/null; then
    printf '  \033[32m✓\033[0m %s\n' "$desc"; PASS=$((PASS+1))
  else
    printf '  \033[31m✗ FAIL\033[0m %s\n    └ %q not found under %s\n' "$desc" "$needle" "$dir"
    FAIL=$((FAIL+1))
  fi
}

uc_summary() { printf '\n  %d passed, %d failed, %d pending\n' "$PASS" "$FAIL" "$PEND"
  [ "$FAIL" -eq 0 ]; }
