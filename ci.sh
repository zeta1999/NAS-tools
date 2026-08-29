#!/usr/bin/env bash
# Full gate. Matches the sibling repos' ci.sh convention.
set -uo pipefail
cd "$(dirname "$0")"
CI_MILESTONE="${CI_MILESTONE:-M1}"
CI_MILESTONE_N="${CI_MILESTONE#M}"
fail=0
step() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }

step "fmt";    cargo fmt --check || fail=1
step "clippy"; cargo clippy --all-targets -- -D warnings 2>&1 | tail -3 || fail=1
step "test";   cargo test --workspace 2>&1 | grep -E "^test result|error" || fail=1
step "formal"; ./formal/check.sh || fail=1
# Release, because the acceptance suite chunks and encrypts megabytes and an
# unoptimised build turns a 2-second gate into a minute.
step "cli";   cargo build --release -p nas-cli 2>&1 | tail -2 || fail=1
# The suite runs at the CURRENT milestone, not at the harness default.
#
# It previously ran at M0, so CI gated 5 assertions while STATUS.md cited 25 --
# a regression in any of the other 20 (all of passphrase mode, every e2ee peer
# assertion, the transit-only ACL) could not turn CI red. Raise this as
# milestones land; that is the point of it being a variable.
step "use-case acceptance (M$CI_MILESTONE_N)"
NAS_MILESTONE="$CI_MILESTONE" NAS_BIN="$PWD/target/release/nas" \
  ./tests/usecases/run.sh || fail=1

printf '\n══════════════════════════════════\n'
[ $fail -eq 0 ] && echo "ci: PASS" || echo "ci: FAIL"
exit $fail
