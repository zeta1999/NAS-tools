#!/usr/bin/env bash
# Full gate. Matches the sibling repos' ci.sh convention.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
step() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }

step "fmt";    cargo fmt --check || fail=1
step "clippy"; cargo clippy --all-targets -- -D warnings 2>&1 | tail -3 || fail=1
step "test";   cargo test --workspace 2>&1 | grep -E "^test result|error" || fail=1
step "formal"; ./formal/check.sh || fail=1
# Release, because the acceptance suite chunks and encrypts megabytes and an
# unoptimised build turns a 2-second gate into a minute.
step "cli";   cargo build --release -p nas-cli 2>&1 | tail -2 || fail=1
step "use-case acceptance"
# PENDING assertions are reported, never counted as passing. run.sh exits
# non-zero on FAIL only -- but that status was previously discarded, so a
# failing assertion could not have turned CI red. It can now.
NAS_BIN="$PWD/target/release/nas" ./tests/usecases/run.sh || fail=1

printf '\n══════════════════════════════════\n'
[ $fail -eq 0 ] && echo "ci: PASS" || echo "ci: FAIL"
exit $fail
