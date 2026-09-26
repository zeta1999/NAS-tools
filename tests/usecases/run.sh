#!/usr/bin/env bash
# Runs every use-case acceptance test and prints a matrix.
#
# Exit 1 on any FAIL. PENDING is reported, never counted as success.
# NAS_MILESTONE (default M0) bounds which assertions actually execute.
cd "$(dirname "$0")"

# A private NAS_HOME per run. Without this the suite would either scribble in
# the user's real namespace directory or fail on the second run, since
# `ns create` refuses to overwrite an existing namespace.
if [ -z "${NAS_HOME:-}" ]; then
  NAS_HOME=$(mktemp -d "${TMPDIR:-/tmp}/nas-acceptance.XXXXXX")
  export NAS_HOME
  trap 'rm -rf "$NAS_HOME"' EXIT
fi

# The fixture is generated, not committed: it is 1.3 MB of pseudo-random bytes
# that compress to nothing and would bloat every clone.
#
# Rebuilt when make.sh is NEWER than the tree, not only when the tree is
# absent. The confidentiality assertions search the peer for markers and file
# names this script plants, so a corpus generated before one of them was added
# is a corpus in which that assertion passes because nothing was planted --
# green, and testing nothing. (`nas test peer-no-plaintext` checks this too and
# refuses; the rebuild is so it never has to.)
if [ ! -d fixtures/tree ] || [ fixtures/make.sh -nt fixtures/tree ]; then
  ./fixtures/make.sh >/dev/null
fi

# Passphrase-mode assertions need a passphrase and there is no tty here. A fixed
# test value, set in the harness rather than defaulted inside the binary -- a
# binary that invented a passphrase when none was given would be worse than one
# that refused.
export NAS_PASSPHRASE="${NAS_PASSPHRASE:-acceptance suite five diceware words}"

# The git-face and mirror checks build throwaway repositories and commit into
# them. Those commits must not depend on the developer's git configuration,
# so the harness supplies its own and ignores both the user and system files.
#
# Measured, not hypothetical: on a machine with `commit.gpgsign = true` and
# `gpg.format = ssh`, every one of those commits dies with "failed to write
# commit object" and the suite reports 89 passed / 17 failed. The same tree
# with signing off reports 106 / 0. A suite whose result depends on whether
# the developer signs commits is measuring the laptop, not the product -- and
# it is how a green 106/0 came to be recorded while other machines saw 17
# failures.
#
# An identity is set for the opposite reason: a fresh CI image has none, and
# `git commit` there fails with "Please tell me who you are". Setting both
# here makes the run identical on a developer box and in a container.
if [ -z "${NAS_KEEP_GIT_CONFIG:-}" ]; then
  _gitcfg="$NAS_HOME/.gitconfig-acceptance"
  cat > "$_gitcfg" <<'GITCFG'
[user]
	name = NAS acceptance suite
	email = acceptance@nas-tools.invalid
[commit]
	gpgsign = false
[tag]
	gpgSign = false
[init]
	defaultBranch = main
[gc]
	auto = 0
GITCFG
  export GIT_CONFIG_GLOBAL="$_gitcfg"
  export GIT_CONFIG_SYSTEM=/dev/null
fi

# git-remote-nas is the same binary as `nas` (argv0 dispatch). Put it next
# to NAS_BIN so `command -v git-remote-nas` and `git push nas://…` resolve.
if [ -n "${NAS_BIN:-}" ] && [ -x "$NAS_BIN" ]; then
  _bindir=$(cd "$(dirname "$NAS_BIN")" && pwd)
  ln -sfn "$(basename "$NAS_BIN")" "$_bindir/git-remote-nas"
  export PATH="$_bindir:$PATH"
  NAS="$_bindir/$(basename "$NAS_BIN")"
fi

tp=0; tf=0; tpend=0; rc=0
for f in uc*.sh; do
  # The manual drills (uc10+: fixed ports, a release binary, docker) print no
  # summary by design and are run by hand; a script that never calls
  # uc_summary is not an acceptance test.
  grep -q '^uc_summary' "$f" || continue
  out=$(bash "$f" 2>&1); status=$?      # capture the SCRIPT's status, not echo's
  echo "$out"
  [ $status -ne 0 ] && rc=1
  line=$(echo "$out" | tail -1)
  if ! echo "$line" | grep -q 'passed,'; then
    printf '\033[31m  !! %s produced no summary (died early?) — treating as FAIL\033[0m\n' "$f"
    rc=1; continue
  fi
  p=$(echo "$line"  | grep -oE '[0-9]+ passed'  | grep -oE '[0-9]+'); tp=$((tp+${p:-0}))
  f2=$(echo "$line" | grep -oE '[0-9]+ failed'  | grep -oE '[0-9]+'); tf=$((tf+${f2:-0}))
  pd=$(echo "$line" | grep -oE '[0-9]+ pending' | grep -oE '[0-9]+'); tpend=$((tpend+${pd:-0}))
done
printf '\n══════════════════════════════════════════════════════\n'
printf 'use-case acceptance (≤%s): %d passed, %d failed, %d pending\n' \
  "${NAS_MILESTONE:-M0}" "$tp" "$tf" "$tpend"
[ "$tf" -gt 0 ] && rc=1
[ "$tpend" -gt 0 ] && printf 'PENDING is not success.\n'
exit $rc
