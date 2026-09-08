#!/usr/bin/env bash
# Builds tests/usecases/fixtures/tree — a deterministic corpus shaped like the
# work source tree UC03 describes.
#
# Deterministic on purpose: a corpus built with $RANDOM would make every
# acceptance number unreproducible, and a dedup ratio measured today would not
# be the ratio measured next month.
set -euo pipefail
cd "$(dirname "$0")"
out=tree
rm -rf "$out"
mkdir -p "$out"/src/deep "$out"/docs "$out"/.hidden

# Deterministic pseudo-random bytes. The input is bounded rather than piping
# /dev/zero into `head -c`: that form SIGPIPEs openssl, which `set -o pipefail`
# correctly reports as a failure.
gen() { # $1=bytes $2=seed
  head -c "$1" /dev/zero | openssl enc -aes-256-ctr -nosalt -pbkdf2 -pass "pass:$2" 2>/dev/null
}

printf '# work tree fixture\n' > "$out/README.md"
: > "$out/empty"
printf 'a\n' > "$out/tiny.txt"
gen 4096    seed-lib   > "$out/src/lib.rs"
gen 200000  seed-main  > "$out/src/main.rs"
gen 1048576 seed-deep  > "$out/src/deep/data.bin"
gen 70000   seed-guide > "$out/docs/guide.txt"
gen 300     seed-hid   > "$out/.hidden/config"
# A duplicate of an existing file, so intra-tree dedup is exercised too.
cp "$out/src/lib.rs" "$out/docs/copy-of-lib.rs"
# A file whose NAME is the secret. Everything else here is named the way a
# source tree is named -- README.md, main.rs, config, tiny.txt -- and a generic
# name is not evidence: `config` is also what the namespace's own plaintext
# configuration file is called, so a "no filename on the peer" check built on
# it would be red on every honest run. `copy-of-lib.rs` above and this one are
# the two that cannot collide with anything the peer legitimately writes, and
# they are the set nas-cli's peerscan module looks for.
gen 900 seed-minutes > "$out/docs/q3-board-minutes-CONFIDENTIAL.md"

echo "fixture built: $(find "$out" -type f | wc -l | tr -d ' ') files, $(du -sk "$out" | cut -f1) KiB"
