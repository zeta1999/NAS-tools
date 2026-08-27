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

echo "fixture built: $(find "$out" -type f | wc -l | tr -d ' ') files, $(du -sk "$out" | cut -f1) KiB"
