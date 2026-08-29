# Manual testing trace

Reproducible commands with **actually observed** output. Every block here was
run on the dev machine; nothing is aspirational. Anything not yet runnable lives
in `tests/usecases/` as a PENDING acceptance assertion instead.

Machine: macOS 26.5.2, aarch64, 16 GB RAM. Lean 4.28.0, Java 17.0.18,
Docker 29.3.0, colima 0.10.1.

---

## 1. Formal verification gate

```sh
cd formal && ./check.sh
```

Observed (2026-08-25):

```
── Lean ──────────────────────────────────────────────────────────
no-sorry gate                                  ok
lean/NasVerify/Transcript.lean                 verified
── TLA+ ──────────────────────────────────────────────────────────
SlotConsistency invariants (MaxSeq=2)          ok — 38709 distinct states
sanity: NeverForks                             violated as required
sanity: NeverAlarms                            violated as required
sanity: ForkAlwaysDetected                     violated as required
──────────────────────────────────────────────────────────────────
formal: PASS
```

`check.sh` fetches `tla2tools.jar` (2.2 MB) on first run; it is gitignored.

### 1a. Deep model check

```sh
cd formal && DEEP=1 ./check.sh
```

Observed at `MaxSeq=3`:

```
60101058 states generated, 4699837 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 30.
Finished in 46s
```

Takes ~46 s and ~3 GB heap. Fine on 16 GB; do not run it concurrently with a
`cargo build`.

### 1b. Reproducing the defect the model caught

Revision 1 of `SlotConsistency.tla` failed in 7 states. To see it, restore the
`pinSeq[c] > 0` guard in `RelayWitness` and re-run — TLC reports
`Invariant ForkDetected is violated` with a trace where a witness reaches a
client that has not yet pinned anything, is dropped, and is never reconsidered.
That is a real client bug shape, not a modelling artefact: "handle the event,
then forget it" is the default way anyone would implement it.

### 1c. Confirming the sanity checks still bite

```sh
cd formal/tlaplus
java -Xmx2g -cp tla2tools.jar tlc2.TLC -nowarning \
  -config MC_ForkAlwaysDetected.cfg SlotConsistency | grep -A2 "is violated"
```

Must print a violation. If it ever stops doing so, the green run in §1 is
meaningless and `check.sh` fails the build.

---

### 1d. Confirming the Lean gates bite

Same discipline as the TLA+ sanity checks: a gate that has never failed is not
known to work. Both cheats were injected as a temporary file under
`formal/lean/NasVerify/` and removed afterwards.

An `axiom` declaration — invisible to a `sorry` grep:

```lean
namespace GateTest
axiom cheating : 1 = 2
theorem bogus : 1 = 2 := cheating
#print axioms bogus
end GateTest
```

Observed (2026-08-27):

```
no-sorry gate                                  ok
lean/NasVerify/Padding.lean                    verified (8 theorems, axioms clean)
lean/NasVerify/Transcript.lean                 verified (3 theorems, axioms clean)
lean/NasVerify/ZZGateTest.lean                 FAIL — unexpected axioms: GateTest.cheating
```

An admitted proof:

```lean
theorem admitted : 1 = 2 := by sorry
```

```
lean/NasVerify/ZZGateTest.lean:2:theorem admitted : 1 = 2 := by sorry
no-sorry gate                                  FAIL — admitted proofs found
lean/NasVerify/ZZGateTest.lean                 FAIL
'GateTest.admitted' depends on axioms: [sorryAx]
```

Caught twice over, which is the point: the axiom check is strictly stronger than
the token grep, since `sorryAx` shows up whether or not the word `sorry` appears
in the source. The token grep survives only as belt-and-braces, and now strips
backticked prose so documentation may name `sorry` without tripping it.

With both files removed the gate returns to `formal: PASS`.

---

## 2. Upstream `simple-network` protocol v1

```sh
cd ../simple-network
cargo test  --no-default-features --features pqc --lib
cargo clippy --no-default-features --features pqc --lib --tests -- -D warnings
cargo fmt --check
```

Observed:

```
cargo test: 15 passed (1 suite, 5.66s)
cargo clippy: No issues found
fmt clean
```

Note `--no-default-features` is required: `examples/rust_demo.rs:3` uses
`simple_network::ffi` unconditionally while `ffi` is a default-on feature, so
`--examples` fails to build. **Pre-existing**, unrelated to protocol v1, and
already listed in that repo's own TODO.

### 2a. The four new tests, and what each proves

| Test | Proves |
|---|---|
| `relayed_hello_rejected_by_a_different_server` | unknown-key-share is closed — a hello signed for server A is refused by server B even though B pins the same client |
| `v0_hello_rejected_with_a_version_error` | no silent downgrade; a pre-binding peer fails loudly on version, not obscurely on a signature |
| `session_keys_depend_on_the_transcript` | identical KEM secret + different transcripts ⇒ independent record keys |
| `transcript_encoding_is_unambiguous` | length prefixes disambiguate field boundaries (the Rust counterpart of `encFields_inj`) |

### 2b. Behaviour change to be aware of

`wrong_pinned_identity_rejected` had to be rewritten. Under v0 the server
completed the handshake and only the client caught the mismatch; under v1 the
server rejects one round trip earlier and never builds a half-open session. The
test now forges an impostor response to exercise the client-side pin check.

**Wire-breaking:** v0 and v1 peers will not talk, deliberately. `simple-backups`
push/pull rides this channel, so both ends of a paired deployment upgrade
together.

---

## 3. Use-case acceptance harness

```sh
./tests/usecases/run.sh
```

Observed: `0 passed, 0 failed, 81 pending`.

88 assertions across 9 use cases, each tagged with the milestone that unblocks
it. **PENDING is never counted as success** — the runner says so explicitly and
exits non-zero on any FAIL.

To run one use case:

```sh
bash tests/usecases/uc04_legal_records_worm.sh
```

Once a `nas` binary exists, point the harness at it:

```sh
NAS_BIN=./target/debug/nas ./tests/usecases/run.sh
```

---

## 4. `nas-crypto` — the key schedule

```sh
cargo test -p nas-crypto
```

Observed: `12 passed`.

### 4a. Why `rust-secure-memory` needed a change first

`secure_memory::crypto::encrypt_aad` generates its nonce internally with
`OsRng` (`crypto.rs:72`). Convergent encryption is therefore **impossible**
through that API: identical plaintext encrypts differently every time and
deduplication silently collapses to zero — it would not fail loudly, it would
just quietly stop saving space.

SPECS §3 claims "all primitives already exist in the sibling crates." That is
false for this path. Fixed upstream by adding `seal_with_nonce` /
`open_with_nonce` (`rust-secure-memory` commit `ff19f55`), with a deliberately
loud doc comment, and `encrypt_aad` refactored to go through it so there is one
AEAD call site rather than two.

The footgun therefore lives in exactly one place, and `nas-crypto` makes it
unreachable: `Key` has no public constructor accepting a nonce policy. The
policy is set by the derivation function, and `seal` reads it from the key.
**A caller cannot choose a nonce, correctly or otherwise.**

### 4b. The four assertions that matter

| Test | Proves |
|---|---|
| `convergent_sealing_is_deterministic` | identical plaintext under one secret gives byte-identical ciphertext — the property dedup is built on |
| `a_different_convergence_secret_breaks_dedup_and_the_oracle` | two tenants storing one file produce different ciphertext, so a co-tenant learns nothing |
| `manifest_keys_never_seal_the_same_bytes_twice` | path-derived keys get a random nonce; a deterministic one here would be keystream reuse across manifest versions |
| `convergence_iff_same_plaintext` (proptest) | convergence happens exactly when the plaintext matches — never more, never less |

Plus `open_never_panics` over arbitrary bytes, because a hostile peer supplies
everything that reaches it.

---

## 5. `nas-store` — padding overhead on a real corpus (M0 exit criterion)

SPECS §4.2.1 estimated the padding premium at "20-35%" and required it be
**measured, not assumed** before anyone enables it. This is that measurement.

```sh
cargo build --release -p nas-store --example measure
./target/release/examples/measure ~/work/simple-network ~/work/rust-secure-memory ~/work/NAS-tools
```

Observed (2026-08-27) — a source-tree corpus, `target/` and `.git/` excluded:

```
corpus: 12904 files under /Users/.../simple-network, /Users/.../rust-secure-memory, /Users/.../NAS-tools

profile      plaintext B      stored B  overhead  vs none   chunks   dedup
None           481016592     465203251     -3.3%     0.0%    15712    7.1%
Classes        481016592     918097920     90.9%    97.4%    15712    7.1%
Fixed          481016592    1129460960    134.8%   142.8%    18365    6.2%

peak RSS: 9060352 bytes (8.6 MiB)
```

```sh
./target/release/examples/measure ~/work/price-master-examples/bin
```

Observed (2026-08-27) — 27 large binaries, several of which are byte-identical
splits of the others, so this corpus also exercises deduplication:

```
corpus: 27 files under /Users/.../price-master-examples/bin

profile      plaintext B      stored B  overhead  vs none   chunks   dedup
None           631374555     290071832    -54.1%     0.0%     7724   54.1%
Classes        631374555     451632528    -28.5%    55.7%     7724   54.1%
Fixed          631374555     529791264    -16.1%    82.6%     9649   16.2%

peak RSS: 5816320 bytes (5.5 MiB)
```

### 5a. The estimate in the specification was wrong

| | SPECS §4.2.1 estimate | measured, large files | measured, source tree |
|---|---|---|---|
| `classes` premium | 20-35% | **+55.7%** | **+97.4%** |
| `fixed` premium | "~0%" | **+82.6%** | **+142.8%** |

Two separate causes, and both were missed:

1. **On any corpus, the ladder doubles.** Chunks averaged 81.7 KiB on the large
   corpus and pad to the 128 KiB class — 1.57×, which is exactly the observed
   figure. A ×2 ladder costs ~1.5× for *any* chunk-size distribution that is not
   already concentrated just below a class boundary. There was never a corpus on
   which 20-35% was achievable with this ladder.
2. **Small files pay the 32 KiB floor.** In the source corpus 11178 of 12904
   files (86%) are under 32764 B and hold 12% of the bytes; each still occupies a
   full 32 KiB class. Those files alone account for ~306 MB of the ~453 MB
   premium. Padding overhead is therefore driven by **file count**, not by
   content or by CDC tuning.

`fixed` was described as "~0%" overhead in the profile table. That is true of the
*chunking* — no CDC, so no boundary drift — and false of the storage, because
every trailing partial chunk still rounds up to 64 KiB. Worse on the source
corpus than `classes`, since most files are a single short chunk.

**Consequences carried back into SPECS §4.2.1 (revision 6):** the estimate is
replaced by these figures. `none` remaining the default is reinforced, not
merely confirmed — the premium is 2-3× what the decision was originally made
against. A denser ladder (1.25× or 1.5× steps) would cut the premium
substantially in exchange for a finer length fingerprint; that trade is now a
recorded open question rather than an assumption.

### 5b. Streaming is real, not claimed

Peak RSS was **5.5 MiB while writing 631 MB** and 8.6 MiB across 12904 files.
Memory tracks the chunker window (`2 × max`, 512 KiB) plus one chunk in flight,
not file size. The 44 MB single file in the source corpus did not move the
figure. Measured with `getrusage(RUSAGE_SELF)`, not estimated.

### 5c. Deduplication works end to end

The large-file corpus is 27 files of which 12 are `.partNN` splits of three
binaries. Content-defined chunking plus convergent encryption recovered **54.1%**
of it without being told the files were related. `fixed` recovered only 16.2% on
the same corpus — the shift-sensitivity the profile table warns about, visible in
a number.

---

## 6. `nas-cli` — the M0 acceptance assertions actually run

```sh
cargo build --release -p nas-cli
NAS_BIN=$PWD/target/release/nas ./tests/usecases/run.sh
```

`run.sh` creates a private `NAS_HOME` per run and generates
`fixtures/tree` if absent — 9 files, 1.3 MB, deterministic (BLAKE3-seeded via
`openssl enc -aes-256-ctr`, so a dedup ratio measured today is the same ratio
next month). The fixture is `.gitignore`d: it is incompressible pseudo-random
bytes that would bloat every clone.

Observed (2026-08-27):

```
UC03 — Work source code, fully end-to-end encrypted  (SPECS §19.3, default M0; running ≤M0)
  ✓ namespace created in e2ee mode
  ✓ round-trip is byte-identical
  ✓ two trees sharing 90% transfer ~10% of bytes
  ○ PENDING peer disk contains no plaintext marker      └ assertion is M1
  ○ PENDING path segments are encrypted on the peer     └ assertion is M1
  ○ PENDING listing resolves locally                    └ assertion is M1
  ✓ confirmation attack succeeds WITH the secret
  ✓ confirmation attack fails WITHOUT the secret  (refused, exit 2)
  ○ PENDING no dedup across tenants                     └ assertion is M1

use-case acceptance (≤M0): 5 passed, 0 failed, 78 pending
```

The individual commands, run directly:

```
$ nas ns create work --mode e2ee
created work at .../nashome/work
  mode e2ee, padding None
  M0: secrets are stored UNENCRYPTED at 0600. nas-vault (M1) replaces this.

$ nas test roundtrip work ./fixtures/tree
roundtrip ok: 13 entries, mode E2ee, padding None, root 1e10701cf772c6da…

$ nas test dedup-ratio work --shared 90 --max-transfer 15
second tree of 8388608 B added 851168 B (10.1%), budget 15%

$ nas test confirmation-attack work --with-cs
confirmation attack SUCCEEDED with CS: 3/3 chunks located          # exit 0

$ nas test confirmation-attack work --without-cs
refused: … located 0/3 chunks — the secret is load-bearing         # exit 2
```

10.1% transfer for a 90%-shared pair is the figure SPECS §19.3 predicts.

### 6a. Confirming the assertions bite

An acceptance suite that has never failed is not known to test anything. Two
stub binaries, same discipline as the TLA+ sanity checks and the Lean gates:

```sh
printf '#!/bin/sh\nexit 0\n'  > /tmp/always-ok   && chmod +x /tmp/always-ok
printf '#!/bin/sh\nexit 1\n'  > /tmp/always-fail && chmod +x /tmp/always-fail
NAS_BIN=/tmp/always-ok   ./tests/usecases/run.sh
NAS_BIN=/tmp/always-fail ./tests/usecases/run.sh
```

Observed:

```
=== always succeeds ===
  ✓ namespace created in e2ee mode
  ✓ round-trip is byte-identical
  ✓ two trees sharing 90% transfer ~10% of bytes
  ✓ confirmation attack succeeds WITH the secret
  ✗ FAIL confirmation attack fails WITHOUT the secret
        └ it SUCCEEDED and must not

=== always fails with exit 1 ===
  ✗ FAIL namespace created in e2ee mode
  ✗ FAIL round-trip is byte-identical
  ✗ FAIL two trees sharing 90% transfer ~10% of bytes
  ✗ FAIL confirmation attack succeeds WITH the secret
  ✗ FAIL confirmation attack fails WITHOUT the secret
        └ BROKEN, not refused: exit 1 (a refusal is exit 2)

always-ok   -> exit 1
always-fail -> exit 1
real nas    -> exit 0
```

The second stub is the one that matters. "Any non-zero means correctly refused"
would have scored `always-fail` as passing every security assertion in the
suite; the exit-2 contract reports it as **BROKEN** instead. That contract is
why `nas` exits **3** for anything specified-but-unbuilt: an unimplemented
subcommand must never be mistaken for a working security control.

### 6b. A gap in `ci.sh` that this exposed

`ci.sh` ran the acceptance suite as `./tests/usecases/run.sh | tail -3` with no
`|| fail=1`. While every assertion was PENDING that was invisible. The moment
assertions began to run it meant **a failing acceptance test could not turn CI
red**. Fixed in the same commit; the suite's status is now checked.

---

## 7. M0 brutal review — four confirmed defects, all fixed

A Fable-5 adversarial review of M0. It reproduced **four** defects. Each was
independently re-reproduced here before being fixed, and each now has a
regression test that fails against the old code.

### 7a. `Addr::from_hex` panicked on 64-*byte* multibyte input — reachable from an untrusted peer

`addr.rs` checked `s.len() != 64` (bytes) and then sliced `&s[i*2..i*2+2]`,
which panics if an index falls inside a multibyte character.

```
$ # "a" + "é"×31 + "a"  — 64 bytes, 33 characters
thread 'main' panicked at crates/nas-core/src/addr.rs:62:42:
end byte index 2 is not a char boundary; it is inside 'é' (bytes 1..3)
```

**Why this was the most serious of the four.** `BlobStore::addrs()` builds this
string from **peer-controlled** blob directory names and relies on the `Err`
branch to skip junk — the comment there says a peer "cannot be allowed to break
a GC sweep by dropping a file in". The panic fires before any `Result` exists,
so a malicious peer could halt the lease sweep (SPECS §6) with one filename.

Fixed by parsing the byte slice, which removes the char-boundary question
entirely. Uppercase hex is now rejected too, so one address has one spelling.
Added a proptest over `".*"` — there was none before, and both hand-written
cases were ASCII, which is exactly why this survived.

### 7b. `DirManifest::decode` panicked on a truncated final entry

```rust
while i + 2 < f.len() + 1 && i + 2 <= f.len() {   // both clauses are the same
    ... f[i + 2] ...                              // needs i + 2 < f.len()
```

```
$ # a 3-field manifest: magic, name, kind — payload missing
thread 'main' panicked at crates/nas-store/src/tree.rs:165:28:
index out of bounds: the len is 3 but the index is 3
```

### 7c. `DirManifest::decode` silently dropped trailing fields

```
#2: clean 79 B, tainted 99 B, decode-equal = true
```

Two distinct encodings decoded to the same manifest. `encoding::decode_fields`
refuses trailing bytes one layer below precisely to prevent this, and `tree.rs`
threw that guarantee away. Both 7b and 7c fixed by requiring the field count to
be one magic plus an exact multiple of three (`TreeError::RaggedEntries`).

**The proptest that should have caught them was theatre.**
`decode_never_panics_on_junk` fed only random bytes — every one rejected at the
magic check, never reaching the loop. It is replaced with structured malformed
inputs: truncations of a valid encoding, and every field count from 0 to 7.

### 7d. The padding covert channel was only half closed

`unpad` checked that the length was *a* class. It did not check it was the
*minimal* class:

```
#4: minimal class = 32768 B, hand-built class = 262144 B, unpad = Ok(5)
```

Every other check passes — valid ladder length, honest length prefix, all-zero
fill — so a writer could encode ~2 bits per chunk in the class index, invisible
to every reader. Worse, it defeats the length-hiding padding exists for: a
writer that picks the class matching the true size range leaks exactly what was
meant to be hidden. Fixed with `PadError::NonMinimalClass`.

**The Lean model could not see it either.** `padLadder_length_mem` proves the
length is a ladder member; nothing proved minimality, because every theorem
quantified only over *outputs of `padLadder`*. Two theorems added:
`unpadStrict_padLadder` (no honest output is rejected) and
`unpadStrict_rejects_other_classes` (no other class is accepted). The general
lesson: a model that only quantifies over well-formed inputs says nothing about
a malicious writer.

### 7e. A format decision made now because it cannot be made later

The review flagged, and reasoning confirms, that POSIX filenames are arbitrary
bytes and `to_string_lossy` destroys them: `a\xFFb` and `a\xFEb` both become
`a\u{FFFD}b`, so the second collides with the first and the **whole tree write
fails** — and a single such file extracts under different bytes than it went in
with. Not reproducible on this machine (APFS rejects non-UTF-8 names with
`EILSEQ`), but the code path is unambiguous and this is an **on-disk format**
decision that becomes a format break once M1 freezes the layout.

Entry names are now `Vec<u8>`. Both `snapshot()` helpers were also keyed on
lossy strings — comparing mangled against mangled — so the round-trip test could
not have detected the mangling either; both now compare raw path bytes.

### 7f. What the review could not fault

It actively tried and failed to break: the nonce-policy type design (a
deterministic nonce on a non-content-derived key is inexpressible), the
`BlobStore::put` verify-then-repair path (no TOCTOU found), the
addr/AEAD/`pt_hash` composition against substitution and reordering, and the
`DirSecret` scoping (a sibling's key cannot open a subtree). The chunker's
stream/slice equivalence also held.

**Net:** the core crypto composition was sound; the **parser layer** was the weak
point. Both reachable panics were in code that untrusted bytes flow through, and
the "never panics" proptests gave false confidence by generating inputs that
were rejected before reaching the defective code. `cargo-fuzz` targets for every
peer-facing parser are raised in priority in TODO.md as a result.

---

## 8. Fuzzing — and the defect it found that the review did not

Six targets, one per parser that consumes bytes it did not write.

```sh
./fuzz/run.sh              # 60 s per target
SECS=900 ./fuzz/run.sh     # before closing a milestone
```

Needs nightly (libFuzzer) and `cargo-fuzz`. Deliberately **not** wired into
`ci.sh`: a time-boxed fuzz run is not a pass/fail gate, and making one into a
gate trades a real signal for a flaky one.

Observed (2026-08-27), after the fixes below:

```
── decode_fields (60 s) ──        ok — 21237979 runs, cov: 74
── addr_from_hex (60 s) ──        ok — 46988046 runs, cov: 57
── unpad (60 s) ──                ok — 232634 runs, cov: 55
── manifest_decode (60 s) ──      ok — 14449259 runs, cov: 112
── dir_manifest_decode (60 s) ──  ok — 13443122 runs, cov: 247
── aead_open (60 s) ──            ok — 5663936 runs, cov: 475
fuzz: PASS
```

The targets assert properties, not merely absence of panics: `decode_fields`
checks injectivity (the Lean theorem `encFields_inj`, checked against the
implementation), `unpad` checks that anything accepted re-pads to the same
bytes, `dir_manifest_decode` checks that anything accepted re-encodes
identically, and `aead_open` asserts that attacker bytes never open.

### 8a. Three canonicalisation defects, found in 45 seconds

The very first run crashed `dir_manifest_decode` — on the **canonical-form**
assertion, not on a panic. Analysis of the artifact:

```
n=3, framed fields:
  [0] len=4  head=[78, 65, 83, 68]        # NASD
  [1] len=35 head=[238, 78, 154, 154, …]  # name
  [2] len=35 head=[1, 91, 91, 91, 91, …]  # kind — THIRTY-FIVE bytes
  [3] len=35 head=[91, 91, 91, 91, 91, …] # payload
decoded 1 entries
re-encoded 91 B vs framed 125 B, equal=false
```

The decoder read `kind.first()`. A 35-byte kind field whose first byte was `1`
was accepted and **34 bytes of attacker data were silently discarded** — an
unbounded covert channel inside a sealed manifest. This survived a full
adversarial human review of the same function; the fuzzer found it in 45 s.

Investigating it surfaced two more of the same class:

| Defect | Channel |
|---|---|
| `kind` read as `.first()`, any length accepted | unbounded |
| entries not required to be in ascending name order — the `BTreeMap` sorted on the way in, `encode` re-sorted on the way out, so a permuted encoding decoded identically | log2(n!) bits |
| two sibling directories permitted to share a `dir_id` | breaks subtree capability scoping (SPECS §15.3): the same `DirSecret`, so a capability for one subtree opens the other |

All three are now `TreeError::NonCanonical`, along with an empty `dir_id` (the
encoder sets `dir_id` from the entry name and `safe_name` forbids an empty
name, so it can never emit one).

**The rule these enforce, stated once:** *the decoder must reject anything the
encoder would not emit.* Every degree of freedom a decoder tolerates and an
encoder never uses is a covert channel, invisible to every reader, and a second
byte string that means the same thing. It is the same rule as
`PadError::NonMinimalClass` and as the trailing-field rejection — three
instances of one bug, in three different parsers.

The sibling `dir_id` case is the one with teeth: it is not merely a channel but
a **capability-scoping break**, and it was reachable by a semi-trusted writer
(SPECS §3.3) against a reader holding a subtree capability.

### 8b. What this says about the review

The human review was good — it found four real defects including a
peer-reachable panic. It read this exact function and did not see the `kind`
field. Fuzzing and review are not substitutes: review found the *reachability*
argument for the `Addr::from_hex` panic (that `BlobStore::addrs` feeds it
peer-controlled names), which no fuzzer would have told me. Fuzzing found the
input a reviewer's eye slid over.

---

## 9. Four adversarial reviews, and what they broke

Four reviews ran in parallel against M1 — crypto/vault, peer/transport,
storage/consistency, and spec-fidelity. Between them they confirmed defects in
every layer. The two most damaging findings were about **the gates themselves**,
which is the worst place to have them, since a broken gate silently certifies
everything downstream of it.

### 9a. The Lean axiom gate could be opted out of

The gate parsed whatever `#print axioms` lines the source happened to contain.
A theorem that never emitted one was simply not checked. The review planted:

```lean
axiom paddingIsAlwaysFree : ∀ (L x : List Nat), (padLadder L x).isSome
theorem sneaky_unverified_claim (L x : List Nat) : (padLadder L x).isSome :=
  paddingIsAlwaysFree L x
```

with no `#print axioms` line, and the gate reported **`axioms clean`**.

Worse, §1d of this file *demonstrates the gate biting* — and that demonstration
only ever worked because the planted cheat happened to print its own axioms. The
demonstration was real and the conclusion drawn from it was wrong.

`check.sh` now extracts every `theorem`/`lemma` name from the file, appends a
generated `#print axioms` for each to a temporary copy, and requires that as many
axiom lines come back as there were declarations. Re-running the exact bypass:

```
lean/NasVerify/Padding.lean   FAIL — unexpected axioms: NasTools.paddingIsAlwaysFree
```

The in-file `#print axioms` blocks were deleted, because leaving them would
suggest the gate still reads them.

### 9b. CI gated 5 assertions while the documentation cited 25

`ci.sh` ran the acceptance suite with no `NAS_MILESTONE`, and `lib.sh` defaults
to M0. So CI ran **5** assertions. All of passphrase mode, every e2ee peer
assertion and the transit-only ACL were ungated: a regression in any of them
could not turn CI red. §6b of this file congratulates itself for making a
failing assertion turn CI red — true, but only for the five that ran.

`ci.sh` now runs at `CI_MILESTONE` (M1), and raising it is a one-line change as
milestones land.

### 9c. An 8-line stub scored 25 out of 25

The harness graded nothing but exit codes. The substance of each assertion lives
inside the `nas test …` subcommands — inside the binary under test. The binary
graded its own homework, and the harness could not tell it from an oracle. The
review wrote this and scored a perfect run:

```sh
#!/bin/sh
for a in "$@"; do case "$a" in wrong-passphrase|--without-cs|--right) exit 2;; esac; done
case "$*" in *"cross-tenant-dedup"*) exit 2;; *"acl check"*"--right write"*) exit 2;; esac
exit 0
```

`lib.sh` gained three primitives that verify **side effects the harness inspects
itself** — `check_creates`, `check_absent_under`, `check_present_under` — and
UC01 and UC03 now use them for the properties that matter most: that a namespace
really stored blobs, that no fixture text or filename appears in any of them in
`e2ee`, and that both *do* appear in `transit-only`.

Observed, same stub, after the change:

```
use-case acceptance (≤M1): 24 passed, 6 failed, 58 pending
  ✗ FAIL e2ee namespace actually stored blobs
    └ nothing at .../work/blobs
  ✗ FAIL harness finds no fixture text in any blob
    └ .../work/blobs does not exist, so nothing was stored
```

Note the second message. `check_absent_under` fails when the directory does not
exist, rather than passing because there was no leak to find — absence of
evidence from an empty store is not evidence of absence.

**This does not make the suite independent.** Twenty-four assertions still pass
for the stub, because they still only check an exit code. The honest description
of the number is: *the count is a progress marker, not third-party
verification.* STATUS.md says so now.

---

## 10. Multi-node simulation (M1)

### 10a. Two processes on localhost — done

The first end-to-end run of the networked path, release binary, no mocks:

1. `nas peer init <dir>`, then `nas peer allow` / `nas peer writer` /
   `nas peer grant` with the keys the client exported via `nas ns export-pub`.
   The peer directory holds one private file — its own transport seed — and
   otherwise only public keys and names (SPECS §10).
2. `nas peer serve <dir> --listen 127.0.0.1:<port>` in one process.
3. In a fresh `NAS_HOME`: `nas ns create`, populate it, then
   `nas peer sync <ns> --peer <addr> --peer-pub <transport.pub>` from a
   second process. The subject the peer evaluates comes from the transport key
   that completed the handshake, never from an argument.

Observed:

- The sync pushed the root record and the blobs behind it over the PQC
  handshake; the peer's blob directory afterwards contains only ciphertext
  addressed by BLAKE3 of the ciphertext, and no plaintext marker.
- A second `nas peer sync` was a **no-op**: the peer reported every blob
  already held and the CAS on the slot refused nothing because nothing changed.
- A sync with a **wrong `--peer-pub`** was refused at the handshake — the
  client never reached the point of sending a record, which is the property
  the pin exists for. A `--peer-pub` that is not exactly 32 bytes is rejected
  before any connection is opened.
- A transport key the operator has not `allow`ed is turned away before the
  KEM runs: the peer reads the hello, checks the claimed key against
  `clients/`, and a stranger costs it one JSON parse.

### 10b. Three nodes in containers — planned

The shape, given 16 GB of RAM:

- **colima with an explicit budget** — `colima start --cpu 4 --memory 6 --disk 40`
  so the VM cannot grow into the working set.
- **Build on the host, ship only the binary.** No cargo toolchain in any image;
  a `scratch`/`distroless` base with one static arm64 binary.
- **arm64 only.** No QEMU amd64 emulation — it is slow and memory-hungry, and
  nothing here is architecture-sensitive.
- **Three nodes:** two `nas-peer` instances plus one `nas-peer --witness`, which
  is the minimum that makes §5.3's fork detection meaningful.

Record observed output here as it lands.
