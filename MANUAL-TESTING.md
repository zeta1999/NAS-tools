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

81 assertions across 9 use cases, each tagged with the milestone that unblocks
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

## 6. Multi-node simulation (planned, M1)

Not yet built. The shape, given 16 GB of RAM:

- **colima with an explicit budget** — `colima start --cpu 4 --memory 6 --disk 40`
  so the VM cannot grow into the working set.
- **Build on the host, ship only the binary.** No cargo toolchain in any image;
  a `scratch`/`distroless` base with one static arm64 binary.
- **arm64 only.** No QEMU amd64 emulation — it is slow and memory-hungry, and
  nothing here is architecture-sensitive.
- **Three nodes:** two `nas-peer` instances plus one `nas-peer --witness`, which
  is the minimum that makes §5.3's fork detection meaningful.

Record observed output here as it lands.
