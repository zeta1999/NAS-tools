# NAS-tools Status

**Current state:** **M0 is done and has survived its brutal review.** All four
steps built, the 5 M0-tagged acceptance assertions pass against the real binary,
and the padding measurement that M0 gated on is complete — it **contradicted the
spec by 2-3×**. The review found **four reproduced defects**, all fixed; see
MANUAL-TESTING.md §7. Next: M1.

`SPECS.md` is at **revision 5** (~1476 lines, 21 sections). It has survived one
adversarial review (rev 1→2, 15 findings, all accepted), a round closing its own
open questions (rev 2→3), and rev 4 adds confidentiality modes, the git face,
permissions/ACLs, Object Lock, DVC, formal methods and a use-case cookbook.
Revision 4 was reviewed and revision 5 closed all six blockers it found.

## Decided

Untrusted peers; Rust; PQC throughout (ML-DSA-65 / hybrid ML-KEM-768 /
XChaCha20-Poly1305 / BLAKE3); localhost daemon as the trust boundary; convergent
encryption with a per-tenant secret; deterministic size-class padding; local
listing; lease-based GC with deltas; **three confidentiality modes** (`e2ee`,
`passphrase`, `transit-only`); `cas-merge` slots for S3, docs and git refs
(fast-forward merge for refs); read-only mount via WebDAV first.

## Shipped

- **`../simple-network` protocol v1** — handshake transcript binding + constant-time
  pin comparison. 15 tests green, clippy clean, fmt clean. Wire-breaking by design;
  v0 peers are refused with an explicit version error rather than downgraded.
- **`formal/lean/NasVerify/`** — VERIFIED under Lean 4.28. **Eleven theorems**,
  zero admitted, and an axiom gate that fails on anything outside `propext` /
  `Classical.choice` / `Quot.sound`. `Transcript.lean`: decoder round-trip,
  encoding injectivity, padding reversibility. `Padding.lean` models the size-
  class **ladder**, closing the gap where the single-class model's `Nat`
  truncation hid a `usize` underflow — including `padTo_underpads`, the negative
  result proving the old theorem could not have caught it. Both gates are
  verified to actually fail on a planted cheat (MANUAL-TESTING.md §1d).
  `unpadStrict_*` was added after the M0 review: the earlier theorems quantified
  only over *outputs of the padder*, so the model could not see a malicious
  writer choosing a non-minimal size class.

- **`formal/tlaplus/SlotConsistency.tla`** — MODEL-CHECKED. 38,709 distinct states
  at MaxSeq=2 (CI gate), 4,699,837 at MaxSeq=3 (deep gate). Its first revision
  failed TLC in 7 states, catching three defects; see `formal/README.md`.
- **`crates/nas-core`** — canonical encoder with proptests mirroring the Lean
  theorems, plus `Addr`, the `Clock` trait and the format discriminants.
  15 tests green.
- **`crates/nas-crypto`** — the §3.1 key schedule. `NoncePolicy` is private and
  `Key` has no constructor that accepts one, so a deterministic nonce on a
  non-content-derived key is unrepresentable. `ChunkReadKey` lets a stored `ck`
  decrypt without being able to seal — the manifest needs the round trip, and
  making the reconstructed key *open-only* is what keeps it from becoming a
  nonce-reuse hole. All twelve signature contexts. 16 tests green.
- **`crates/nas-store`** — FastCDC (gear table in-repo and golden-pinned, because
  it is a format constant), checked size-class padding, the blob store with
  proof-of-possession, manifests, and the object write/read pipeline.
  **76 tests green**, including whole-tree round-trips under the per-directory
  key chain and incremental writes. Entry names are **raw bytes**, not `String`:
  a POSIX filename need not be UTF-8, and `to_string_lossy` collided distinct
  names into one. That is a format decision, made before M1 freezes the layout.
- **`crates/nas-slots`** — SPECS §5. Signed, hash-chained slot records in both
  regimes; roster; chain walking; witnesses and publishable fork proofs; and the
  client accept logic that is the Rust counterpart of `SlotConsistency.tla` —
  `AnchorFloor`, `MonotonicPins` and `ForkDetected` each map to a specific
  rejection or alarm. **57 tests green.**
- **`crates/nas-lease`** — SPECS §6. Deltas and checkpoints, a count-committed
  Merkle root, chain replay, and the sweep decision — the only code in the
  system that deletes user data, so every guard §6.2–§6.4 names is a separate
  named reason rather than one folded boolean. **45 tests green.**
- **`crates/nas-vault`** — SPECS §2.2.2 and §3.9. Argon2id parameters with the
  floor as an explicit *policy* rather than a constructor constant (so tests
  cannot quietly weaken production); `NamespaceSecrets` derived from a DEK; the
  `WrapRecord` that **is** the capability for passphrase mode, carrying the
  freshness anchor; and the sealed local vault with `CS` generations and pinned
  peers. **42 tests green.**
- **`crates/nas-peer`** — SPECS §10, §15. The rights vocabulary and a
  peer-evaluated ACL whose answer has **four** outcomes, not two: `NotEnforceable`
  exists because in an encrypted mode the peer has no read control to offer, and
  reporting allow-or-deny there would describe a control that does not exist.
  Slot ordering with compare-and-swap, roster checks, retention holds, the
  proof-of-possession responder — and `Hostility`, which is a flag on the real
  peer rather than a mock, so the attack path and the honest path share their
  parsing and bookkeeping. **35 tests green.**
- **`crates/nas-transfer`** — SPECS §14. A bounded request/response protocol
  over `simple-network`'s **synchronous** PQC handshake, so NAS-tools needs no
  async runtime of its own. Every frame is size-checked *before* allocation —
  otherwise a peer answers with `0xFFFFFFFF` and the client reserves four
  gigabytes for four bytes of effort. **Eight integration tests cross a real
  socket**, and they exist to prove the client-side defences still fire against
  a networked peer rather than only an in-process one. **23 tests green.**
- **`crates/nas-cli`** — the `nas` binary. Exit codes are a *contract*: 0 ok,
  1 error, 2 refused by policy, **3 unimplemented**. A specified-but-unbuilt
  subcommand must never exit 2, or the harness would score unwritten code as a
  passing security control.
- **`tests/usecases/`** — 83 acceptance assertions, milestone-gated; 53 are
  M0–M2. **5 passing, 0 failing, 78 pending** at `NAS_MILESTONE=M0` (what CI
  gates on), and **16 passing, 9 failing, 58 pending** at `NAS_MILESTONE=M1` —
  and **25 passing, 0 failing, 58 pending** at `NAS_MILESTONE=M1` — UC01
  (transit-only), UC02 (passphrase) and UC03 (e2ee) are all green end to end. Verified to
  bite: a stub that always exits 0 fails the refusal assertion, and one that
  always exits 1 is reported BROKEN rather than refused (MANUAL-TESTING.md §6a).

## Fuzzing

Twelve targets under `fuzz/`, one per parser that consumes bytes it did not
write: `decode_fields`, `addr_from_hex`, `unpad`, `manifest_decode`,
`dir_manifest_decode`, `aead_open`, `slot_record_decode`, `witness_decode`,
`lease_decode`, `wrap_decode`, `wire_decode`.
The last two were added **with** the formats they parse, not after — SPECS §20
lists the peer's plaintext records as format-breaking to change once written. They assert *properties* — injectivity,
canonical re-encoding, and that attacker bytes never open — not merely absence
of panics. ~102 M executions clean at 60 s per target.

The first run found **three canonicalisation defects in 45 seconds**, in a
function a full adversarial review had just read: a `kind` field read via
`.first()` so any length was accepted and the surplus discarded; entries not
required to be in sorted order; and two sibling directories permitted to share a
`dir_id`, which gives them the same `DirSecret` and so **breaks subtree
capability scoping** (SPECS §15.3). Not in `ci.sh` — a time-boxed fuzz run is
not a pass/fail gate. Run `./fuzz/run.sh` before closing a milestone.

## Measured, not assumed

- **Padding overhead (M0 exit criterion).** SPECS §4.2.1 estimated 20–35%.
  Measured on two real corpora: **+56%** on large files, **+97%** on a source
  tree. The estimate was off by 2–3× and SPECS has been corrected (rev 6). A ×2
  ladder costs ~1.5× on any distribution, and small files pay the 32 KiB floor
  regardless of tuning — overhead scales with *file count*.
- **Streaming is real.** 5.5 MiB peak RSS while writing 631 MB; 8.6 MiB across
  12904 files. Memory tracks the chunker window, not file size.
- **Dedup works.** 54.1% recovered on a corpus of split binaries without being
  told the files were related; `fixed` managed only 16.2% on the same data.

See `MANUAL-TESTING.md` §5 for the commands and raw output.

## Known weaknesses, stated rather than discovered later

- **The vault key sits beside the vault.** `vault.bin` is now sealed and
  authenticated (that was the M0 weakness, and it is closed), but `vault.key` is
  written next to it at 0600. That *relocates* the secret rather than protecting
  it. An OS keychain or a passphrase-derived key is what makes it real; both are
  in TODO. `--mode passphrase` still exits 3 rather than creating a namespace
  whose config claims a protection it does not have — **passphrase mode is now
  wired through the CLI** and stores *nothing* locally that opens a namespace.
- **Names are not separately encrypted.** SPECS §4.4 specifies Cryptomator-style
  per-segment encryption; that design exists because Cryptomator maps segments
  onto *server filenames*. Here the peer sees `blobs/<ab>/<hex>` and names live
  inside the sealed directory manifest, so a second layer buys nothing.
  `transit-only` — where the peer legitimately reads plaintext and names must be
  *visible* — will need this reconsidered at M1.
- **Symlinks are skipped**, not stored: following them lets a tree escape its
  own root, and storing them needs a format field that does not exist.

## Where the numbers stand

`ci.sh` is green end to end today, at `CI_MILESTONE=M1`:

| | count |
|---|---|
| Rust unit tests | 363 |
| Lean theorems (clean axiom gate) | 14 |
| `cargo-fuzz` targets | 11 |
| Acceptance assertions passing (≤M1) | 30 of 88 |
| Acceptance assertions pending (M2+) | 58 |

**30 of 88 is a progress marker, not a verification result.** The 58 pending
assertions are not failures and not successes — they are unwritten code that
`ci.sh` refuses to score. Every one of them is a claim SPECS makes that nothing
yet demonstrates, and the three use cases with a passing score (UC01–UC03) are
the three whose milestones have arrived. UC04, UC07 and UC09 — deletion
resistance, roaming, and the hostile peer — are at zero.

TLC is green with its three sanity checks still failing as required.

> The TLA+ model constrains SPECS §5, which is **M2** code. It is assurance
> about the design, not about anything shipped. Its correspondence to
> `nas-slots` is **partial**: same-sequence equivocation only, asserted as such
> by `a_fork_at_disjoint_sequences_is_not_detected`.

## Not built

M2: fork detection end to end against a live hostile peer, lease-based GC with
a caller, retention/Object Lock enforcement, quota admission (§6.4), the
single-writer handoff (§5.1), and the multi-process localhost simulation.

## Environment constraints

16 GB RAM on the dev machine. Docker 29.3 (desktop-linux), colima 0.10.1, lima
2.1.0 available. The multi-node simulation must build on the host and run slim
runtime containers — a `cargo` toolchain inside each node would not fit.

See `TODO.md`.
