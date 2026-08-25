# Implementation plan — M0 → M2

Scope chosen: **M0 through M2**, i.e. up to the point where *"resists a hostile
peer"* is a demonstrated claim rather than a design intention. Padding defaults
to `none`. Multi-node simulation on colima with a bounded VM.

Target of done: the 81 acceptance assertions in `tests/usecases/` stop being
PENDING. They were written from the use-case cookbook before any code existed,
precisely so the implementation cannot quietly redefine success.

---

## Step 0 — a decision that must precede M0

**SPECS §20.3: convergent encryption is an unforced choice.** A client-side
encrypted index `BLAKE3(plaintext) → addr` gives within-tenant dedup under
ordinary random keys, with no confirmation oracle, no convergence secret, no
per-tenant salt, and no rotation story for a lost device.

| | Convergent (current spec) | Indexed alternative |
|---|---|---|
| Works from cold with only a key | **yes** | no — needs the index |
| Confirmation oracle | **yes**, mitigated by a shared secret | none |
| Machinery | `CS`, generations, rotation, per-tenant salt (§3.9c, §2.2.3) | an index to sync, merge and recover |
| Blast radius of a leaked secret | every blob, permanently | none — keys are per-object random |

This **locks the on-disk format**, so it cannot be deferred past M0. Everything
below assumes convergent unless overridden; switching later is a rewrite of
`nas-crypto` and `nas-store`, not a flag.

> **Blocking question for the user.** Convergent as specified, or indexed?

---

## M0 — substrate, local only

No network, no containers. Four crates.

### 1. `nas-core`
Types, error taxonomy, addresses, capability types, manifest format, and the
**canonical length-prefixed encoder**.

- The encoder must be the one `formal/lean/NasVerify/Transcript.lean` models. A
  `proptest` mirrors `encFields_inj` directly: distinct field vectors never
  encode alike. The proof constrains the design; the test constrains the code.

### 2. `nas-crypto`
The §3.1 key schedule, as the **only** place in the workspace that chooses a
nonce.

- API shape is the safety property: callers pass a `KeyClass`, and the nonce
  policy follows from it. A deterministic nonce must be *unreachable* for a
  non-content-derived key rather than merely discouraged. Revision 1 of the spec
  was one implementer-inference away from keystream reuse here; the type system
  should close what prose could not.
- Convergent chunk keys, `dir_secret` chain, `dk`, all eleven signing contexts.
- Wraps `rust-secure-memory` for locked buffers and zeroization.

### 3. `nas-store`
FastCDC, padding, blob store, manifests, per-directory keys, bounded LRU cache
encrypted under a per-boot key.

- **Padding arithmetic uses checked subtraction.** `class - 4 - len` underflows
  on `usize`; the Lean proof does not catch it because `Nat` truncates (SPECS
  §4.2.1). Boundary test at `len == class - 4` and `len == class - 3`.
- Measure padding overhead against a real corpus and record it in
  `MANUAL-TESTING.md`. The 20–35% figure is an estimate nobody has checked.

### 4. `nas-cli` (minimal)
`ns create`, `put`, `get`, `ls`, and the `nas test …` subcommand tree the
acceptance harness already calls. The harness is the interface contract.

**M0 exits when** `uc03_work_e2ee.sh` is green apart from peer-dependent
assertions, and round-trip, dedup-ratio and the confirmation-attack pair pass.

---

## M1 — the peer

### 5. `nas-slots`
Slot records, both regimes, history with `prev` chaining, freshness anchors,
client pins, skip-chain checkpoints.

### 6. `nas-lease`
Delta and checkpoint records, young-blob grace, per-holder quotas.

### 7. `nas-transfer`
Client protocol over `simple-network` `pqc`. **Verify v1 interoperability
first** — protocol v1 is wire-breaking and `simple-backups` shares the channel.

### 8. `nas-peer` — the untrusted server
The component our own threat model assumes is malicious, so it holds no secrets
and requires none.

- Blob store; slot ordering and CAS; **plaintext roster verification** (§3.5);
  retention sets with peer-verified superset semantics (§16.3); lease
  enforcement and sweep; PoP responder; `--witness` mode holding no blobs.

### 9. Multi-node simulation
- `colima start --cpu 4 --memory 6 --disk 40` — a bounded VM that cannot grow
  into the working set on a 16 GB machine.
- **Build on the host, ship only the binary.** No cargo toolchain in any image;
  distroless base, one static arm64 binary. arm64 only — no QEMU.
- Three nodes: two peers plus one witness, the minimum that makes §5.3
  meaningful.

**M1 exits when** push/pull round-trips against a real peer over the PQC channel
and the lease cycle runs end to end, honest-peer only.

---

## M2 — adversarial hardening

### 10. The hostile peer
`nas-peer --hostile <behaviour>`: tamper, rollback, withhold, dedup-lie,
fork (refuse CAS), withhold-witness, ignore-retention.

> Without this, every attack test is a mock asserting what we already believe.
> The hostile peer is the load-bearing piece of M2, and it should be built
> **first**, not last.

### 11. Detection
Witness publication and relay, chain walking, cold-start from a capability alone.

- The client must re-evaluate accumulated evidence on **every** pin change, not
  on witness arrival. This is not a preference: TLC found the arrival-only
  version admits an undetected fork in 7 states (`formal/README.md`), and
  "handle the event then forget it" is the default way anyone writes it.

### 12. Model checks
`LeaseGC.tla` (write/sweep race against the grace period) and `DeleteQuorum.tla`
(quorum, approval replay, cooling-off bypass), both wired into `formal/check.sh`
with their own must-fail sanity checks.

**M2 exits when** `uc09_hostile_peer.sh` is fully green, including the cold-start
case.

---

## Engineering discipline

### RAM — 16 GB is the binding constraint
```toml
[profile.dev]
debug = 1            # line tables only; full debug info is what actually hurts
codegen-units = 16
[profile.dev.package."*"]
opt-level = 2        # fast deps, cheap rebuilds of our own crates
```
- Never run `DEEP=1 ./formal/check.sh` (3 GB, 46 s) concurrently with a build.
- Cap `cargo -j` while the colima VM is up.

### CI — `ci.sh`, matching the sibling repos
`cargo fmt --check` → `cargo clippy --all-targets -- -D warnings` → `cargo test`
→ `formal/check.sh` → `tests/usecases/run.sh`.

Gates that are easy to forget and therefore explicit:
- **fails on `sorry`** in any Lean file;
- **fails if a TLA+ sanity check stops failing** — a vacuous model is worse than
  no model;
- **PENDING acceptance assertions are reported, never counted as passing.**

### Commits
One per crate-level milestone, message carrying the acceptance matrix delta.
Work on `impl/m0` and merge at each milestone boundary rather than committing
directly to `main`.

### Review points
Brutal review after **each** of M0, M1 and M2 — not only at the end. Revisions
1→2 and 4→5 both found blockers that would have been far more expensive after
the format was written to disk.

---

## Risks, ranked

1. **The §20.3 decision** — locks the format; everything else is downstream.
2. **ML-DSA signature size in the lease and retention paths.** 3.3 KB per
   signature is the constraint that shaped §3.8. Measure real record sizes at M1
   against a realistic blob count before the format sets.
3. **`simple-network` v1 wire break** versus `simple-backups`. Verify at M1.
4. **FastCDC × padding interaction** on real data, unmeasured today.
5. **The peer's storage layout is format-breaking to change.** Roster, retention
   and lease records are all plaintext on-peer structures introduced in revision
   5 and have never been exercised by code.
