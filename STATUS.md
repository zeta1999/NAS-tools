# NAS-tools Status

**Current state:** Design + one upstream fix landed. No NAS-tools code yet.

`SPECS.md` is at **revision 4** (~1476 lines, 21 sections). It has survived one
adversarial review (rev 1→2, 15 findings, all accepted), a round closing its own
open questions (rev 2→3), and rev 4 adds confidentiality modes, the git face,
permissions/ACLs, Object Lock, DVC, formal methods and a use-case cookbook.
**Revision 4 has not yet been reviewed.**

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
- **`formal/lean/NasVerify/Transcript.lean`** — VERIFIED under Lean 4.28. Three
  theorems, zero `sorry`: decoder round-trip, encoding injectivity, padding
  reversibility.

## Written but NOT verified

- **`formal/tlaplus/SlotConsistency.tla`** — `tla2tools.jar` is not installed, so
  this has never been model-checked. Labelled as such in `formal/README.md`. It is
  a design document with angle brackets until TLC runs it.

## Not built

Everything else. `crates/` does not exist. Next action is M0.

## Environment constraints

16 GB RAM on the dev machine. Docker 29.3 (desktop-linux), colima 0.10.1, lima
2.1.0 available. The multi-node simulation must build on the host and run slim
runtime containers — a `cargo` toolchain inside each node would not fit.

See `TODO.md`.
