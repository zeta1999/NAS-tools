# NAS-tools TODO

Honest status. **M0 is complete**; this tracks the design decisions that are
settled and the work that follows from them.

## Done (design)

- [x] Trust model fixed: peers untrusted, ciphertext only, PQC throughout
- [x] Localhost daemon as the trust boundary; all three faces are local adapters
- [x] `SPECS.md` rev 1 → rev 2 after adversarial review (15 findings, all accepted)
- [x] Normative key/nonce schedule — deterministic nonces only for content-derived keys
- [x] Signature domain separation + role-separated ML-DSA keypairs
- [x] `pt_hash` in manifests to restore key commitment
- [x] Proof-of-possession challenge before honouring a dedup skip
- [x] Slot regimes: `cas-merge` (S3, docs) vs `single-writer` (git refs)
- [x] Freshness anchors in caps; peer-retained slot history; hash chain
- [x] Lease deltas + signed checkpoints, young-blob grace, 90-day expiry, quotas
- [x] Gateway auth: unix socket `0600` by default, loopback + credential for TCP
- [x] `nas-peer` added to the workspace (was missing entirely from rev 1)
- [x] Deterministic size-class padding, three profiles, `padding_profile` in manifests
- [x] Three revocation paths separated: peer block / roster removal / `CS` rotation
- [x] Witness records + witness-only nodes for roaming and rarely-online devices
- [x] Slot-history compaction: retain-N + skip-chain checkpoints, explicit degradation
- [x] Doc liveness: adaptive polling is the correctness path; pubsub is optional
- [x] Three confidentiality modes: `e2ee`, `passphrase`, `transit-only` (rev 4)
- [x] Git face: remote helper, inflated loose objects, encrypted OID map
- [x] Refs revised from `single-writer` to `cas-merge` with fast-forward merge
- [x] Worktrees, patch objects and patch queues
- [x] Rule-filtered mirroring modelled as a *derived repo*, not a copy
- [x] Four permission layers + rights vocabulary + per-directory keys from M0
- [x] Object Lock (governance/compliance/legal hold) + deletion approval loop
- [x] DVC integration at three levels; `simple-backups` convergence path
- [x] Use-case cookbook (§19) and requirement traceability (§20)

## Upstream — `../simple-network`

- [x] **Bind the handshake transcript into the KDF** — protocol v1. Both signatures
      and both directional record keys now commit to a canonical length-prefixed
      transcript (version, both verifying keys, `kem_pub`, KEM ciphertext).
- [x] **Signature context tags** — `.../sig/client-hello/v1`, `.../sig/server-response/v1`.
      Closes unknown-key-share and cross-protocol signature reuse.
- [x] **Constant-time `check_pin`** (`ct_eq`, no early exit)
- [x] 15 tests green (4 new), clippy clean, fmt clean
- [ ] **Wire-breaking — coordinate the rollout.** v0 peers are refused with an
      explicit version error. `../simple-backups` push/pull rides this channel, so
      both ends of any paired deployment must upgrade together.
- [ ] *(only if the doc face later wants pubsub)* topic filtering; route pubsub over
      `SecureConnection` rather than raw TCP; durable subscriptions with reconnect

## Formal

- [x] `formal/lean/NasVerify/Transcript.lean` — VERIFIED, 3 theorems
- [x] `formal/lean/NasVerify/Padding.lean` — VERIFIED, 10 theorems. Models the
      *ladder*, closing the gap where `Nat` truncation hid a `usize` underflow,
      and (after the M0 review) the reader's strict check: `unpadStrict_padLadder`
      proves no honest output is rejected, `unpadStrict_rejects_other_classes`
      proves the class-selection covert channel is closed
- [x] `formal/README.md` — what each tool is for, and what we deliberately skip
- [x] Fetch `tla2tools.jar` and actually model-check `SlotConsistency.tla` —
      **done**: 38,709 distinct states at MaxSeq=2 (CI gate), 4,699,837 at
      MaxSeq=3 (deep gate), with three must-FAIL sanity checks proving the model
      is not vacuous. Note it constrains **§5, which is M2 code** — it is
      assurance about the design, not about anything shipped in M0.
- [x] CI gate that fails on `sorry` in any Lean file — and a stronger one: every
      theorem carries `#print axioms`, and the gate fails on anything outside
      `propext` / `Classical.choice` / `Quot.sound`. Both verified to bite.
- [ ] `LeaseGC.tla` — the write/sweep race against the young-blob grace period
- [ ] `DeleteQuorum.tla` — quorum, approval replay, cooling-off bypass
- [ ] `cargo-fuzz` targets for every parser consuming peer bytes. **Raised in
      priority by the M0 review**: both reachable panics it found were in
      parsers, and the "never panics" proptests missed them by generating
      inputs that were rejected before reaching the defective code.

## M0 — substrate, local only

- [x] `nas-core`: types, addresses, `Clock`, manifest format discriminants,
      canonical encoding
- [x] `nas-crypto`: key schedule (§3.1) as the single source of truth for nonces
- [x] FastCDC + deterministic size-class padding + convergent encryption
- [x] Blob store, manifests, proof-of-possession, object write/read pipeline
- [x] **Measure padding overhead** against the real CDC distribution — done, and
      the spec's estimate was wrong by 2–3× (MANUAL-TESTING.md §5, SPECS rev 6)
- [ ] **Retune the ladder** in light of the measurement, or record the decision
      not to. Deferred to M2 as an open question, *not* silently dropped: the
      premium is 56–97%, the default is `none`, so nothing is stored under a bad
      ladder in the meantime.
- [x] Per-directory key derivation (impossible to retrofit — see SPECS §15.3)
- [x] Round-trip test: bytes in, byte-identical bytes out, every profile
- [x] Dedup test: 54.1% recovered on a corpus of split binaries
- [x] `nas-cli` + the `nas test` substrate, honouring the exit-2 refusal contract
- [x] The 5 M0-tagged acceptance assertions pass against the real binary
- [ ] **Per-segment name encryption — reconsider, do not just implement.**
      Names already live inside the sealed directory manifest and the peer never
      sees a filename, so §4.4's Cryptomator-style second layer buys nothing in
      `e2ee`. The case that actually needs a decision is `transit-only`, where
      the peer legitimately reads plaintext and names must be *visible*. M1.
- [ ] **Store symlinks.** Currently skipped: following them lets a tree escape
      its own root, and storing them needs a manifest field that does not exist.
- [ ] **`nas-vault` (M1 step 7) replaces the M0 plaintext vault.** `ns create`
      writes `CS` and the namespace root secret unencrypted at 0600 today.

## M1 — the peer

- [ ] `nas-peer`: blob store, slot ordering + history, CAS enforcement
- [ ] Lease deltas, checkpoints, sweep, young-blob grace, per-holder quotas
- [ ] Proof-of-possession responder
- [ ] `--witness` mode: no blobs, no caps, relay only
- [ ] Push/pull over `simple-network` `pqc` (honest-peer path)

## M2 — adversarial hardening

- [ ] Freshness anchors, client pins, chain walking, skip-chain checkpoints
- [ ] Witness publication and relay
- [ ] One named test per attack: tamper, rollback, withhold, dedup-lie,
      CAS-non-enforcement, lease griefing, witness withholding
- [ ] Cold-start test: a fresh client holding only a cap resists all of the above

## M3 — S3 face

- [ ] `nas-gateway`: unix socket + loopback TCP with SigV4
- [ ] `cas-merge` with per-key LWW, Lamport clocks, roster tiebreak, tombstones
- [ ] Local listing from decrypted manifests
- [ ] `state/outbox/` staging for offline writes + replay-with-remerge
- [ ] `aws s3` and `rclone` work; unauthenticated local process is refused

## M4 — read-only mount

- [ ] WebDAV on the same gateway (`OPTIONS` / `PROPFIND` / `HEAD` / `GET`)
- [ ] Encrypted chunk cache under a per-boot key, bounded LRU
- [ ] Ranged read of a 1 GB file fetches O(range), not O(file)
- [ ] Decide whether macOS WebDAV performance forces the NFSv3 path

## M5 — git face

- [ ] Remote helper; refs as `single-writer` slots; signed ownership handoff

## M6 — doc face

- [ ] CRDT engine, op-log blobs, compaction
- [ ] Adaptive polling; pubsub only if latency demands it

## Cross-cutting

- [ ] `ci.sh`: fmt, clippy `-D warnings`, tests; macOS + linux arm64/amd64
- [ ] Automated "no plaintext on the peer" grep over blobs, slots and leases
- [ ] User manual must state plainly: fork detection is not prevention; a blocked
      peer keeps what it already had; a revoked device reads old data until rewritten
- [ ] Propose CDC + at-rest encryption upstream to `simple-backups` rather than
      maintaining two stores
