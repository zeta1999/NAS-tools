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
- [x] `formal/lean/NasVerify/Padding.lean` — VERIFIED, 11 theorems. Models the
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
- [x] **Close the `ForkDetected` gap in `nas-slots` alone.** **Done.** A
      `Witness` is now format v2 and carries one edge of the chain — the
      observed record's `record_hash` plus that record's own `prev` — so
      `SlotClient::forked` no longer needs a served history to compare two
      branches at *different* sequence numbers, which is what a real fork looks
      like since each device witnesses its own head
      (`a_fork_at_disjoint_sequences_is_detected_once_the_links_are_known`).
      `SlotConsistency.tla` revision 3 matches: witnesses carry a predecessor,
      detection is `KnownIncompatible` over links the client actually holds,
      and `ForkDetected` carries that hypothesis in its antecedent instead of
      handing the client the global `Compatible`.
      **What is genuinely left, and it is the design's own limit, not a bug:**
      a walk still needs the linking observations. Two witnesses with a gap
      between them are left unproven and raise nothing
      (`a_gap_in_the_walk_raises_nothing`) — soundness over completeness, since
      a relay that withheld one witness could otherwise make an honest slot
      look forked. That is SPECS §5.4's "converges once witnesses propagate",
      and no data model closes it. The over-the-wire route is unchanged and
      still stronger where the peer retains history
      (`a_fork_below_the_served_head_is_detected_by_the_offer_alone`,
      `uc12_fork_drill.sh` conns 6 and 10).
- [x] **Vary `ForkAt` in the TLC configs.** Was fixed at 2 in both configs.
      Now gated over the whole admissible range `1..MaxSeq` — `MC_*_fork1.cfg`
      (fork at genesis, no shared prefix) and `MC_full_fork3.cfg`
      (`ForkAt=MaxSeq`) — with the sanity counterexamples at both ends. See
      `formal/README.md` "Varying `ForkAt`".
- [x] `LeaseGC.tla` — the write/sweep race against the young-blob grace period.
      `formal/tlaplus/LeaseGC.tla`, gated by `formal/check.sh`; 7 invariants
      hold, 5 must-FAIL checks fire. It found one: §6.2's grace is keyed to the
      blob file's mtime and `BlobStore::put` does not touch a file it already
      has, so a **deduplicated** upload gets no grace (`EveryUploadGetsGrace`,
      and `formal/README.md`). Left open below.
- [ ] **A deduplicated upload gets no young-blob grace (SPECS §6.2).** Found by
      `LeaseGC.tla`'s `EveryUploadGetsGrace` check. §6.2 promises immunity to
      "any blob uploaded within `grace_period`"; `Peer::inventory` takes
      `uploaded_at` from the blob file's mtime and `BlobStore::put` returns
      early without touching a file whose address it already holds. So a second
      client's convergent upload (§3.2), or one client retrying after a crash —
      the case §6.2 names — is swept while it is still inside the window it was
      promised, and the `take_lease` that follows fails with `NoSuchBlob`. Fix
      is either to touch the file on a deduplicated put or to record
      `uploaded_at` out of band; both change what `uploaded_at` means, so it is
      a decision, not a patch.
- [ ] **No authenticated `forget` for the retention floor (SPECS §6.3, §16.3).**
      §16.3's table routes a shrink through the offline delete authority;
      `Peer::publish_retention` implements no such path and refuses *every*
      shrink, so the only way an address leaves the floor is a peer running
      `--hostile ignore-retention`. Safe, but not what the spec describes.
      `LeaseGC.tla`'s `Forget` models the spec's act, not the code's absence.
- [ ] `DeleteQuorum.tla` — quorum, approval replay, cooling-off bypass
- [x] `cargo-fuzz` targets for every parser consuming peer bytes — **six**
      shipped (`fuzz/run.sh`), asserting properties rather than merely absence
      of panics. Found three canonicalisation defects in 45 seconds that the
      adversarial human review of the same function missed, one of them a
      capability-scoping break (MANUAL-TESTING.md §8a).
- [x] A fuzz target per peer-facing record format — the plaintext peer records
      are format-breaking to change once written (SPECS §20), so they are
      fuzzed while still cheap to fix. Fourteen targets; the three added with
      M1's new formats are `handoff_decode` (§5.1), `checkpoint_decode` (§5.5)
      and `delete_decode` (§16.2).
- [x] Raise coverage on the thin targets — `wrap_decode` went 61 → 933 with
      framed input, and immediately earned its keep: it found that
      `WrapPolicy` bounded Argon2 parameters only from **below**, so a peer
      (which holds the wrap record, §2.2.2) could demand `memory_kib =
      u32::MAX` and a recovering client would attempt four terabytes.
      `TooStrong` and a ceiling now close it.

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
- [x] **Store symlinks.** Entry kind `2`, target bytes; never followed on
      store, re-created as a link on restore, and a stale link at a restored
      name is replaced rather than written through. Mode bits, uid/gid, mtime,
      xattrs (SPECS §15.1) remain unstored.
- [x] **`nas-vault` replaces the M0 plaintext vault.** `vault.bin` is sealed and
      authenticated; the seed derives every role identity; `CS` generations are
      kept on rotation so revocation is not a data-loss event.
- [ ] **The vault key still sits beside the vault** in `vault.key` (0600), which
      relocates the secret rather than protecting it. Needs an OS keychain
      (Keychain / Secret Service) or a passphrase-derived vault key. Until then
      `e2ee` at rest is only as strong as the local disk.
- [x] Wire `--mode passphrase` through the CLI. **UC02 is green end to end**:
      all 9 assertions pass, including the Argon2id floor read from the *stored*
      record rather than from a constant in the binary, the wrong-passphrase
      refusal at exit 2, re-wrap without re-encryption, recovery carrying the
      freshness anchor, and superseded wraps removed.
- [x] **`transit-only` mode** (SPECS §2.2.3): plaintext at rest, per-tenant
      salted addressing, visible filenames, directory manifests stored
      unsealed. UC01 is green but for the two peer-enforced ACL assertions.
- [x] Interactive passphrase prompt (`nas-cli/src/prompt.rs`): `--passphrase`,
      then `$NAS_PASSPHRASE`, then a person at the controlling terminal. With
      no terminal the command is refused (`NO_TERMINAL`), never defaulted —
      a prompt that silently fell back to a default would be worse than none.
      Namespace creation asks twice and refuses a mismatch or an empty line.
- [x] **The root manifest key `rk_v` is built** (SPECS §3.1).
      `nas_crypto::root_key` derives `derive_key("nas-tools/root/v1",
      root_secret ‖ le64(seq))` into its own `RootKey` type, which only
      `seal_root` / `open_root` accept — the general `seal` cannot take it.
      `seal_root` draws the random nonce and *returns* it: the nonce lives in
      the signed slot record (`root_nonce`), not in the blob, and
      `ROOT_NONCE_LEN == NONCE_LEN` is asserted at compile time. `nas peer sync`
      seals `RootManifest { tree, generation }` under `rk_seq` with AAD
      `slot_id ‖ seq`, stores, pushes and leases it; on the read side it
      fetches, hash-checks and opens the root a verified head points at, and
      refuses a peer that serves the record but not the blob as withholding.
      `transit-only` stores it unsealed with a zero nonce, as it stores every
      manifest. Drilled: uc10's withholding step now refuses at the head, exit
      2, where it used to exit 0 (MANUAL-TESTING §10).

## M1 — the peer

- [x] `nas-slots`: signed records, both regimes, hash chain, roster, chain
      walking, anchors, pins, witnesses, publishable fork proofs. **ML-DSA
      record sizes measured while the structs were designed** (PLAN step 6):
      a SlotRecord is 3502 B of which 3309 B is signature — **103x the 32-byte
      root address it authenticates**, which is the number behind SPECS §3.8.
      A witness is 5365 B, so a fork proof costs 10730 B.
- [x] Skip-chain checkpoints (SPECS §5.5) — `Checkpoint` in `nas-slots`,
      hash-linked and signed at every rung, `verify_skip_chain` walking a
      ladder then the tail records in full. On the wire as
      `PublishCheckpoint` / `Checkpoints`; the peer stores rungs (bounded,
      keeping *both* of two conflicting rungs because the writer equivocating
      is evidence and the peer is not the party that judges it); `nas peer
      sync` publishes a rung every 256 records and pins the top one, so a peer
      serving a different ladder is refused the way a different record at a
      pinned sequence is. Drill: `uc13_skip_chain.sh`, MANUAL-TESTING §14.
- [x] Use the ladder to *shorten* a walk — `plan_walk` (pure, in `nas-slots`)
      chooses the full walk whenever it is within budget and climbs otherwise;
      `nas peer sync` pages the tail and reports how many records it took on
      the writer's word and how many memories it could not check. Two defects
      found by building it: `MAX_RECORDS = 256` was unreachable (a 256-record
      response is 3x `MAX_FRAME`, so the peer **dropped the connection**
      instead of answering), and without paging no rung could ever leave a
      walkable tail because the checkpoint interval (256) exceeds what one
      response carries (~74).
- [x] **`CHECKPOINT_INTERVAL` reconciled with what a response carries — keep
      256, page both fetches.** Climbing costs `S/I + I` items, minimised at
      `I = sqrt(S)`; for §5.5's own 100 000-behind example that is ~316, so 256
      costs 646 against an optimum of 632. Shrinking it to one response (74)
      would cost 1425 — more than double. The frame is a transport limit and
      does not get to set a protocol constant, so the ladder fetch is paged
      too. That was a live defect, not a hypothetical: asking once truncated
      the ladder at the *bottom*, losing exactly the high rungs a far-behind
      client climbs to. `the_interval_is_sized_against_the_span_not_against_a_frame`
      keeps the arithmetic from drifting.
- [x] Single-writer ownership handoff (SPECS §5.1) — `SlotHandoff` in
      `nas-slots`, signed by the **outgoing** writer, binding slot, sequence
      and both writers. `verify_chain_with_handoffs` accepts an authorised
      change and still refuses a takeover; plain `verify_chain` refuses every
      change, which is the safe reading for a caller that was handed no
      handoffs. The peer stores them (`publish_handoff`), survives a restart,
      and consults them in `publish_slot`.
- [x] Serve handoffs over the wire — `PublishHandoff` / `Handoffs` on the
      protocol, dispatched like the witness pair, so a device can learn of an
      ownership change it did not make. Publishing turned the handoff store
      into a network-reachable append-only map, so it is now bounded
      (`MAX_HANDOFFS_PER_SLOT`, a refusal not an eviction) and keyed by the
      authorisation — which also fixed a filename collision that lost one of
      two handoffs across a restart. A witness-only node still refuses both.
      `nas peer sync` fetches them, verifies them and walks with them, and
      reports any handoff claiming *this* namespace signed its slot away.
- [ ] Give the client roster a source other than its own key. `nas peer sync`
      deliberately does not add a handoff's `from_pk` to its roster — that
      would let the peer decide who may have written this namespace's history
      — so a chain crossing an authorised change still stops at
      `UnknownWriter`. Until a device can be told about another writer
      (a repo-side roster, `nas ns roster add`), the handoff path is correct
      and unreachable from the CLI: every device of a namespace derives the
      same `Role::Slot` key, so there is only ever one writer.
- [x] `nas-peer` core: blob store, slot ordering + history, CAS enforcement,
      roster checks, retention holds, PoP responder, the rights vocabulary and
      a peer-evaluated ACL, and **all six `--hostile` behaviours as branches in
      the real peer** rather than as a mock.
- [x] Serve it over the network — `nas-transfer` on `simple-network` `pqc`,
      synchronous handshake so no async runtime enters NAS-tools. Eight
      integration tests cross a real socket, including the tamper, dedup-lie
      and rollback defences and the peer-key pin.
- [x] Wire `nas-transfer` into the CLI: `nas peer serve` / `nas peer sync`,
      plus `nas peer init|allow|writer|grant|show` so an operator admits a
      client's transport key, its slot key and its rights by hand. Exercised
      end-to-end on localhost against the release binary: a namespace pushed
      over a real PQC socket, a second sync is a no-op, and a client with the
      wrong pinned peer key is refused at the handshake before any record
      moves. See MANUAL-TESTING.md §10.
- [x] The three-process localhost simulation: `tests/usecases/uc10_three_node_drill.sh`
      (honest peer restarted `--hostile rollback`, a `--witness` node, three
      devices). Found and fixed two defects the in-process tests could not:
      `Repo::open` dropping `$NAS_PASSPHRASE`, and the pin silently not
      written on a copy-joined device with no `state/`. MANUAL-TESTING.md §12.
- [x] Then containers: `tests/usecases/uc11_containers.sh` + `docker/`
      (Dockerfile, compose.yaml). Host-built binary, slim runtime images,
      three nodes on one compose network; same drill as UC10, passes under
      colima. Docker Desktop's daemon was unreachable on this machine; colima
      + `DOCKER_HOST=unix://$HOME/.colima/default/docker.sock` works.
      MANUAL-TESTING.md §13.
- [x] `nas-peer --witness`: no blobs, no caps, relay only — `nas peer serve
      --witness` (see the M1 entry above).
- [x] Lease deltas, checkpoints, sweep, young-blob grace, per-holder quotas.
      **Measured:** a LeaseDelta is 5337 B fixed + 32 B per address — 8537 B for
      100 addresses, where signing each address individually would cost
      334100 B, **39x more**. A LeaseCheckpoint is 5377 B whether it covers 100
      addresses or ten million. That is SPECS §3.8 and §6.1 in numbers.
- [x] **`nas peer sync` leases what it holds, and renews by syncing.** Until
      now no client took a lease over the wire: the peer owned leases and a
      quota (SPECS §6.4), the sweep warned (§6.3), and every real client's
      answer to both was empty because nothing had ever been leased. Sync now
      ends its blob step with `TakeLease` over every local address, in
      `MAX_RECORDS` (256) batches. A take is a union that stamps the holder's
      last-seen, so one take per sync is both the first lease and the renewal,
      and a device with nothing local sends an empty take, which renews
      without changing the set (pinned at the peer:
      `one_take_renews_the_holder_and_clears_the_warning` — lapsed, warned of
      3, one empty take, warned of nothing, the sweep that would have ended
      the window deletes nothing). Sync never releases: a second device of the
      same subject holds none of the first's blobs, and releasing what is not
      local would hand the sweep the namespace; release is §16.2's explicit
      act. uc10 shows the line (`leases: 2 …`, `leases: 0 …` for the blob-less
      second device) with unchanged exit codes. **Open:** renewal costs one
      round trip per 256 blobs per sync — the constant-size renewal is a
      signed §6.1 `LeaseCheckpoint` over the wire, not built; and a quota
      refusal mid-way leaves the earlier batches leased, which sync reports
      (`N of M blobs leased before the refusal`) rather than unwinds.
- [x] **The warn-before-sweep window is only `grace` wide.** SPECS §6.3 says the
      peer must not sweep until `expiry + grace`, and a returning client inside
      that window is warned. With the defaults that is a **24-hour** warning
      after a **90-day** absence, which is not much of a warning. Either the
      window wants its own (longer) setting, or the warning has to reach the
      client by some route other than it happening to reconnect. Decide before
      `nas-peer` starts actually deleting.
      **Decided (SPECS revision 6):** its own setting. `GcPolicy::notice`,
      default **30 days**, is §6.3's window; `grace` stays §6.2's 24-hour
      upload-race immunity and no longer has anything to do with absence. Two
      things were wrong, not one: the window was `grace` wide, *and* the
      warning fired only for blobs already in `delete` — i.e. only once the
      window had closed, after the deletion, which is an obituary. Now every
      holder of a `LeasedByExpiring` blob is warned, so inside the window the
      list is what a sweep *would* take and renewing still saves it; the
      `sweep.rs` tests pin that the inside-window list equals the after-window
      `delete`. The route is `nas peer sync`, which now asks `SweepWarnings`
      first thing and prints what is at risk. The peer test named
      `..._and_is_warned` had never asserted a warning; it does now, and both
      UC07 drills probe just past `expiry + grace`, where the conflation
      swept. **Since closed:** `sync` now leases everything it holds (the
      item above), so the answer is real for every client. **Still open:** a
      client that never reconnects is never told — the spec's
      "some route other than reconnecting" is not built.
- [x] Proof-of-possession responder (`Request::Prove` → `BlobStore::prove`,
      `nas-transfer/src/server.rs:36`; the client checks with `check_proof`
      before trusting a dedup claim, SPECS §4.5)
- [x] `--witness` mode: no blobs, no caps, relay only (`nas peer serve
      --witness`; refused at the dispatch in `nas_transfer::handle`, the one
      place every request passes)
- [x] Push/pull over `simple-network` `pqc` (honest-peer path)

## M2 — adversarial hardening

- [x] Freshness anchors, client pins, chain walking (`nas-slots` `client.rs`:
      `Anchor`, `Verdict`, pinned-seq refusal; exercised by the rollback and
      fork drills)
- [x] Fork detection over the wire against a live `--hostile fork` peer: pin
      carries seq + record hash, `sync` walks `SlotHistory` from the lowest
      witnessed/pinned seq (`tests/usecases/uc12_fork_drill.sh`,
      MANUAL-TESTING.md §13)
- [x] Skip-chain checkpoints (SPECS §5.5) — see the M1 entry
- [x] Witness publication and relay (`PublishWitness`/`Witnesses` in
      `nas_transfer::handle`, `nas-slots` `witness.rs`; relay is
      witness-only-capable via `peer serve --witness`)
- [x] One named test per attack: tamper, rollback, withhold, dedup-lie,
      CAS-non-enforcement, witness withholding (`nas test attack <kind>`,
      `crates/nas-cli/src/attack.rs`; UC09 scores 6 of 8 at M1)
- [x] Lease-based GC with a caller: `Peer::sweep` + `Peer::inventory` drive
      `nas_lease::plan_sweep` and delete through `delete_blob`, so retention is
      the floor *and* the last gate. Quota breaches are reported, never
      enforced by deleting (§6.4)
- [x] Retention enforced as §16.3 specifies: `publish_retention` takes the whole
      proposed set and refuses a drop (`nas test retention-extend-only`,
      `nas test retention-shrink --key everyday`, `nas test attack go-silent`)
- [x] Object Lock recorded at creation (`ns create --object-lock … --retention …`),
      with the enforced/not-enforced split printed rather than implied
- [x] Deletion approval loop (§16.2) in `crates/nas-delete`: signed request /
      approval / execution, quorum by scope, distinct-holder counting, the
      rolling window against decomposition, and approvals bound to a request
      hash. Drills: `nas test delete-quorum|cooling-off-bypass|
      quorum-decomposition-attack|approval-replay`, `nas delete-request execute`
- [x] **`decide` checks the deletion authority, not just distinctness**
      (SPECS §16.1). Found while starting the peer wiring: counting distinct
      approvers is a headcount, and whoever held the requesting laptop could
      mint three keypairs and satisfy the namespace quorum of 3. `Authority` is
      now a parameter — held by the verifier, never read out of the records it
      judges — an approval from outside it is refused rather than ignored, and
      an empty authority approves nothing. Drill:
      `nas test invented-approvers`.
- [x] **The peer retains the §16.2 audit trail.** `publish_delete_request` /
      `publish_delete_approval` / `execute_delete`, append-only and persisted,
      with the executed history behind it — so the rolling window survives a
      restart instead of being a `Vec` a compromised client passes as empty.
      Building it found that `DeleteExecution` had no `encode`/`decode` at all:
      the third record of a loop whose first line is "all of it append-only"
      could not be written down. It has one now, with its approvals nested and
      bounded.
- [x] Serve the delete trail over the wire — `PublishDeleteRequest` /
      `PublishDeleteApproval` / `ExecuteDelete`, plus `DeleteRequestRecord` and
      `DeleteApprovals` so a second device can collect a quorum it did not
      gather itself. Only opening a request is ACL-gated
      (`Right::DeleteRequest`): approvals are signed on the offline device
      §16.1 describes and relayed by whatever machine has a connection, so
      gating the relay would make the air gap unusable — what bounds them is
      authority membership, which is cryptographic.
- [ ] **Execution does not delete data, and cannot yet.** In an encrypted
      namespace the peer cannot resolve `Scope::Object("2024/scan.pdf")` to an
      address (SPECS §2.2): it holds ciphertext under content addresses and no
      mapping. So the peer records the authorisation and the client — which
      holds the mapping — must release the leases and let the sweep run. That
      client half is unbuilt, and needs the key→object mapping the S3 face
      brings (§7.1), same as `put`/`rm`.
- [x] **Object Lock establishes the append-only posture** (SPECS §16), decided
      with the user: `ns create --object-lock … --device <subject>` seeds that
      subject **append and nothing else**. §16's whole ransomware defence is
      "add, never overwrite or delete", and a posture nobody remembers to
      configure is not a defence. The device is *named* rather than assumed —
      an ACL entry is only meaningful against a subject an operator binds a key
      to. Without `--object-lock` the ACL stays empty, so default-deny is
      untouched.
- [x] UC07's roaming drills (SPECS §5.6, §6.3) — `nas test
      witness-opportunistic`, `offline-30d`, `sweep-warning`, in
      `crates/nas-cli/src/roaming.rs`. `Peer::sweep_warnings` gives a
      returning client §6.3's warn-before-sweep list, served as
      `SweepWarnings` on the wire. All three are **mutation-tested**: shrink
      the expiry, silence the warnings, or add a staleness rule to the relay,
      and each drill goes to exit 2 rather than passing.
- [x] Lease griefing bounded by per-holder quota (SPECS §6.4) — the peer now
      **owns** the leases (`take_lease` / `release_lease` / `holders`,
      persisted), because a quota is an admission control and admission needs
      state: `plan_sweep` can report a breach after the fact, only the party
      taking the lease can refuse it. All-or-nothing, so a griefer cannot
      bisect its way to the ceiling; counted against what the holder *would*
      hold, so it cannot creep up one small request at a time; and a lease on
      a blob the peer does not hold is refused outright. `TakeLease` /
      `ReleaseLease` / `Leases` on the wire, holder id derived from the
      authenticated subject rather than taken as an argument. Drills:
      `nas test attack lease-griefing` and `lease-on-nothing`.
- [x] Cold-start test: `nas test attack all --cold-start` — six drills detected
      against a cap-only client; exits 3 only because lease griefing is pending

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

- [x] `ci.sh`: fmt (not `--all` — see the comment there), clippy `-D warnings`,
      workspace tests, `formal/check.sh`, release `nas`, and the acceptance
      suite at `CI_MILESTONE` (default M1).
- [ ] **CI on linux.** `docker/build.sh` builds a static arm64 musl `nas` in a
      `rust:alpine` container and bakes the `nas-node` image, but nothing runs
      the tests or the acceptance suite under linux, and amd64 is not built at
      all. Needs a matrix (macOS host + linux arm64 + linux amd64) that runs
      `ci.sh` itself, not just the build.
- [x] Automated "no plaintext on the peer" scan: `nas test peer-no-plaintext
      <ns>` (`nas-cli/src/peerscan.rs`) walks the whole peer root — blobs,
      slots, leases, witnesses, everything under it — for the fixture's
      content markers, the fixture file names, and a planted canary.
      `check_corpus` first confirms the fixture tree really carries the
      marker, so a stale fixture is an error rather than a green. UC02 and
      UC03 assert it; UC01 asserts the inverse (`peer-holds-plaintext`).
- [x] User manual must state plainly: fork detection is not prevention; a blocked
      peer keeps what it already had; a revoked device reads old data until rewritten
      — `MANUAL.md` (§1 "what you're buying", §5 forks, §6 revocation, §8 limits)
- [ ] `MANUAL.md` §6: "a rotated peer can't be un-rotated" is a design statement —
      re-check once `nas peer` grows a rotation subcommand; and §6 deletion prose
      needs the M6 quorum flow filled in when it exists
- [ ] `MANUAL.md` §4: no `nas vault export` / secret-mode command yet; the manual
      names the path (`vault.key`) rather than a command — update when one exists
- [ ] Propose CDC + at-rest encryption upstream to `simple-backups` rather than
      maintaining two stores
