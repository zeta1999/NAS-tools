# NAS-tools Status

**Current state:** **M0 is done and has survived its brutal review.** All four
steps built, the 5 M0-tagged acceptance assertions pass against the real binary,
and the padding measurement that M0 gated on is complete — it **contradicted the
spec by 2-3×**. The review found **four reproduced defects**, all fixed; see
MANUAL-TESTING.md §7. **M1 is in progress:** the peer, the slot system and the
transfer protocol are built and networked, and the CLI now drives them
(`nas peer serve` / `nas peer sync`) — a namespace has been pushed over a real
PQC socket between two `nas` processes on localhost, and again between three
containers. The ownership handoff (§5.1) and the skip-chain ladder (§5.5) are both built
and served over the wire, which closes the last two M1 protocol items.

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
  passing security control. `nas peer serve` runs a `nas-peer` behind a
  `nas-transfer` listener; `nas peer sync` pushes a local namespace to it with
  the peer's key pinned on the command line, so a peer presenting any other key
  is refused before a single record is sent.
- **`tests/usecases/`** — 88 acceptance assertions, milestone-gated; 58 are
  M0–M2. Measured on the current binary: **5 passing, 0 failing, 83 pending**
  at `NAS_MILESTONE=M0`; **36 passing, 0 failing, 52 pending** at
  `NAS_MILESTONE=M1` (what `ci.sh` gates on); **49 passing, 9 failing, 30
  pending** at `NAS_MILESTONE=M2`. UC07's two witness-node assertions
  (a fork detected by devices that never meet; the node holds no blobs and no
  slot data) pass in-process via `nas test fork-detect-via-witness` and
  `nas test witness-node-holds-nothing`. UC01 (transit-only), UC02 (passphrase)
  and UC03 (e2ee) are all green end to end; UC04 (WORM) is 9 of 13, the four
  remaining being the object verbs and the ACL grant they need; UC09 (hostile
  peer) is 6 of 8, the two remaining being lease griefing and the `all` drill
  that contains it. Verified to
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
| Rust unit tests | 367 |
| Lean theorems (clean axiom gate) | 14 |
| `cargo-fuzz` targets | 11 |
| Acceptance assertions passing (≤M1) | 36 of 88 |
| Acceptance assertions pending (M2+) | 52 |

**36 of 88 is a progress marker, not a verification result.** The 52 pending
assertions are not failures and not successes — they are unwritten code that
`ci.sh` refuses to score. Every one of them is a claim SPECS makes that nothing
yet demonstrates, and the four use cases with a passing score (UC01–UC03,
UC09) are the ones whose milestones have arrived. UC04 and UC07 — deletion
resistance and roaming — are at zero.

The UC09 drills (`nas test attack <kind>`) run the server's own dispatch
against a peer opened with one hostility flag, after first proving the same
flow succeeds against an honest peer; the transport is not in the loop, so
"6 of 8" is a statement about the client-side controls, not about the wire.
Two of the drills are explicit about their limits: `withhold` is caught against
the client's upload receipt and cannot distinguish withholding from loss, and
`witness-withholding` exits 2 from a single relay — SPECS §5.4 says it is
undetectable there — passing only when a second, witness-only relay exists.

TLC is green with its three sanity checks still failing as required.

> The TLA+ model constrains SPECS §5, which is **M2** code. It is assurance
> about the design, not about anything shipped. Its correspondence to
> `nas-slots` is **partial**: same-sequence equivocation only, asserted as such
> by `a_fork_at_disjoint_sequences_is_not_detected`. Once the peer's history
> is offered it does see it (`…is_detected_once_the_chain_is_walked`), which
> is what `nas peer sync` does over the wire.

## Not built

M2: the object verbs `put`/`rm` — which need the key→object mapping the S3
face brings, so they are reclassified M3 (§7.1) rather than pending here. Nine
assertions still fail at `NAS_MILESTONE=M2`.

**The single-writer handoff (§5.1) is built.** `SlotHandoff` is signed by the
*outgoing* writer and binds slot, sequence and both writers, so it authorises
one change rather than granting a reusable token — the distinction between a
handover and a takeover, which is the whole of §5.1. It is a standalone record
rather than a field on `SlotRecord`, because that format is peer-facing and
frozen (§20). `verify_chain_with_handoffs` accepts an authorised change;
`verify_chain` still refuses every change, which is the right default for a
caller that was handed no handoffs.

**It is now on the wire.** `PublishHandoff` / `Handoffs` are dispatched like
the witness pair, so a device can learn of an ownership change it did not
make; `nas peer sync` fetches them, keeps only those that verify for the slot,
and walks with them. Making the store network-reachable is what forced two
fixes to it: it is bounded (`MAX_HANDOFFS_PER_SLOT`, refusing rather than
evicting — evicting a handoff turns an authorised change back into a
takeover), and it is keyed by the authorisation rather than held in a `Vec`,
which closed a filename collision that let one of two handoffs vanish across a
restart. A witness-only node refuses both requests: a handoff is an
authorisation, not an observation, and §5.3 says that node holds no caps.

Sync deliberately does **not** add a handoff's `from_pk` to its roster, though
the record carries the key in full and it would be easy. That would let the
peer decide who may have written this namespace's history, which is the one
thing a roster exists to say. The consequence is stated rather than hidden: a
chain crossing an authorised change still stops at `UnknownWriter` until a
device can be told about another writer by something other than the peer. It
changes no outcome today either way — every device of a namespace derives the
same `Role::Slot` key, so the CLI has only ever had one writer per slot.

**Skip-chain checkpoints (§5.5) are built.** A `Checkpoint` is the writer's
signed assertion that the record at some sequence is a given hash and that the
rung below it was a given checkpoint — hash-linked, so the ladder is a chain
rather than a pile of independent claims, and a rung removed from the middle
does not verify. `verify_skip_chain` climbs the ladder and then walks the tail
records in full, which bounds the unverified span by the checkpoint interval:
recent history, where an omission matters most, is never skipped.

What it proves is stated in the type rather than left to the reader.
`SkipWalk` reports `records` and `skipped` separately, because a skip walk
proves the *writer* committed to this ancestry and does **not** prove the
records between two rungs exist or chain — a peer may omit or substitute those
unseen. It is strictly stronger than the degraded head-only path (which has no
ancestry at all) and strictly weaker than a full walk, and §5.4 says to name
that rather than round it up. Against a lying *writer* neither helps; that
needs a second observer, which is what witnesses are for.

`PublishCheckpoint` / `Checkpoints` carry it. The peer keeps **both** of two
conflicting rungs at one sequence: the writer equivocating about its own
history is evidence, and choosing which branch to keep is the one thing a
distrusted peer must not decide. `nas peer sync` publishes a rung every 256
records, verifies the served ladder against a pinned top rung, and pins a
ladder it merely verified as well as one it published — so a peer that drops
or replaces the ladder is refused by a device that never wrote a rung.
Demonstrated across processes in MANUAL-TESTING §14.

The saving is now taken. `plan_walk` is a pure function — the `plan_sweep` /
`decide` shape — that picks the full walk whenever it is within budget and
climbs otherwise; the full walk wins ties, because it proves contiguity and a
ladder does not. `nas peer sync` pages the tail and reports both numbers: how
many records it verified link by link, and how many it took on the writer's
word. A memory falling in the skipped span is counted as **unchecked**, not
quietly passed.

Building it found two defects that the ladder itself had hidden:

- **`MAX_RECORDS = 256` was unreachable.** A `SlotRecord` is ~3.5 KB, so 256
  of them are three times `MAX_FRAME`. A peer asked for a long history built a
  response it could not encode and **dropped the connection** — turning a
  partial answer into what a client cannot distinguish from the peer dying,
  which is the one thing the dispatch is written to avoid. List responses are
  now bounded by bytes as well as by count, in one place for all four of them.
- **Without paging the ladder was decorative.** The checkpoint interval is 256
  and one response carries ~74 records, so no rung could ever leave a tail
  short enough to walk. The *ladder* fetch had the same defect and was worse:
  asking once truncated it at the **bottom**, losing exactly the high rungs a
  far-behind client climbs to, so a good ladder read as "unreachable" past
  about 19 000 records.

The interval itself was then checked rather than assumed, and **256 stands**.
Climbing costs `S/I + I` items, minimised at `I = sqrt(S)`; for §5.5's own
100 000-behind example that is ~316, so 256 costs 646 against an optimum of
632. Shrinking it to fit one response would cost 1425 — more than double. A
frame size is a transport limit and has no business setting a protocol
constant, so both fetches page instead.

**The deletion approval loop (§16.2) is built** (`crates/nas-delete`):
`DeleteRequest` / `DeleteApproval` / `DeleteExecution`, quorum scaled by blast
radius, and the rolling window that makes decomposition expensive — past ten
single-object deletes in thirty days, the next owes the namespace quorum
whatever its scope. `decide` is pure, like `plan_sweep`: it returns a verdict
and deletes nothing, because the data-destroying operations should be
inspectable before they run. Approvals bind the request hash, so one cannot be
replayed against another request, and two approvals from one holder count as
one holder.

Cooling-off is where the honesty matters. SPECS §16.2 is explicit that there
is no trusted time source in this design — the peer's clock is adversarial by
assumption and the requester signs its own timestamp — so **nothing in the
protocol can enforce a delay**. `Approver::may_sign` is a client-side gate
against the device's own clock: it buys a human time to notice and compels
nothing. Key separation is what defeats ransomware; the delay is a convention.
`nas delete-request execute` accordingly refuses and names the missing step
rather than pretending to delete.

Lease-based GC **has** a caller now: `Peer::sweep` plans with
`nas_lease::plan_sweep` and deletes through `delete_blob`, so retention is
applied twice — as the floor handed to the planner, and again on the way out.
Quota breaches are reported and never enforced by deleting (§6.4), which is
the point: an accounting dispute must not become data loss. Retention is
enforced as SPECS §16.3 specifies it — `Peer::publish_retention` takes the
whole proposed set and refuses any publish that drops an address, a plaintext
comparison the peer can make without reading anything.

**What Object Lock does and does not do today.** `nas ns create --object-lock
<governance|compliance|legal-hold> --retention <7y>` records the policy in the
plaintext config, and `ns create` prints which half is live: the extend-only
retention set is enforced; the retention *period*, and shortening or loosening
the policy, are not — they need the offline delete authority and its quorum
(§16.1–§16.2), which is unbuilt. A namespace created this way is not yet proof
against an owner who holds that key, and says so on creation.

Fork detection over the wire against a live
forking peer now exists (`tests/usecases/uc12_fork_drill.sh`,
MANUAL-TESTING.md §13): `nas peer sync` walks the peer's retained history
from the lowest witnessed or pinned sequence and compares each witness and
the pin at its own sequence, so a fork *below* the served head is refused
over a real socket. The three-node container simulation exists too
(`tests/usecases/uc11_containers.sh`, MANUAL-TESTING.md §10b): host-built
`nas` binary, three slim runtime containers on one compose network, honest
peer restarted `--hostile rollback`, a `--witness` node, three devices —
same assertions as the localhost drill, all passing under colima.

## Environment constraints

16 GB RAM on the dev machine. Docker 29.3 (desktop-linux), colima 0.10.1, lima
2.1.0 available. The multi-node simulation must build on the host and run slim
runtime containers — a `cargo` toolchain inside each node would not fit.

See `TODO.md`.
