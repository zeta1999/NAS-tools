# Implementation plan — M0 → M2

> **Revision 2**, after an adversarial review of revision 1. Revision 1 had an
> unsatisfiable definition of done, a Step 0 whose central claim was false, and
> four unowned subsystems. See §8 for what changed.

Scope: **M0 through M2** — up to where *"resists a hostile peer"* is demonstrated
rather than intended. Padding defaults to `none`.

**Definition of done: the 53 M0–M2 acceptance assertions in `tests/usecases/`
pass.** The other 30 stay PENDING (M3–M5) and 1 is deferred (M6). Revision 1 said
"all 81", which was unachievable inside this scope — and since `ci.sh` runs the
harness, that would have made CI permanently red from the first binary, until
somebody disabled the gate.

---

## 1. Step 0 — the dedup scheme decision

**Revision 1 claimed this "locks the on-disk format." That was wrong.** SPECS §4.3
stores `ck` per chunk *because a reader has no plaintext and cannot derive it* —
so reads never derive a key from `CS`, and `addr = BLAKE3(ct)` either way. The
blob and manifest layouts are already scheme-agnostic.

What it actually locks: the **capability format** (whether a cap carries `CS`),
the **write/dedup path**, the **rotation machinery** (§3.9c), and the **test
contract** — SPECS §12.5 and `uc03` hard-code the confirmation-attack pair, so
choosing "indexed" means editing the spec and the harness too.

| | Convergent (spec) | Indexed (`BLAKE3(pt) → addr`, random keys) |
|---|---|---|
| Reads from cold with only a key | yes | yes — only *dedup* degrades until the index syncs |
| Confirmation oracle | yes, gated on `CS` | yes, gated on **the index** — a stolen snapshot is an oracle over everything indexed at that moment |
| Extra machinery | `CS`, generations, rotation, per-tenant salt | multi-writer index merge, index recovery |
| Multi-writer cost | none | a new consistency object riding slots that don't exist until M1 |

Revision 1's table claimed indexed had "no blast radius" and did not work from
cold. Both were wrong, in opposite directions.

> **Recommendation: convergent, as specified**, plus a `key_scheme` byte in the
> manifest so the door stays open at zero cost. The oracle needs `CS` compromise
> and is within-tenant; `passphrase` mode already forces per-namespace `CS_ns`;
> and indexed drags a multi-writer index-merge problem into M0, before slots
> exist to carry it.

---

## 2. Cross-cutting work, owned explicitly

Revision 1 had no owner for any of these, while the harness demands all of them.

| Concern | Where | Why it cannot wait |
|---|---|---|
| **Clock abstraction** | `nas-core`, M0 | Lease expiry, grace, sweep, cooling-off and "30 days offline" all need virtual time. A `Clock` trait retrofitted after M0 touches every crate. |
| **`nas test` substrate** | `nas-cli`, M0→M2 | ~40 subcommands that spawn topologies, inject hostility and drive virtual time. This is a test *framework*, comparable to a crate — not CLI plumbing, and partly needed at M0. |
| **Vault + identity + pairing** | `nas-vault`, M1 | `vault.bin` holds ML-DSA identities, `CS` generations, pinned peers, blocklist. Pairing distributes `CS` and negotiates quota and accepted modes. |
| **`nasd`** | folded into `nas-cli` for M0–M2 | A stated decision, not an omission: the trust boundary is a library plus a CLI until the gateway arrives at M3. |
| **Config** | `nas-core`, M1 | The §19 cookbook YAML shapes are the user-facing contract. |
| **Observability** | all, from M0 | Our security model *is* detection. An alarm with no output channel is not detection. Structured `tracing` from the first crate. |
| **Format versioning** | `nas-core`, M0 | Every on-disk and on-peer record carries a scheme/version field. Five plaintext peer record types are new in SPECS rev 5 and unexercised. |
| **Fuzzing** | `fuzz/`, M1 | `formal/README.md` calls this the highest value per hour in the project, and revision 1 omitted it from CI. Every parser taking peer bytes. |

---

## 3. M0 — substrate, local only *(baseline: 1×)*

1. **`nas-core`** — types, error taxonomy, addresses, caps, manifest format with
   version + `key_scheme` fields, the canonical length-prefixed encoder, the
   `Clock` trait. ✅ *encoder landed; proptests mirror the Lean theorems.*
2. **`nas-crypto`** — the §3.1 key schedule, the **only** place a nonce is chosen.
   Callers pass a `KeyClass`; a deterministic nonce is *unreachable* for a
   non-content-derived key. All **twelve** signing contexts.
3. **`nas-store`** — FastCDC, padding with **checked** subtraction (`class - 4 -
   len` underflows on `usize`; the Lean proof misses it because `Nat` truncates),
   blob store, manifests, per-directory keys. *No cache — that is an M4 mount
   concern and revision 1 pulled it in for no reason.*
4. **`nas-cli` + test substrate** — `ns create/put/get/ls`, and the `nas test`
   scaffolding with the **exit-2 refusal contract** the harness now enforces.

**Exit:** the 5 M0-tagged assertions pass; padding overhead measured on a real
corpus and recorded in `MANUAL-TESTING.md`.

## 4. M1 — peer, modes, vault *(~3× M0)*

Revision 1 called this "push/pull + lease cycle" while the harness hung 20
further assertions on it — two confidentiality modes, peer ACLs, wrap records.
That is how revision 2 of SPECS ended up with a milestone containing half the
project; naming the sizing is how it stays visible.

5. **`nas-slots`** — records, both regimes, history, anchors, pins, skip-chains.
6. **`nas-lease`** — deltas, checkpoints, grace, quotas. **Measure ML-DSA record
   sizes here, while the structs are being designed** — not "at M1" generically.
   3.3 KB per signature is the constraint that shaped §3.8.
7. **`nas-vault`** — identities, `CS` generations, pinned peers, pairing.
8. **Modes** — `transit-only` (per-tenant salt, plaintext names, peer read ACLs)
   and `passphrase` (Argon2id KEK, `WrapRecord` carrying the freshness anchor,
   rewrap-not-reencrypt, superseded-wrap deletion).
9. **`nas-transfer`** — over `simple-network` `pqc`. ✅ *upstream committed and
   tagged `pqc-protocol-v1`; `simple-backups` verified green against it (16 tests).*
10. **`nas-peer`, built hostile from day one.** Blob store, slot ordering and CAS,
    plaintext roster verification, retention with peer-verified superset
    semantics, lease sweep, PoP responder, `--witness`.

    > **`--hostile tamper|rollback|withhold|dedup-lie|fork|ignore-retention`
    > ships in M1, not M2.** Revision 1 put it in M2 while arguing it was
    > load-bearing. But the five plaintext peer record formats freeze during M1
    > and are format-breaking to change (§7 risk). Adding hostility afterwards
    > means those formats never feel adversarial pressure while they are still
    > cheap to change — which is exactly when a crafted record that slips past
    > the retention-superset comparison would be found.

11. **Simulation.** Start with **three `nas-peer` processes on localhost ports** —
    that exercises everything except network namespaces, for zero VM cost.
    Containers only when isolation is genuinely needed:
    `colima start --cpu 4 --memory 2 --disk 40` (revision 1 said 6 GB, which
    over-allocates on a 16 GB box: three distroless containers running one static
    binary each need well under 2 GB). Cross-compiling on macOS arm64 needs
    `aarch64-unknown-linux-musl` plus a cross linker — **name the toolchain
    (`cargo-zigbuild`) or use a multi-stage Docker builder.** "No cargo in the
    image" is about the *runtime* image.

**Exit:** the 20 M1-tagged assertions pass; fuzz targets running.

## 5. M2 — adversarial detection and the deletion loop *(~2× M0)*

12. **Detection** — witness publication and relay, chain walking, cold start from
    a capability alone. The client must re-evaluate accumulated evidence on
    **every pin change**, never on witness arrival: TLC found the arrival-only
    version admits an undetected fork in 7 states, and "handle the event, then
    forget it" is how anyone writes it by default.
13. **The §16 deletion loop** — `DeleteRequest/Approval/Execution`, scope-scaled
    quorum with the rolling-window decomposition defence, approver-device
    cooling-off, key separation, `simple-secrets` Shamir integration. Revision 1
    planned the *model* of this and none of the code.
14. **Model checks** — `LeaseGC.tla`, `DeleteQuorum.tla`, each with must-fail
    sanity checks, wired into `formal/check.sh`.

**Exit:** the 28 M2-tagged assertions pass, including cold-start.

---

## 6. Engineering discipline

**RAM.** `debug = 1`, `codegen-units = 16`, deps at `opt-level = 2` — already in
`Cargo.toml`. The real lever is a concrete parallelism cap: **`cargo build -j 6`**
while anything else is running. Never run `DEEP=1 ./formal/check.sh` (3 GB, 46 s)
during a build.

**CI — `ci.sh`.** fmt → clippy `-D warnings` → test → `formal/check.sh` →
`tests/usecases/run.sh` at the current `NAS_MILESTONE`. Gates that are easy to
lose: fails on `sorry`; fails if a TLA+ sanity check stops failing; PENDING never
counts as passing; **`check_refuses` demands exit 2 specifically**, so a stub that
errors on everything fails instead of passing.

**Commits** per crate-level milestone, message carrying the acceptance delta.
Branch `impl/m0`, merge at milestone boundaries.

**Review** after each of M0, M1 and M2 — not only at the end. Four review rounds
have now each found blockers, and every one was cheaper before the format hit disk.

---

## 7. Risks, ranked

1. **`ml-dsa = "0.0.4"`** — a pre-1.0, pre-audit RustCrypto crate is the signature
   scheme under *every* security property here. Needs a pinning and upgrade
   policy, and a decision about what a breaking change to it costs us.
2. **The peer's plaintext record formats** — roster, retention, lease, wrap,
   witness: five signed structures introduced in SPECS rev 5, unexercised by any
   code, and format-breaking to change. Mitigated by building the hostile peer in
   M1 (§4.10).
3. **Test-substrate cost.** ~40 `nas test` subcommands driving topologies,
   hostility and virtual time. Easy to underestimate; partly needed at M0.
4. **Virtual-time retrofit.** Mitigated only if the `Clock` trait lands in M0.
5. **BLAKE3 is a new dependency.** SPECS §3's "all primitives already exist in the
   sibling crates" is false for it — no sibling uses it. Load-bearing and new.
6. **Single-developer bandwidth** across 9 crates and 2 further TLA+ models.

*Dropped from revision 1:* the harness defects (fixed); the `simple-network` wire
break (committed, tagged, verified); FastCDC × padding (moot now `padding: none`
is the default — it only bites opt-in users).

---

## 8. What changed in revision 2

| Change | Driver |
|---|---|
| Done = 53 M0–M2 assertions, not 81 | 25 belonged to M3–M5; with `ci.sh` running the harness, CI would have been red from the first binary until someone disabled the gate |
| Harness gains milestone gating, an exit-2 refusal contract, and a fixed exit check | `check_refuses` passed on *any* non-zero exit, so a stub CLI erroring on everything passed all 14 security assertions; `run.sh` checked `echo`'s status |
| Assertions reconciled with §5.4, §2.2, §19.1 | Three claimed more than the spec guarantees — including one that the must-fail `ForkAlwaysDetected` check deliberately disproves |
| Step 0 restated | It locks caps and the test contract, not the disk format; both directions of the comparison table were wrong |
| §2 cross-cutting work given owners | Clock, test substrate, vault, pairing, config, observability, versioning and fuzzing had none |
| Modes and the §16 loop given steps | 31 assertions depended on code no step built |
| Relative sizing added | Absence of estimates is the mechanism by which a milestone hides half a project |
| Hostile peer moves to M1 | Formats freeze in M1; adversarial pressure must arrive before they do |
| Simulation starts as localhost processes; VM 6 GB → 2 GB; cross-toolchain named | Containers were assumed rather than justified, and over-allocated |
| Risks reranked | `ml-dsa 0.0.4` and the plaintext record formats outrank everything revision 1 listed |
