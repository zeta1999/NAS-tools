# NAS-tools — specs

> **Revision 5.** Fixes six blockers found reviewing revision 4: the roster was
> unreadable by the peer that must check it (§3.5), `append` was not peer-
> enforceable in encrypted modes (§16.3), `passphrase` mode's recovery path was
> unspecified (§2.2.2), `transit-only` dedup leaked a confirmation oracle to
> co-tenants (§2.2.3), revision 4 contradicted the Goal and §12 (both rewritten
> mode-conditionally), and the deletion quorum fell to decomposition (§16.2).
> Padding now defaults to `none`.
>
> **Revision 4.** Adds confidentiality **modes** (§2.2) — end-to-end encrypted is
> no longer the only option — plus the git remote helper (§7.3), the four layers
> of permissions and ACLs (§15), append-only / Object Lock with a deletion
> approval loop (§16), DVC integration (§17), the formal-methods plan (§18), and
> a use-case cookbook mapping intentions to configuration (§19), and requirement
> traceability explaining why each feature exists (§20). See §21.

## Goal

A suite of NAS-style decentralized tools where **storage peers are untrusted and
hold ciphertext by default**. Three application faces — a git-style app, an
S3-style app, a doc-style app — over one content-addressed substrate, plus a
read-only filesystem mount.

*"By default"* is load-bearing: a namespace may opt out per §2.2 and store
plaintext on a peer you trust to read it. What never varies is integrity,
authenticity and rollback detection.

Part of **simple tools**. Reuse sibling crates; do not reinvent crypto.

## Non-goals (v0)

- Read-write mount (RO first; write-back cache and FS-layer conflict handling deferred)
- Erasure coding (replication only)
- Access-pattern privacy (ORAM); see §1 — this leak is accepted and documented
- Cross-tenant deduplication (deliberately given up, see §3.2)
- **Server-mediated** public sharing / presigned URLs, in `e2ee` and `passphrase`
  namespaces — a peer there can only hand out ciphertext. Sharing *is* supported
  by handing a read-cap out of band; scoped sub-namespace caps are post-v0.
- **Peer-side features** (thumbnails, indexing, transcoding, a web gallery).
  `transit-only` (§2.2.3) makes them *possible*; v0 does not ship them. They are a
  remote plaintext-serving surface needing their own identity model, auth
  protocol and transport story, and half-specifying that is worse than deferring
  it. §2.2.3 lists what the mode permits, not what exists.
- Byzantine consensus between peers (fork *detection*, not prevention — §5)
- Mobile clients (a mobile `nasd` is post-v0; `simple-backups` has the Android scaffold)

## Inspiration / prior art

- `../simple-backups` — repo model, CAS layout, manifests, refs, gc, PQC pairing, push/pull
- `../simple-network` (`pqc`) — hybrid ML-KEM-768/X25519 channel, ML-DSA-65 auth, XChaCha20 records
- `../simple-secrets` + `../rust-secure-memory` — vault, zeroizing key handling, PQC KEM
- `../seal-dao-public` — house PQC posture (ML-DSA-65 / ML-KEM-768 / SHA3)
- Tahoe-LAFS — capability model, convergence secret, lease-based GC
- Cryptomator — per-segment filename encryption
- SUNDR — fork consistency. **We do not reach it**; see §5.4 for the honest bar.

---

## 1. Threat model

**Adversary A — the storage peer.** It stores our blobs, serves them back, and is
assumed actively malicious: it may read everything it holds, withhold data, lie
about what it holds, replay old state, and collude with other peers.

**Adversary B — a future quantum adversary** recording traffic today
(harvest-now-decrypt-later).

**Adversary C — a local process** on the client machine. New in revision 2: the
localhost gateway is *not* a security boundary by itself (§2.1).

> **Everything in §1 describes the default `e2ee` mode.** Two other modes exist
> (§2.2) and they trade confidentiality away deliberately. What does *not* vary
> by mode: integrity, authenticity, rollback detection, leases and witnesses are
> identical in all three. You never lose the ability to know your data was not
> tampered with — only, sometimes, the guarantee that nobody read it.

### What is protected

| Property | Mechanism | Strength |
|---|---|---|
| Content confidentiality | XChaCha20-Poly1305, keys never leave `nasd` | strong |
| Content integrity | `addr = BLAKE3(ciphertext)`; `pt_hash` re-checked after decrypt | strong |
| Mutable-state authenticity | ML-DSA-65 over every slot version, context-tagged | strong |
| Rollback / replay | cap freshness anchor + slot history chain + client gossip | **detection only**, and only for clients that eventually communicate — §5.4 |
| Confirmation attacks | per-tenant convergence secret `CS` | strong while `CS` is unleaked; unrevocable once shared — §3.5 |
| Harvest-now-decrypt-later | hybrid ML-KEM-768 for all key distribution | strong |
| Dedup-skip data loss | proof-of-possession challenge before honouring a skip (§4.5) | strong |

### What is NOT protected (accepted leaks)

- **File size**, to chunk granularity. No padding in v0.
- **Chunk-length distribution — reduced, not eliminated.** CDC boundaries are
  plaintext-determined, so the sequence of chunk lengths fingerprints a file. As of
  revision 3, chunks are padded to size classes (§4.2.1), coarsening the sequence
  from exact byte lengths to a short ladder. A peer can still compare *class*
  sequences without `CS`; the attack becomes much noisier, not impossible. Only
  fixed-size chunking removes it outright, at the cost of shift-resistant dedup.
- **Lease inventories.** A lease set is a signed, cleartext list of every address
  a holder retains. Diffing epochs yields exact churn — what was added, what was
  deleted, when — bound to a long-term identity and correlatable across colluding
  peers. This is the single largest metadata artifact in the design. Partial
  mitigation: deltas are batched to epoch boundaries so timing is coarse (§6).
- **Dedup equality oracle.** The peer observes whether a write introduced zero new
  blobs or N new blobs, giving intra-tenant content-equality and snapshot-similarity
  signal. Distinct from access patterns.
- **The writer roster.** It must be plaintext, because the peer that enforces it
  cannot read encrypted manifests (§3.5). That publishes device count, each
  device's verifying key, and the timing of additions and revocations —
  correlatable with the lease inventory above. This leak is the direct price of
  peer-enforced write control; the alternative was no enforcement at all.
- **Retention sets.** Like lease sets, a plaintext list of protected addresses
  with an expiry (§16.3).
- **Access patterns.** Which blobs are fetched, together, in what order. Defending
  this means ORAM, unusably slow for a filesystem.
- **DAG shape**, partially — manifest sizes imply object counts.
- **Activity timing** — when writes happen, and how big they are.
- **Local plaintext**, bounded: the chunk cache is encrypted under an ephemeral
  per-boot key (§8.3), but the gateway necessarily handles plaintext in memory,
  and any process running as the same user can reach the gateway (§2.1).

Anyone deploying this must understand that content is protected and *behaviour*
is not.

---

## 2. Architecture — the trust boundary is a local daemon

An S3 client expects plaintext. So does `git`. So does the kernel. If a peer only
ever sees ciphertext, **no app face can be a remote endpoint** — each is a
localhost adapter in front of `nasd`, which owns the keys.

```
  git remote  ──→ unix socket ──┐
  aws / rclone ─→ 127.0.0.1 ────┤
  doc client  ──→ unix socket ──┼──→ [ nasd ]  ◀── trust boundary
  WebDAV mount ─→ 127.0.0.1 ────┘        │
                                         │  CDC → encrypt → BLAKE3(ct) → ML-DSA sign
                                         ▼
                               untrusted peers running `nas-peer`
                                  blobs + slot history + leases
```

### 2.1 Gateway authentication (was missing in revision 1)

"Localhost-only" is not access control: any process of any user on the machine
can otherwise connect and read the whole namespace in plaintext.

- **Default transport is a unix domain socket** at `$XDG_RUNTIME_DIR/nasd.sock`,
  mode `0600`. The git remote helper and doc client use it.
- **TCP is opt-in**, bound to `127.0.0.1` only, and required only because `aws`
  and `rclone` cannot speak unix sockets. It demands a credential:
  - S3 face: SigV4 against a locally generated access-key pair in `state/gateway.json` (`0600`).
  - WebDAV face: Basic auth over loopback with the same secret.
- **Residual, stated plainly:** a process running as the *same user* can read the
  socket or the token file and is therefore inside the boundary. Full per-app
  isolation needs capability handoff and is post-v0.

### 2.2 Confidentiality modes — NORMATIVE

Not all data wants the same treatment. Family photos on a NAS in your own house
have a different threat model from source code on a rented VPS, and forcing both
into end-to-end encryption gets you a single point of failure — lose the vault,
lose the photographs — in exchange for protection against an adversary who was
never there.

Three modes. **Mode is a property of a namespace, chosen at creation, and
immutable thereafter** (changing it would mean rewriting every blob).

| | `e2ee` *(default)* | `passphrase` | `transit-only` |
|---|---|---|---|
| At rest on the peer | ciphertext | ciphertext | **plaintext** |
| Key source | 32 B CSPRNG in the vault | Argon2id over a passphrase | none |
| In flight | PQC channel | PQC channel | PQC channel |
| Names | encrypted per segment | encrypted per segment | plaintext |
| Padding | `classes` | `classes` | `none` |
| Dedup scope | within tenant | within tenant | global on the peer |
| Peer can read content | no | no | **yes** |
| Peer-side features | none possible | none possible | thumbnails, index, search, gallery |
| Losing the key means | data is gone | recoverable from memory | nothing to lose |
| **Read** ACL enforceable by peer | no — cryptographic only | no | **yes** |
| Integrity, rollback detection, leases, witnesses | identical | identical | identical |

#### What the peer can actually enforce

Revision 4 claimed write ACLs were peer-enforceable in every mode. That was too
glib, and the correction matters because §16's ransomware defence rests on it:

| Peer-side check | `e2ee` / `passphrase` | `transit-only` |
|---|---|---|
| signature valid, writer is on the roster | **yes** — the roster is plaintext (§3.5) | yes |
| sequence monotonic, CAS honoured | **yes** | yes |
| retention set covers the addresses being swept | **yes** — the set is plaintext addresses | yes |
| lease quota per holder | **yes** | yes |
| read ACL | **no** — capability possession only | yes |
| **semantic** append-only: "no existing key was removed" | **NO** | yes |

That last row is the one to internalise. In encrypted modes a slot update is an
opaque new root address; **the peer cannot distinguish "added a key" from
"deleted every key."** Append-only is therefore not a peer-enforced property in
encrypted modes — it is enforced by the retention set (§16.3), recoverable from
slot history (§5.5), and audited by clients. §16 is written accordingly.

#### Rules

1. Mode is displayed in every listing, in the gateway's responses, and in the
   mount's presentation. It must never be unclear which mode you are writing into.
2. Copying between namespaces of different modes is an explicit, logged operation
   — never implicit. A downgrade (`e2ee` → `transit-only`) requires confirmation
   and is recorded in the audit trail.
3. Peers advertise the modes they accept at pairing. A rented VPS may be
   configured to accept `e2ee` only, and will refuse the rest.
4. Peer-side features (§2.2.3) are off by default even where the mode allows them.

#### 2.2.1 `e2ee`

As specified throughout §3. The namespace key is high-entropy and lives in the
vault. No recovery path exists by design: lose the vault and lose the data. Use
for anything whose exposure would actually hurt.

#### 2.2.2 `passphrase`

For data you want protected from the machine that stores it, but recoverable
from your memory rather than from a key file.

```
KEK = derive_key_argon2(passphrase, salt, m ≥ 256 MiB, t ≥ 3, p = 1)
DEK = 32 B CSPRNG                    ← the namespace root secret
wrapped = XChaCha20Poly1305(KEK, random_nonce, DEK)

    root_secret  = derive_key("nas-tools/ns/root/v1",        DEK)
    CS_ns        = derive_key("nas-tools/ns/convergence/v1", DEK)
    sk_slot_seed = derive_key("nas-tools/ns/slot/v1",        DEK)
```

> **The passphrase wraps a random key; it never *is* the key.** That indirection
> is what lets you change the passphrase by re-wrapping 32 bytes instead of
> re-encrypting a terabyte.

`derive_key_argon2` already exists in `rust-secure-memory`. `sequential_stretch`
must **not** be used here — it is not memory-hard, and this is precisely the
low-entropy input it is unsuited to.

> **Honest warning, to appear in the user manual verbatim.** The peer holds the
> ciphertext, so it can attempt an *offline* brute force at its leisure. Argon2id
> raises the cost per guess; it does not save a weak passphrase. Four words will
> eventually fall. Use five or more diceware words, and prefer this mode on
> hardware you own over hardware you rent.

##### What the DEK unwraps into

Revision 4 never said, and §3 has no single "namespace key" it could have meant.
Everything the namespace needs derives from the DEK, as above. Note in particular
that **the convergence secret is per-namespace (`CS_ns`), not the tenant-wide
`CS`** — otherwise a passphrase namespace would need a vault secret to write, and
"recoverable from memory alone" would be false. The price is that a passphrase
namespace deduplicates only within itself.

##### Where the wrap lives, and how recovery gets an anchor

```
WrapRecord { salt, argon2_params, wrapped_DEK, seq,
             anchor: (slot_seq, sig_hash), prev, sig }
sig context "nas-tools/sig/wrap/v1"
```

Stored **on the peer** beside the slot, signed, leased and covered by retention
so the peer cannot quietly drop it. If it lived only on your machine, losing that
machine would lose the wrap and "recoverable from memory" would be a lie.

**The wrap record carries the freshness anchor**, and that is what closes the hole
revision 4 opened. A client recovering from a passphrase alone holds no
capability, so under revision 4 it had no anchor — reopening exactly the
bootstrapping rollback hole §5.3(1) exists to close. Here **the wrap record *is*
the capability** for this mode: unwrapping it yields both the key material and the
`(seq, sig_hash)` floor beneath which nothing will be accepted.

##### Changing a passphrase does not retire the old target

Re-wrapping is mechanically cheap, but a peer that keeps the superseded
`WrapRecord` keeps a brute-force target against the *old* passphrase forever, and
that record still unwraps the same DEK. So:

- Superseded wraps are deleted, and `prev` chaining makes their absence checkable.
- **Against a hostile peer this is best-effort** — it may retain a copy, and
  nothing can stop it. Genuinely retiring a compromised passphrase means rotating
  the DEK and re-encrypting, exactly as §3.9(c) requires for `CS`.
- The user manual must say "changing your passphrase protects future writes; it
  does not un-expose data an attacker already copied."

#### 2.2.3 `transit-only`

Encrypted on the wire, plaintext at rest. The peer can read everything.

- `addr = BLAKE3(tenant_salt ‖ plaintext)`. Revision 4 used bare
  `BLAKE3(plaintext)` and called global dedup "harmless: there is no
  confidentiality claim to leak" — which considered only the peer as reader. **On
  a shared peer it hands every co-tenant a confirmation oracle:** upload a
  candidate file into your own namespace, watch for the dedup skip (§4.5), and
  learn that somebody else on this peer holds it. "Not secret from my own NAS" is
  a very different statement from "confirmable by anyone who rents space beside
  me." A per-tenant salt restores tenant-scoped dedup and removes the oracle. The
  salt is not secret; it only has to be unshared.
- Padding is pointless (the peer sees the content anyway), so it defaults to
  `none` — recovering the 20–35 % overhead.
- Names are plaintext, which is exactly what makes server-side browsing possible.
- Unlocks optional peer features: thumbnail generation, full-text indexing,
  transcoding, a web gallery. All off by default, all impossible in the other
  two modes.
- Slots are still signed, sequence numbers still enforced, rollback still
  detected, leases and witnesses unchanged.

> **What you give up, stated bluntly.** In `transit-only`, read access control is
> a policy the peer chooses to enforce, not mathematics. If you do not trust the
> peer, you have **no read access control at all** in this mode. It is the right
> choice for a machine in your own house and the wrong one for a rented box.

---

## 3. Crypto specification

All primitives already exist in the sibling crates. Nothing new is invented.

| Purpose | Primitive | Note |
|---|---|---|
| Content hash | BLAKE3-256 | see §3.6 for the honest rationale |
| Bulk encryption | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce, 128-bit tag |
| Key derivation | BLAKE3 `derive_key` / `keyed_hash` | domain-separated, §3.1 |
| Signatures | **ML-DSA-65** (FIPS 204) | pk 1952 B, sig 3309 B |
| Key distribution | **hybrid ML-KEM-768 + X25519** | via `simple-network` `pqc` |
| Transport | `simple-network` `pqc` channel | Tor / I2P carriers available; §14 |

### 3.1 Key and nonce schedule — NORMATIVE

> **The rule:** a deterministic nonce is permitted **only** when the key is
> content-derived, because such a key cannot encrypt two different plaintexts.
> **Every non-convergent key uses a fresh random 24-byte nonce**, stored beside
> its ciphertext. Revision 1 omitted this and was one implementer-inference away
> from keystream reuse on the root manifest.

| Key | Derivation | Encrypts | Nonce | May it see two plaintexts? |
|---|---|---|---|---|
| `CS` (tenant convergence secret) | 32 B CSPRNG, vault-held, never leaves `nasd` | nothing directly | — | — |
| `ck` (chunk key) | `BLAKE3::keyed_hash(CS, plaintext_chunk)` | exactly one plaintext, ever | deterministic: `keyed_hash(ck, "nas-tools/nonce/chunk/v1")[..24]` | **No** — content-bound by construction |
| `dir_secret` (per directory) | `derive_key("nas-tools/dir/v1", parent_dir_secret ‖ dir_id)` | nothing directly | — | — |
| `dk` (directory manifest key) | `derive_key("nas-tools/dir/manifest/v1", dir_secret)` | one manifest version | **random 24 B** | **Yes** → random nonce mandatory |
| `rk_v` (root manifest key) | **per-version:** `derive_key("nas-tools/root/v1", root_secret ‖ le64(seq))` | one root version | **random 24 B**, stored with the ciphertext | **No**, given per-version derivation *and* random nonce — belt and braces |
| `cache_k` | 32 B CSPRNG per boot, `rust-secure-memory`, zeroized on shutdown | cache entries | **random 24 B** | Yes → random nonce mandatory |
| `sk_slot` | ML-DSA-65, derived from vault seed, role-separated | signs only | — | — |
| `sk_lease` | ML-DSA-65, **distinct keypair** | signs only | — | — |
| `sk_transport` | ML-DSA-65, owned by `simple-network` | signs only | — | — |

**Signature domain separation — NORMATIVE.** Revision 1 specified KDF contexts but
not signature contexts, and implied one identity for everything. Every signed
message is prefixed with its context string, and roles use distinct keypairs:

```
"nas-tools/sig/slot/v1"             "nas-tools/sig/lease/v1"
"nas-tools/sig/checkpoint/v1"       "nas-tools/sig/roster/v1"
"nas-tools/sig/cap/v1"              "nas-tools/sig/witness/v1"
"nas-tools/sig/retention/v1"        "nas-tools/sig/delete-request/v1"
"nas-tools/sig/delete-approval/v1"  "nas-tools/sig/delete-execution/v1"
"nas-tools/sig/wrap/v1"             "nas-tools/sig/mirror-publish/v1"
```

Revision 4 listed only the first five and then introduced six more signed objects
without contexts — the exact mistake §3.1 exists to prevent. **Any signed object
added later must land in this list in the same commit that introduces it.**

`simple-network`'s handshake signatures carry contexts as of its protocol v1
(§14).

### 3.2 Convergent encryption

```
CS   = tenant convergence secret            (32 B, vault, never leaves nasd)
ck   = BLAKE3::keyed_hash(key = CS, input = plaintext_chunk)
n    = BLAKE3::keyed_hash(key = ck, input = "nas-tools/nonce/chunk/v1")[..24]
C    = XChaCha20Poly1305(ck, n, plaintext_chunk)
addr = BLAKE3(C)
```

- Identical plaintext under the same `CS` → identical `C` → dedup works.
- Without `CS` an outsider cannot compute `C` for a candidate file, so
  **confirmation-of-file attacks fail**.
- Dedup works *within* a tenant, never across tenants. Cross-tenant dedup is
  exactly the leak, so it is given up deliberately.

### 3.3 Key commitment

XChaCha20-Poly1305 is **not key-committing**. Addressing the ciphertext means a
*peer* cannot exploit this — but a write-cap holder could publish two manifests
citing one `addr` with different `ck`s that decrypt to different valid plaintexts.
Harmless among mutually trusting writers, live the moment semi-trusted writers
exist.

**Therefore:** every manifest entry additionally carries
`pt_hash = BLAKE3(plaintext_chunk)`, verified after decrypt. Cheap, restores
"one address = one content", and doubles as an integrity check.
`pt_hash` is unsalted and **must never leave the encrypted manifest** — exposing it
would reintroduce the confirmation attack.

### 3.4 Addressing ciphertext gives verification for free

Because `addr = BLAKE3(ciphertext)`, an untrusted peer can verify and repair its
own blobs by recomputing the hash, with no capability granted and nothing
revealed. Tahoe's separate verify-cap is unnecessary here.

### 3.5 Capability model and the convergence secret

Revision 1's write-cap could not actually write: it lacked `CS`.

| Cap | Contents | Grants |
|---|---|---|
| read-cap | `slot_id`, namespace verifying key, `root_secret`, **`CS`**, **freshness anchor `(seq, sig_hash)`** | read the namespace, safely, from cold |
| write-cap | read-cap + `sk_slot` + a roster entry | publish new slot versions |

- **`CS` distribution** rides hybrid ML-KEM-768 encapsulation over the
  `simple-network` `pqc` channel during device pairing. It is never written to a
  peer in any form.
- **`CS` is unrevocable by itself.** Any past holder can run confirmation attacks
  against existing blobs forever. Revocation therefore requires *rotation* into a
  new generation `CS'`, under which new writes dedup separately. Generations are
  numbered in every manifest so several coexist; see §3.9 for the full path.
- **Writer roster — a plaintext, slot-chained object, NOT inside the manifest.**

  ```
  RosterRecord { namespace_id, seq, writers: {writer_id → ML-DSA vk},
                 revoked: [writer_id], prev, sig }
  sig context "nas-tools/sig/roster/v1"
  ```

  Revision 4 placed it in the root manifest and simultaneously required the peer
  to check slot updates against it. The peer cannot read the root manifest, so
  peer-side write enforcement reduced to "any signature at all." It must therefore
  be plaintext, sequence-chained and signed by the namespace key.

  **This is a real leak** — device count, verifying keys, and the timing of every
  addition and revocation, correlatable with lease inventories. It is listed in §1
  and it is the honest price of peer-enforced write control. The alternative was
  believing in enforcement that could not happen.

### 3.6 Why BLAKE3 — corrected

Revision 1 justified BLAKE3 over the house SHA3 posture by claiming tree hashing
was functionally required for verified random-access range reads. **That was
wrong.** XChaCha20-Poly1305 needs the complete ciphertext to verify its tag, so
the read path fetches and verifies a whole chunk regardless. At 16–256 KiB chunks,
SHA3-256 per chunk would be functionally identical.

The honest rationale: BLAKE3 is chosen for **speed on the hot path** and because
its `keyed_hash` and `derive_key` modes are load-bearing throughout §3.1 — one
primitive serves as hash, MAC and KDF. Its tree structure is *not* exploited
today. Should the `large-object` profile (§4.2) ever want sub-chunk verified
reads, it would require Bao outboard trees **and** a segmented AEAD; neither is
specified, and both are out of scope for v0.

### 3.7 PQ rationale

- Symmetric primitives lose only a Grover factor of two; 256-bit parameters remain
  sound.
- **Ed25519 and classical-only KEX are excluded outright.** `iroh` was evaluated
  and **rejected** for exactly this reason (Ed25519 node identity, classical
  TLS 1.3), despite an otherwise excellent blob layer.

### 3.8 Signature-size consequence (architectural)

ML-DSA-65 signatures are ~50× Ed25519. Therefore:

> **Sign roots and deltas. Never sign leaves.**

This constrains three designs here: manifests are signed at the root only, leases
are signed as sets and deltas (§6), and per-chunk signatures are forbidden. It is
also why per-key slots were rejected for S3 (§7.1) — 3.3 KB of signature per
object is untenable.

### 3.9 Revocation paths

Three different things get revoked, and conflating them is how people end up
believing they are safe when they are not.

**(a) Blocking a peer.** Purely a local trust decision: drop it from the pinned
set, stop pushing, re-replicate its share elsewhere, and record it in a vault-held
blocklist. `nas-cli peer block <id>`.

> A blocked peer still holds every ciphertext it already had. Blocking stops
> *future* exposure. It does nothing about the past, and there is no mechanism that
> could — the bytes left the machine.

**(b) Revoking a device (the lost laptop).** Remove its `writer_id` from the signed
roster (§3.5) and publish a revocation record into the namespace root under
`"nas-tools/sig/roster/v1"`. That device can no longer publish slot versions any
honest verifier will accept. Peers are *told* to reject writes from revoked writer
ids — defence in depth only, since we do not trust them to comply.

> Roster removal stops **writes**. It does not stop reads: the device still holds
> `CS` and its read-caps, so everything it could already decrypt stays readable, and
> it can still run confirmation attacks. Stopping that needs (c).

**(c) Rotating `CS` — generational, lazy.** A full re-encrypt of a NAS is not an
operation anyone will actually run, so it must degrade gracefully:

1. Generate `CS'`, bump the generation counter. **All new writes** use `CS'`.
2. Remove the device from the roster (b) and block any peer it controls (a).
3. Background rewrite, hot data first, oldest generation last. Progress is
   observable; the job survives restarts.
4. Data still in generation `n` stays readable by the revoked device until its
   chunk is rewritten. **This is the honest security statement** and belongs in the
   user manual, not just here.

Rotation costs all cross-generation dedup for rewritten data. That is the price of
revocation and there is no cheaper one.

---

## 4. On-disk / on-peer layout

```
<repo>/
  config.yaml                    # repo-level defaults
  blobs/<ab>/<cdef…>             # encrypted chunks + manifests, addr = blake3(ct) hex
  slots/<slot_id>/<seq>.json     # SIGNED SLOT HISTORY, not just the head
  slots/<slot_id>/HEAD           # convenience pointer
  leases/<holder>/…              # signed lease checkpoints + deltas
  state/                         # LOCAL ONLY — pins, cache, gateway creds. Never shipped.
  vault.bin                      # ML-DSA identities, CS generations, pinned peers
```

A peer holds `blobs/`, `slots/`, `leases/`. Never `state/` or `vault.bin`.

**Slot history retention** is new in revision 2 and is required for chain
verification (§5.2). History records are leased like blobs, and may be compacted
below a client's acknowledged pin.

### 4.2 Chunking

FastCDC over plaintext. Defaults **min 16 KiB / avg 64 KiB / max 256 KiB**,
tunable per bucket.

The knob is read amplification: a 4 KiB read costs one whole chunk fetched,
verified and decrypted — 16× at 64 KiB average, 256× at 1 MiB. Backup-shaped
workloads want large chunks; a mount wants small. A `large-object` profile
(avg 1 MiB) exists for write-once bulk data.

### 4.2.1 Padding — NORMATIVE

Chunks are padded to size classes before encryption, to blunt the length
fingerprint (§1).

```
ladder  = { 32, 64, 128, 256 } KiB          # default; CDC avg 64 KiB lands mostly in 2 classes
padded  = le32(len) ‖ plaintext ‖ 0x00 × (class − 4 − len)
ck      = BLAKE3::keyed_hash(CS, padded)     # note: over the PADDED bytes
```

> **Padding MUST be deterministic.** Random padding would give identical plaintext
> different bytes, different `ck`, different ciphertext — destroying convergent
> dedup entirely. Zero-fill with a length prefix is deterministic and reversible.

Profiles, per bucket:

| Profile | Chunking | Fingerprint | Dedup | Overhead *(measured, M0)* |
|---|---|---|---|---|
| `none` *(default)* | CDC | full leak | best | 0% |
| `classes` | CDC + ladder | coarsened to class sequence | full | **+56%** large files, **+97%** many small files |
| `fixed` | fixed 64 KiB, no CDC | none | brittle — one insertion shifts everything | **+83%** / **+143%**, and dedup falls from 54% to 16% |

**Default is `none`.**

Revision 5 of this document estimated the premium at "20–35%" and required it be
**measured, not assumed** before anyone opted in. It has now been measured on two
real corpora (`MANUAL-TESTING.md` §5), and **the estimate was wrong by a factor
of two to three.** The figures above replace it.

Two causes, neither of which is a tuning problem:

1. **A ×2 ladder costs ~1.5× on any realistic distribution.** Chunks averaged
   81.7 KiB and padded to the 128 KiB class. There is no corpus on which
   20–35% was reachable with `{32, 64, 128, 256}`; the estimate was arithmetic
   that was never done.
2. **Small files pay the 32 KiB floor regardless of chunking.** In a source-tree
   corpus, 86% of files sat under 32764 B holding 12% of the bytes, and each
   still occupied a full class. Padding overhead scales with **file count**, not
   with content — so the worst case is a document or code repository, precisely
   the workload a NAS is most often pointed at.

`fixed` was listed at "~0%" overhead. That was true of chunking and false of
storage: every trailing partial chunk still rounds up to 64 KiB, which on a
small-file corpus is worse than `classes`.

**This strengthens the default rather than merely confirming it.** The choice was
originally made against a 20–35% premium; the real premium is 56–97%, against a
threat (an adversary holding a candidate file and wanting confirmation) that
remains low-probability unless the user is individually targeted.

> **Open question (M2), not an assumption.** A denser ladder — 1.25× or 1.5×
> steps rather than ×2 — would cut the premium substantially in exchange for a
> finer length fingerprint, and a floor below 32 KiB would help the small-file
> case specifically. Neither is decided here. What is decided is that the
> trade-off must be argued against measurements, since the last estimate made
> without them was off by 3×.

The `padding_profile` field is written into every manifest from M0 regardless, so
enabling it later is a configuration change and never a format break.

> **Implementation note carried back from the Lean model (§18).**
> `unpad(pad(x)) = x` is proved unconditionally — but in Lean, where `Nat`
> subtraction *truncates at zero*. The Rust expression `class - 4 - len` over
> `usize` **underflows** when `len > class - 4`: a panic in debug, a wrap-to-2⁶⁴
> allocation in release. The model erases precisely the failure mode most likely
> to occur, so the class arithmetic needs a checked subtraction and a boundary
> test. A proof constrains the design, not the code that drifts from it.

### 4.3 Manifest

An encrypted blob like any other:

```
{ name_enc, kind: file|dir, size, chunks: [ { addr, ck, pt_hash, len } ], meta }
```

`ck` must be stored — a reader lacks the plaintext and cannot derive it. The
manifest's own encryption protects both `ck` and `pt_hash`.

### 4.4 Names and listing

Path *segments* are encrypted individually (Cryptomator-style), so listings
resolve without a server-side prefix scan. **Listing is local**: the client
fetches and decrypts the manifest and answers `PROPFIND` / `list-objects` from it.
The peer is never asked to match a prefix and could not.

### 4.5 Upload dedup requires proof of possession

If the peer answers "already have `addr`" the client would skip the write — and a
lying peer thereby converts dedup into silent deletion, discovered only at a
future read when the plaintext is long gone.

**Therefore:** before honouring a skip, the client challenges with a random 32-byte
`nonce`; the peer must return `BLAKE3(nonce ‖ ciphertext)`. Only a peer actually
holding the ciphertext can answer. Failure ⇒ upload normally and flag the peer.

---

## 5. Slot consistency

Every mutable pointer is a slot. Revision 1 had one regime and it was wrong for
both faces; revision 2 declares a regime per slot at creation.

```
SlotRecord { slot_id, seq: u64, root: addr, root_nonce, writer_id,
             prev: hash-of-previous-record, regime, sig }
sig = ML-DSA-65.sign(sk_slot, "nas-tools/sig/slot/v1" ‖ canonical(…))
slot_id = BLAKE3(namespace_pk ‖ label)
```

### 5.1 Regime A — `single-writer` (git refs)

Exactly one device holds the write-cap for the slot at a time. Concurrent updates
are **not** merged; any observed divergence is a genuine alarm. Ownership handoff
is an explicit, signed operation. Simple, and correct for refs where a silent
merge would be wrong anyway.

### 5.2 Regime B — `cas-merge` (S3 buckets, doc heads)

Writers do read-modify-write with **compare-and-swap on `seq`**: a publish carries
the `prev_seq` it was computed against, and the peer rejects it if the head has
moved. On rejection the client re-reads, re-merges and retries. The merge function
is per-face (§7).

The critical property: **a rejected CAS is a normal retry, not a fork alarm.**
Revision 1 could not distinguish honest concurrency from malicious rollback, which
made the alarm worthless. Now it can.

An untrusted peer may of course refuse to enforce CAS honestly. That is what §5.3
is for.

### 5.3 Rollback and fork detection

Three mechanisms, all new or repaired in revision 2:

1. **Freshness anchor in the cap.** Every cap carries the `(seq, sig_hash)` current
   at issue time. A fresh client — new device, restored laptop — can never be
   served anything older. This closes revision 1's bootstrapping hole, where a
   client with no pin accepted any validly signed historical record.
2. **Slot history + hash chain.** Peers retain `slots/<slot_id>/<seq>.json` and each
   record's `prev` chains to its predecessor, so a client pinned at seq 5 that
   receives seq 9 can *walk 5→9 and verify*. Revision 1 stored only the head, which
   made its own chain check impossible to perform.
3. **Witness records, relayed by the peer.** Revision 2 said "clients gossip",
   which quietly assumed clients meet. They do not — the target user is a laptop
   moving between home, office and cafés (§5.6). So a client publishes a *signed*
   observation and the untrusted peer relays it:

   ```
   Witness { witness_pk, slot_id, seq, sig_hash, logical_time, sig }
   sig context "nas-tools/sig/witness/v1"
   ```

   The peer stores and serves witnesses. It can withhold or delay them; it
   **cannot forge** them. Two witnesses citing incompatible `(seq, sig_hash)` on one
   slot are a self-contained, publishable *proof* of a fork — not a heuristic.
   Devices that never meet directly therefore still detect forks, so long as the
   peer does not withhold consistently and forever; and persistent withholding is
   itself a signal, since an active device's witnesses should keep arriving.

   **Witness-only nodes.** `nas-peer --witness` runs a node that holds no blobs, no
   caps and no secrets, and only relays and publishes witnesses. A €3/month VPS is
   enough. This is the practical answer to a two-device tenant where one device is
   rarely online.

### 5.4 The honest bar

With anchors, history chains and witness relay we get **fork detection that
converges once witnesses propagate** — which needs the peer to relay them at least
sometimes, not clients to meet. We do **not** get fork *prevention*, and we do
**not** reach SUNDR's fork consistency: SUNDR requires clients to sign a version
structure covering all users' operations, which is not specified here. Revision 1
cited SUNDR as "the bar we can actually reach"; that overclaimed.

A peer that withholds every witness in both directions, forever, can keep two
devices forked. Adding a witness-only node makes that require *all* nodes to
collude. **State this in the user manual, not only here.**

### 5.5 Slot history compaction

Peers must retain history for chain walking (§5.3), but the peer is both the
entity we distrust and the one deciding what to prune. Four schemes were weighed:

| Scheme | How | Verdict |
|---|---|---|
| Retain-N | keep last N records | simple, bounded, degrades gracefully |
| Lease-driven | lease slot records like blobs | couples GC to slots; long-offline client's lease expires anyway |
| Acknowledged watermark | compact below `min(K)` over all clients | one dead client pins history forever |
| Skip-chain checkpoints | signed links every N records | O(log n) walks, costs one extra signature |

**Chosen: retain-N plus skip-chain checkpoints.** Default `N = 1024`, with a
checkpoint every 256 records carrying a signed link to the previous checkpoint. A
client 100 000 updates behind walks ~400 checkpoints rather than 100 000 records.
The writer already signs every slot version, so a checkpoint signature is marginal.

**Degradation is explicit:** a client further behind than retained history falls
back to verifying the cap anchor plus the head signature, and *raises a warning*
rather than silently accepting. Losing the chain must be visible.

### 5.6 Roaming and unstable connectivity

The design target is one laptop moving between home, office and cafés, plus a
peer that must be reachable from all of them.

- **Reachability.** A Tor onion service (already in `simple-network`) gives a peer
  a stable address with no NAT traversal, no port forwarding and no VPN, from any
  network. Latency is the price. A VPS with a stable address is the low-latency
  alternative; both are supported carriers.
- **Opportunistic, never scheduled.** Witness exchange and lease renewal piggyback
  on whatever connection happens to exist. Nothing requires a session to be up at a
  particular time.
- **Offline writes stage locally.** The gateway accepts writes with no peer
  reachable, queues them in `state/outbox/`, and replays them on reconnect —
  re-running the CAS merge (§5.2) against whatever the head has become. A conflict
  surfaces as a merge, not an error.
- **Lease expiry is 90 days** (§6.3) precisely so a fortnight of bad connectivity
  is uneventful.

---

## 6. Garbage collection by lease

A peer cannot mark-and-sweep an encrypted DAG. Leaking child pointers so it could
traverse was considered and rejected — it hands the adversary the DAG shape.

Revision 1's "one Merkle root over the full set, replaced wholesale per epoch" does
not survive contact: the tree compressed only the *signature*, while the full
address set still shipped every epoch — a holder of 10M chunks would push ~320 MB
per renewal.

### 6.1 Deltas with signed checkpoints

```
LeaseDelta      { holder_pk, epoch, seq, add: [addr], remove: [addr], prev, sig }
LeaseCheckpoint { holder_pk, epoch, root = merkle(sorted full set), count, prev, sig }
```

Deltas ship incrementally and chain by `prev`; a checkpoint every N deltas lets the
peer compact and lets a client resync from cold. One signature per delta or
checkpoint — never per address (§3.8).

### 6.2 Young-blob grace period

Any blob uploaded within `grace_period` (default 24 h) is **immune from sweep
regardless of leases**. This closes revision 1's race where a blob written
mid-epoch had no lease yet, and the case where a client crashes between upload and
lease publication.

### 6.3 Offline clients

The median case for a NAS is a laptop closed for weeks; revision 1 left this as an
open question, which was not good enough.

- Lease expiry defaults to **90 days**, not one epoch.
- The peer must not sweep a holder's set until `expiry + grace`.
- A per-repo `retention_floor` is never swept without an authenticated `forget`.
- **Warn before sweep:** a returning client within expiry receives the list of
  blobs that *would* have been swept, so silent loss is not the failure mode.

### 6.4 Quotas

Nothing otherwise stops a paired holder leasing addresses it never wrote, blocking
GC of other tenants' data on a shared peer. The peer enforces `max_leased_bytes`
per `holder_pk`, negotiated at pairing.

### 6.5 Accepted leak

Lease sets are cleartext inventories bound to a long-term identity (§1). Batching
deltas to epoch boundaries coarsens churn timing; it does not hide the inventory.

---

## 7. The three app faces

All are localhost adapters over the same substrate.

| App | Namespace semantics | Slot regime | Genuinely new work |
|---|---|---|---|
| **S3-style** | per-key LWW *inside* a bucket manifest | `cas-merge` | S3 shim, SigV4, merge function |
| **git-style** | immutable commit DAG + mutable refs | `cas-merge`, fast-forward only (§7.3) | remote helper, patch queues |
| **doc-style** | per-doc CRDT | `cas-merge` | CRDT engine, op-log compaction |

### 7.1 S3 merge semantics (revision 1 lost writes)

One slot per bucket made LWW *bucket*-granular: two devices PUT different keys and
the second slot update erased the first device's key. Real S3 never does that.

Per-key slots would fix it but cost ~3.3 KB of ML-DSA signature *per object* — see
§3.8. So the bucket keeps one slot, and the manifest carries per-key versioning:

```
key → { chunks, lamport: u64, writer_id, deleted: bool }
```

Merge on CAS retry is per-key LWW ordered by `(lamport, writer_id)`, with
`writer_id` from the signed roster (§3.5) breaking ties deterministically.
Concurrent PUTs to *different* keys both survive. Concurrent PUTs to the *same*
key resolve last-writer-wins, which is genuine S3 behaviour.

Tombstones (`deleted`) are retained for one lease epoch so a delete is not undone
by a stale writer.

### 7.3 The git face — a remote helper

Git's extension point is the remote helper: a binary named `git-remote-nas` is
invoked by `git push nas://photos` over a line protocol on stdin/stdout. Prior
art: `git-annex`, and `git-remote-gcrypt`, which is close to our case — an
encrypted remote git cannot read.

**Use the `fetch`/`push` capability, not `import`/`export`.** The fast-import
stream is easier but does not preserve commit SHAs. Git objects are already
content-addressed and immutable, which is exactly what our CAS wants, so moving
them ourselves is both faithful and cheap.

Three details decide whether this works:

1. **Store inflated loose objects, never packfiles.** The obvious shortcut — let
   git build a pack and CDC-chunk it — fails, though not for the reason revision 4
   gave. Packfiles deflate each object and delta *individually*, not as one
   stream, so nothing "cascades" through a shared compressor. The real CDC killers
   are **delta-base selection and nondeterministic object ordering**: repacking
   the same history can pick different bases and a different layout, so
   byte-identical content yields entirely different pack bytes and dedup collapses
   anyway. The conclusion stands; the mechanism does not. So we
   inflate and store objects individually. Most fall under the 16 KiB minimum and
   become one chunk each; large blobs chunk normally. Batch them into one manifest
   per push so there is no round trip per object.
2. **The OID map must never leave the encrypted manifest.** Git addresses by
   SHA-1 of the *plaintext*; we address by BLAKE3 of the *ciphertext*, so a
   `git_oid → addr` table exists. Exposed, it is a confirmation oracle for every
   public repository in existence — an attacker knows every OID in the kernel
   tree. It lives inside the encrypted manifest, reachable only through the ref
   slot.
3. **Refs use `cas-merge` with fast-forward as the merge rule.** *(Revised: rev 2
   specified `single-writer`.)* Git already has a well-defined concurrency rule
   and your muscle memory expects it. The peer enforces sequence-CAS; the
   **client** enforces the descendant check, since the peer cannot read the DAG.
   A rejected push surfaces as git's own non-fast-forward error — `git pull
   --rebase` and retry.

   > **Fast-forward is a client convention with post-hoc detection, not an
   > enforced property.** The peer checks only sequence-CAS, so any rostered — or
   > compromised — device can publish a non-descendant root as an ordinary slot
   > record, with no override flag and nothing distinguishing it in the audit
   > trail. Other clients detect it afterwards by walking history. A writer can
   > also publish a tip whose ancestry objects it withholds, leaving honest
   > clients unable to verify descent; they must refuse the tip rather than accept
   > it unverified. This is strictly better than
   passing slot ownership between devices; `single-writer` remains available as a
   stricter opt-in.

### 7.4 Worktrees

`git worktree` gives several working directories over one object store, and
coding agents lean on it heavily — one worktree per agent, per task, per branch.
It mostly works for free, with three requirements on the helper:

1. **Never assume `.git` is a directory.** In a linked worktree it is a *file*
   pointing elsewhere. Resolve paths with `git rev-parse --git-dir` and
   `--git-common-dir`, never by string-appending `/.git`.
2. **Only shared refs get slots.** `refs/heads/*` and `refs/tags/*` are shared and
   published; `HEAD` and `refs/worktree/*` are per-worktree and stay local.
3. **Worktrees are local, the remote is `nas://`.** The v0 mount is read-only, so
   a worktree cannot live *on* the mount. It lives on local disk and pushes to us.

The payoff is worth stating: because each ref is an independent slot under
`cas-merge` (§7.3), **N agents in N worktrees pushing N branches do not contend at
all.** They touch disjoint slots. Contention only appears when two agents push the
same branch, and then it appears as git's own non-fast-forward error, which is
the behaviour everyone already knows how to resolve.

### 7.5 Patches as first-class objects

Agents produce patches, and a patch is a better review unit than a push: small,
readable, independently signable, and meaningful without the surrounding history.

- `nas patch export <range>` writes a patch series as a blob in the namespace —
  addressed, encrypted, and signed by its author.
- `nas patch import <addr>` applies it, verifying the author signature against
  the roster first.
- A **patch queue** is a slot holding an ordered list of patch blobs. It is
  naturally append-only, so it is a good fit for `append-only` namespaces (§16)
  and gives a lightweight review flow with no forge involved.
- Native interop: `git format-patch` / `git am` on the way in and out, so nothing
  here is a private format.

The reuse worth noticing: **applying a patch to a protected branch can require
the same signed quorum as deleting data (§16).** One approval mechanism, two uses
— review gating and destruction gating are the same shape of problem.

### 7.6 Mirroring to GitHub / GitLab, with rules

The requirement is a private canonical repo on the NAS and a *filtered* public
mirror — for instance, a `fixes/` directory that exists in your work and must
never appear publicly.

> **The trap, stated first: a filtered mirror is not a mirror.** You cannot
> remove a path from git history without rewriting it, and rewriting changes every
> downstream commit SHA. What you get is a **derived repository** with its own
> DAG. Anyone who calls this "mirroring" will eventually be surprised by a forced
> push.

So it is modelled as a derivation, not a copy:

1. **Two DAGs plus a persisted mapping.** `private_sha → public_sha`, produced by
   `git filter-repo` and stored in the private namespace. Without persisting it,
   every re-publish invents new SHAs and force-pushes over the public history.
   The mapping itself is mildly sensitive — it reveals correspondence and the
   count of filtered commits — so it never leaves the encrypted namespace.
2. **Rules** are path include/exclude globs, plus: drop commits left empty by
   filtering, optionally rewrite author/committer identity, optionally filter
   commit *messages* (private messages mention private things), and select which
   refs and tags publish at all.
3. **Fail closed.** If any rule fails to evaluate, nothing publishes. A leak here
   is irreversible in a way nothing else in this design is — once it is on a
   public forge it is cloned, cached, and indexed within minutes, and deleting the
   repository does not recall it.
4. **Mandatory gates before every publish:** a dry run showing exactly which paths
   and commits would become public, a secret scan, and a **signed approval** —
   the same quorum machinery as §16. Publishing outward is irreversible, so it
   gets the same ceremony as destruction.
5. **One-way by default.** Accepting public contributions back means mapping
   public commits into the private DAG, which is a cherry-pick through the
   mapping. Possible, but explicit — never automatic.

What this adds over `git filter-repo` in a cron job: the rules, the mapping, and
the audit trail live in the encrypted namespace rather than on someone's laptop,
the publish is signed and reproducible, and the dry run is a required step rather
than a habit.

### 7.2 Doc-face liveness: poll first, pubsub never for correctness

Poll-on-slot and pubsub are not alternatives at the same layer.

- **Poll-on-slot** is the *correctness* path: fetch the head, verify signature and
  chain, merge. It works today over plain request/reply, needs nothing new, and
  survives a connection dropping mid-café. Latency equals the poll interval.
- **Pubsub** is a *latency optimisation only*. Against an untrusted peer a
  notification cannot be believed and its absence cannot be believed either — you
  always re-verify by fetching. So pubsub can never be load-bearing.

**Therefore the doc face is not blocked on `simple-network` pubsub.** Build
adaptive polling first (sub-second while a document is actively edited, minutes
when idle); it captures most of the benefit and degrades cleanly on a flaky link,
which a held-open push channel does not. Pubsub is a post-M6 optimisation whose
upstream cost is set out in §14.

---

## 8. Read path and mount

One gateway carries the S3 API and WebDAV. The mount is **read-only in v0**.

The shim is a small fraction of the work; the substance is shared:

```
path → slot → root manifest → segment-decrypt names → chunk list
     → byte range → fetch → verify BLAKE3(ct) → decrypt → verify pt_hash → bytes
```

| Option | Build | Install burden | macOS client quality |
|---|---|---|---|
| **WebDAV (v0)** | small — `OPTIONS`/`PROPFIND`/`HEAD`/`GET` | none, built in | mediocre: slow, cache-happy, `._` litter |
| NFSv3 self-served | moderate — XDR/RPC | none, built in | good; same path FUSE-T uses internally |
| FUSE-T | moderate | user must install FUSE-T | good, but NFS underneath regardless |

WebDAV first: it rides the HTTP server the S3 face already needs, and HTTP range
GETs map onto chunk range reads directly. Migrate to self-served NFSv3 when macOS
WebDAV performance becomes the limit — the read path is unchanged, only the shim
moves.

*(Revision 1 also claimed WebDAV grants browser and mobile access. It does not:
§2.1 binds the gateway to loopback and a unix socket. Mobile requires a mobile
`nasd`, which is a non-goal for v0.)*

### 8.3 Chunk cache

`state/cache/` holds recently read chunks — without it, every read is a network
round trip. Revision 1 stored them in plaintext under "full-disk-encryption
assumptions", which quietly undid the vault's rigour.

Entries are encrypted under `cache_k`: 32 B from the CSPRNG **per boot**, held in
`rust-secure-memory` and zeroized on shutdown, with a random nonce per entry
(§3.1). A stolen disk yields nothing; the cost is one AEAD pass on an already
memory-bound path. Bounded, LRU.

---

## 9. Relationship to `simple-backups`

Revision 1 claimed `simple-backups` provided "~70% of the substrate". Reading the
code, that was an overclaim: `crates/backups-store` is a small plaintext SHA-256
**file-level** CAS, and the table below replaces every invariant it has — hash,
chunking, encryption, read granularity, ref mechanism, GC. **30–40% is honest**,
and what genuinely carries over is the transfer/pairing/vault *shape*, most of
which lives in `simple-network` and `simple-secrets` rather than `simple-backups`.

Six gaps:

| Gap | `simple-backups` today | NAS-tools requires |
|---|---|---|
| Encryption at rest | none — plaintext objects; PQC is transport-only | convergent E2EE — **the blocker for untrusted peers** |
| Chunking | file-level CAS (explicit v0 non-goal) | FastCDC |
| Read granularity | whole-file restore | byte-range reads |
| Hash | SHA-256 | BLAKE3-256 (§3.6) |
| Ref safety | `refs/latest` is a bare file | signed slot history, `seq`, chain, anchors |
| GC | local mark-and-sweep over manifests | lease deltas; peer cannot traverse |

**Decision:** a new `nas-store` crate rather than a fork, since encryption and CDC
change the store's core invariants. Reused directly: `simple-network` (`pqc`
transport, pairing), `simple-secrets` + `rust-secure-memory` (vault, zeroizing key
handling). CDC and at-rest encryption should be proposed upstream to
`simple-backups` afterwards rather than maintained twice.

---

## 10. Workspace layout

```
crates/
  nas-core/       # types, caps, manifest format, canonical encoding
  nas-crypto/     # key schedule (§3.1), convergent encryption, signing contexts
  nas-store/      # CDC, blob store, manifests, encrypted cache
  nas-slots/      # slot records, regimes, history chain, anchors, pins, gossip
  nas-lease/      # lease deltas, checkpoints, quotas
  nas-transfer/   # client peer protocol over simple-network pqc
  nas-peer/       # ** THE UNTRUSTED PEER SERVER ** — blobs, slot ordering + history,
                  #    lease enforcement, sweep, quotas, PoP challenge responder
  nas-gateway/    # localhost S3 + WebDAV, unix socket / loopback auth
  nasd/           # client daemon (trust boundary)
  nas-cli/        # CLI
```

`nas-peer` was absent from revision 1 entirely — an omission of a double-digit
percentage of the project. Note it is the one component that must be *hostile-safe*
by construction: it is the software our own threat model assumes is malicious, so
it must hold no secrets and require none.

## 11. Milestones

Revision 1's M1 contained the peer server, the whole lease subsystem and fork
semantics; it was plausibly half the project wearing one milestone's name. Split:

**M0 — substrate, local only.** CDC + convergent encryption + key schedule + blob
store + manifests. Round-trip a directory byte-identically; dedup provable across
two similar trees.

**M1 — the peer.** `nas-peer`: blob store, slot history with ordering and CAS,
lease deltas and sweep, quotas, PoP responder. Push/pull over `simple-network`
`pqc`. Honest-peer path only.

**M2 — adversarial hardening.** Freshness anchors, pins, chain walking, client
gossip. A named test per attack: tamper, rollback, withhold, dedup-lie,
CAS-non-enforcement, lease griefing.

**M3 — S3 face.** Gateway with SigV4 + unix socket, cas-merge with per-key LWW,
local listing. `rclone` and `aws s3` work against `localhost`.

**M4 — RO mount.** WebDAV on the same gateway; encrypted chunk cache; ranged reads.

**M5 — git face.** Remote helper; refs as `cas-merge` slots with a fast-forward
merge rule; worktrees; patch objects and queues.

**M6 — doc face.** CRDT engine, op-log blobs, compaction.

## 12. Success criteria (v0 = M0–M4)

1. Byte-identical round-trip through chunk → encrypt → peer → fetch → decrypt.
2. For `e2ee` and `passphrase` namespaces, a peer's on-disk state contains no
   plaintext — automated test greps blobs for known markers. Roster, lease and
   retention records are *expected* to be plaintext (§1) and are excluded by name,
   not by accident. For `transit-only` namespaces the same test asserts the
   **opposite**, and additionally that no `e2ee` namespace's data has ever landed
   in one.
3. Two trees sharing 90% content transfer roughly 10% of the bytes.
4. Rollback, tamper, withholding, dedup-lie and CAS-non-enforcement each have a
   test that *detects* them, and a fresh client with only a cap resists all five.
5. Confirmation attack fails without `CS` and succeeds with it — proving `CS` is
   load-bearing, not decorative.
6. Two devices PUT different keys to one bucket concurrently; **both survive**.
7. A client offline past one epoch, returning within expiry, loses nothing and is
   warned about would-be sweeps.
8. `aws s3 ls` and `rclone` work against the gateway; a non-authenticated local
   process is refused.
9. Finder mounts the WebDAV share; a ranged read of a 1 GB file fetches O(range).
10. `./ci.sh` green: fmt, clippy `-D warnings`, tests — macOS and linux arm64/amd64.

## 13. Open questions

Revision 2's five open questions are now closed — padding (§4.2.1), revocation
(§3.9), compaction (§5.5), roaming and witnesses (§5.3, §5.6), doc liveness (§7.2).
What genuinely remains:

- **Padding overhead is a guess.** 20–35% is an estimate; the real figure depends
  on the CDC distribution against the ladder. Measure at M0 and retune the ladder
  before it is baked into stored data.
- **How many `CS` generations may coexist** before a rewrite is compulsory, and
  what forces the rewrite to finish rather than stall at 90%.
- **Witness quorum.** How many independent witnesses before a fork claim is acted
  on rather than merely logged? One is proof of divergence but not of *who* is
  honest.
- **Outbox conflict UX.** When a staged offline write merges into a moved head, what
  does the user see? Silent merge is wrong for documents and right for backups.
- **Erasure coding**, still deferred: replication cost against an untrusted peer is
  paid in full copies, which gets expensive past two peers.

## 14. Inherited open items from `simple-network`

The `pqc` channel exists and is tested (hybrid ML-KEM-768 + X25519, ML-DSA-65 auth,
XChaCha20-Poly1305 records, replay/reflection tests, Tor and I2P carriers). But its
own `TODO.md` lists items this design silently depends on:

- **Handshake transcript is not bound into the KDF.** Session keys derive from the
  KEM shared secret and fixed labels; signatures cover `kem_pub`/`ciphertext` with
  no role, peer identity or context tag. Pinned keys mitigate; the gap is real.
- **`check_pin` compares pinned verifying keys with `!=`**, not in constant time.
- **PubSub ignores topics**, and the Erlang-style patterns still use raw TCP rather
  than `SecureConnection`.
- mTLS / cluster cert pairing is unimplemented.

**Status: the first three are DONE upstream** as `simple-network` protocol v1 —
transcript binding into the KDF, signature context tags, and a constant-time
`check_pin`. 15 tests green. Revision 4 still described them as open; that text is
withdrawn.

**Carry the deployment constraint:** protocol v1 is **wire-breaking**. A v0 peer
is refused with an explicit version error rather than silently downgraded, so both
ends of any paired deployment upgrade together — `simple-backups` push/pull rides
this channel. Verify interoperability at M1 rather than assuming it.

If the doc face later wants pubsub (§7.2), the upstream cost is: topic filtering
(small), routing pubsub over `SecureConnection` instead of raw TCP (moderate, and
needed for anything secure regardless), and durable subscriptions with reconnect
and missed-message semantics (the real work). Only the third is genuinely hard, and
none of it is on the critical path.

---

## 15. Permissions and ACLs

Four distinct things get called "permissions". Conflating them is how people end
up believing they have access control they do not have.

### 15.1 POSIX metadata of stored files

Mode bits, uid/gid, mtime, xattrs, symlinks — all live in the encrypted manifest,
so in `e2ee` and `passphrase` modes the peer never sees them. Two traps:

- **Store uid/gid as both number and name, and prefer the name on restore.**
  Numeric ids are machine-local; restoring elsewhere otherwise hands your files
  to whoever happens to hold uid 501.
- **Filter `com.apple.quarantine`** on restore, or every recovered file is blocked
  by Gatekeeper.

### 15.2 What the mount can actually express

**WebDAV has no concept of POSIX mode.** Files appear as whatever the client
synthesises — typically `0644`, owned by whoever mounted the share. The stored
mode is preserved faithfully for *restore*, but it is **not visible through a
WebDAV mount**. NFSv3 carries mode/uid/gid properly, which is a second argument
for that migration beyond raw throughput. Since v0 is read-only, write-permission
semantics largely do not arise yet.

A `uid_mode: preserve | squash` knob is provided, because on a NAS you usually
want everything to appear owned by the mounting user.

### 15.3 Who may read — and why the mode decides

| | `e2ee` / `passphrase` | `transit-only` |
|---|---|---|
| Mechanism | possession of a capability | ACL evaluated by the peer |
| Enforced by | mathematics | the peer's cooperation |
| Revocation | re-key the namespace (§3.9c) | delete the ACL entry — instant |
| If the peer is hostile | still safe | **no read control whatsoever** |

That is the real trade and it should be presented to users as such: **cryptographic
access control you cannot easily revoke, or revocable ACLs you must trust the peer
to honour.** There is no third option, and picking one is what choosing a mode
means.

**Per-directory key derivation is mandatory from M0**, even though v0 only ever
issues namespace-root capabilities. Each directory carries a `dir_secret` derived
from its parent's (§3.1), so a capability can later be scoped to a subtree.
Retrofitting after data exists means re-keying everything.

Revision 4 asserted this while §3.1 still made manifest keys *convergent* — two
mutually exclusive key schedules for one object. Resolved as:

- **Chunks stay convergent.** `ck` is content-derived, dedup is preserved, and
  this is where essentially all the bytes are.
- **Directory manifests use `dk`, derived from `dir_secret`, with a random
  nonce.** Manifest dedup is given up. It was never worth much — manifests are a
  rounding error beside chunk data — and in exchange a subtree capability becomes
  possible and a directory *move* re-keys one manifest rather than its entire
  contents.

So "it costs nothing" was wrong; it costs manifest dedup, which is the right
trade rather than a free one.

### 15.4 Who may write — enforceable in every mode

Authenticity does not require readability, so the peer can enforce write policy
even when it cannot read. The signed roster (§3.5) maps `writer_id` to verifying
key; slot updates are checked against it.

Rights vocabulary:

| Right | Means |
|---|---|
| `read` | decrypt / fetch |
| `write` | create, overwrite, delete within the namespace |
| `append` | create **new** keys only — no overwrite, no delete (§16) |
| `delete-request` | may open a deletion request, may not execute one |
| `delete-approve` | may sign approvals toward a quorum |
| `publish` | may push to an external mirror (§7.6) |
| `admin` | roster and policy changes |

`append` plus withholding `delete-*` from every day-to-day device is the whole of
the ransomware defence in §16.

---

## 16. Append-only, Object Lock, and the deletion approval loop

Mirrors S3's vocabulary deliberately, since `aws` and `rclone` users know it:
**Governance** (deletable with special permission), **Compliance** (undeletable
until retention expires, by anyone including the owner), and **legal hold** (an
indefinite freeze).

> **What this protects against, stated before the design.** A malicious peer
> deleting your data is the withholding attack we can only detect, never prevent
> (§5.4). What WORM genuinely stops is **ransomware on your own laptop**, a
> mistaken `rclone sync --delete`, and a bad decision at 2 a.m. That is the
> majority of real data loss, so it is worth building — but nobody should believe
> it constrains the storage provider.

### 16.1 Key separation is the mechanism

Everyday writes use the write-cap on your laptop. Deletion, retention shortening,
and policy loosening require a signature from a **separate ML-DSA key that is
deliberately not on that laptop** — a hardware token, a second device, or split
m-of-n. `simple-secrets` already implements Shamir sharing (`shares/`), so an
m-of-n deletion authority is an integration rather than new cryptography.

Ransomware on the laptop cannot delete, because the authority is not there to
steal.

### 16.2 The loop

All of it append-only, so the audit trail cannot be edited either:

1. `DeleteRequest { scope, reason, requested_by, nonce }`, signed.
2. **Cooling-off period**, default 7 days. This is the part that actually defeats
   ransomware, which needs to act inside minutes.
3. `DeleteApproval { request_hash, approver_id }` × m, from distinct holders.
   Binding the request hash is what stops an approval being replayed against a
   different request.
4. On quorum **and** elapsed cooling-off, `DeleteExecution` publishes and only
   then are leases dropped.

**Scope is one object, a prefix, or a whole namespace — and quorum scales with
blast radius.** One approver to remove a file; three to remove a tree.

**But per-request quorum alone is defeated by decomposition.** With `object: 1`,
one stolen approval token deletes an entire namespace as N single-object
requests, never once triggering the namespace quorum of 3. So quorum is also
aggregated over a rolling window:

```yaml
delete_quorum:
  object: 1
  prefix: 2
  namespace: 3
  rolling: { window: 30d, objects: 10, escalate_to: 3 }
```

Past the rolling threshold, every further request — whatever its scope — demands
the namespace quorum. Volume is what actually correlates with harm, not the label
on any single request.

##### Whose clock gates the cooling-off

There is **no trusted time source anywhere in this design.** The peer's clock is
adversarial by assumption, and a request's timestamp is signed by a requester who
may be compromised. So:

> **Cooling-off is enforced by the approver devices, against their own local
> clocks.** An approver must refuse to sign before its own cooling-off has
> elapsed. Nothing in the protocol can enforce it.

That reorders §16's claim. Revision 4 said cooling-off "is the part that actually
defeats ransomware" — backwards. **Key separation defeats ransomware.**
Cooling-off is a convention enforced by approver software, valuable because it
gives a human time to notice, not because the protocol compels it.

### 16.3 Retention must override leases

This is the subtle failure and it must not be missed. GC is lease-driven (§6): if
a client stops renewing, the peer sweeps. **So a compromised client can destroy a
WORM namespace by simply going quiet** — no deletion request required, no policy
violated.

Revision 4's retention record was one signature over a Merkle root of the
protected set. That does not work: a root hash gives the peer **no way to decide
membership** when it is about to sweep a given address. It also never said who
signs it, or how it grows to cover newly appended data.

```
RetentionSet { namespace_id, epoch, addrs: [addr], expiry, mode,
               prev, signer, sig }
sig context "nas-tools/sig/retention/v1"
```

The set ships **addresses**, like a lease checkpoint (§6.1), so membership is
decidable. The signing rule is what makes it survive a compromised laptop:

| Operation | Required key | Peer-verified condition |
|---|---|---|
| **Extend** — add addresses | the everyday write key | new set ⊇ previous set |
| **Shrink or shorten expiry** | the offline delete authority | quorum per §16.2 |

**Ransomware holding the everyday key can only ever add protection.** A publish
that removes addresses or pulls in the expiry is rejected by the peer on a check
it can actually perform — plaintext set comparison — with no need to read
anything. That is what makes append-only real despite the peer being unable to
understand the manifest (§2.2).

Pair any WORM namespace with at least two peers so that one peer ignoring
retention is detectable rather than fatal.

##### Auditing an archive you do not hold

§4.5's proof of possession requires the challenger to have the ciphertext, in
order to recompute `BLAKE3(nonce ‖ ciphertext)`. A client auditing a seven-year
archive does **not** hold it — that was the entire point of the archive — so as
written the periodic challenge was either a full re-download or impossible.

Instead, at write time the client precomputes and stores a small set of
challenge/response pairs `(nonce_i, BLAKE3(nonce_i ‖ ciphertext))` inside the
encrypted manifest. Auditing spends one pair per challenge and needs no bytes
from the peer beyond its answer. Pairs are replenished on any read that
materialises the data.

### 16.4 Versioning, the gentler option

A separate axis from Object Lock: every PUT creates a new version, DELETE writes a
delete-marker and destroys nothing. Manifests are immutable and slots keep history
(§5.5), so this is cheap — and for many "never lose anything" requirements it is
what people actually want, without the ceremony of retention policy.

> **But versioning alone is not a ransomware defence.** Old versions survive only
> while leased, and leases are published by the very client that may be
> compromised: it can emit `remove:` deltas (§6.1) and let the old manifests sweep
> after the grace period. Versioning without a retention set (§16.3) does not
> survive the attack §16 exists to stop. Revision 4 called it "nearly free
> protection"; it is nearly free *convenience*.

---

## 17. DVC integration

**How DVC works.** Large files stay out of git. `dvc add data/train.csv` hashes
the file (MD5 by default), moves it into the cache — `.dvc/cache/files/md5/<ab>/<rest>` in DVC 3.x; the
flatter `.dvc/cache/<ab>/<rest>` is the 2.x layout —
links it back into the workspace, gitignores the real path, and writes a small
`train.csv.dvc` pointer containing the hash. You commit the pointer: git versions
the pointer, DVC versions the bytes. `dvc push` uploads cache contents to a remote
(S3, WebDAV, SSH, a directory); `dvc pull` fetches what the checked-out pointers
reference. A tracked directory becomes a `.dir` object — a content-addressed JSON
listing of `{relpath, md5}`. Above that, `dvc.yaml` and `dvc.lock` form a
make-for-ML that re-runs only stages whose input hashes changed.

**Its weakness is our strength.** DVC's cache is **whole-file** content-addressed.
Change one row of a 10 GB CSV and it stores another 10 GB. No chunking, no delta.
Our CDC layer fixes that without DVC knowing anything happened.

| Level | Cost | Gain |
|---|---|---|
| Point DVC at our gateway as an S3 or WebDAV remote | **nothing** — works at M3/M4 | encrypted datasets on untrusted storage, plus chunk-level dedup DVC cannot do |
| A native `fsspec` remote speaking to `nasd` over the unix socket | moderate | drops the HTTP hop; exposes our hashes |
| Make `nas-store` *be* the DVC cache, materialising checkouts by reflink | invasive | one store; no duplicate copy between cache and workspace |

Level 1 is the compelling one: zero work, and it removes DVC's single biggest
limitation *on the wire and on the peer* as a side effect.

> **Precisely what improves.** "One changed row costs kilobytes, not 10 GB" is
> true of **transfer and peer storage**. DVC's own local cache still writes a
> second full 10 GB copy on your disk, and chunking underneath does not change
> that — only Level 3, where `nas-store` becomes the cache, addresses it. Do not
> let anyone read Level 1 as fixing local disk usage.

**Caution:** DVC's MD5 is not collision-resistant. Treat it as a *name*, never as
an integrity guarantee — `addr = BLAKE3(ciphertext)` remains the real check.

**Where `simple-backups` fits.** These answer different questions, not competing
ones: simple-backups answers *"this tree as of last Tuesday"*, DVC answers *"the
data belonging to commit abc123"*, the git face answers *"this ref's history"*.
Three naming layers over one substrate. If `simple-backups` adopts `nas-store` (the
upstream proposal in `TODO.md`), a nightly snapshot, a DVC dataset and a git repo
share one deduplicated encrypted store — and a model checkpoint appearing in both
a backup and a DVC directory is stored **once**.

---

## 18. Formal methods

Full plan and status in `formal/README.md`. Summary:

| Artefact | Tool | State |
|---|---|---|
| `formal/lean/NasVerify/Transcript.lean` | Lean 4.28 | **VERIFIED** — 3 theorems, 0 `sorry` |
| `formal/tlaplus/SlotConsistency.tla` | TLA+ / TLC | **written, not yet checked** |

The split is by question type. **TLA+** for adversarial interleaving — slot
consistency under a peer that replays, forks and withholds; the lease-GC/write
race; the deletion quorum. **Lean 4** for properties that are theorems: the
transcript encoding is injective (so a signature commits to one reading of its
field boundaries), and padding is reversible for any class size (so a padding bug
is a privacy regression, never data loss). **proptest** for round-trips.
**cargo-fuzz** for every parser consuming peer-supplied bytes — the highest value
per hour in the whole list, because it is the exact surface an adversary reaches.

Explicitly **not** formalised: the cryptographic primitives (vetted
implementations, proving them here is theatre) and the system end-to-end (nobody
finishes it, and a half-finished proof implies more than it delivers).

**CI must reject `sorry`.** `simple-network/proofs/lean4/` currently contains
`theorem eventual_consistency : True := by sorry` — vacuous statement, admitted
proof. It reads as verification and carries none. Three real theorems beat thirty
admitted ones.

---

## 19. Use-case cookbook

Mapping intentions to configuration. Each case names the mode, the policy, and
the access model.

### 19.1 Family photos on the NAS in your house

*"My family should browse them. I must not lose them because I lost a laptop.
They are not secret."*

```yaml
namespace: photos
mode: transit-only          # plaintext at rest; the NAS is yours
padding: none               # pointless when the peer can read anyway
names: plaintext            # what makes server-side browsing possible
peer_features: [thumbnails, index, gallery]   # PERMITTED by the mode; NOT in v0
access:                     # REAL ACLs here — the peer can enforce them
  - { subject: family,  rights: [read] }
  - { subject: renaud,  rights: [read, write, admin] }
retention: none
peers: [home-nas]           # NOT a rented VPS
```

Trade accepted: the NAS can read every photo, and read control depends on the NAS
honouring it. In exchange: nothing is lost if every key you own burns, the family
gets a web gallery, and thumbnails work.

### 19.2 Important documents, "locked by a simple password"

*"Passport scans and contracts. Encrypted, but recoverable from memory."*

```yaml
namespace: documents
mode: passphrase            # Argon2id KEK wraps a random DEK (§2.2.2)
argon2: { m: 512MiB, t: 4, p: 1 }
padding: classes
names: encrypted
access:
  - { subject: renaud, rights: [read, write] }
peers: [home-nas]           # NOT a rented VPS — see the warning below
```

**Use five or more diceware words.** The peer holds the ciphertext and can brute
force offline at its leisure; Argon2id raises the cost per guess but will not save
a weak passphrase. Changing the passphrase re-wraps 32 bytes — it does not
re-encrypt the data.

### 19.3 Work source code and secrets

```yaml
namespace: work
mode: e2ee
padding: classes
names: encrypted
peer_features: []           # impossible in this mode anyway
peers: [home-nas, vps-fra]  # a rented VPS is fine here
```

No recovery path by design. Lose the vault, lose the data.

### 19.4 Legal records that must never be deleted

```yaml
namespace: records
mode: e2ee
object_lock:
  mode: compliance          # not even the owner deletes before expiry
  retention: 7y
  legal_hold: false
access:
  - { subject: laptop,   rights: [append] }          # no delete rights at all
  - { subject: token-a,  rights: [delete-approve] }  # offline hardware token
  - { subject: token-b,  rights: [delete-approve] }
  - { subject: token-c,  rights: [delete-approve] }
delete_quorum:
  object: 1
  prefix: 2
  namespace: 3
  rolling: { window: 30d, objects: 10, escalate_to: 3 }  # blocks decomposition (§16.2)
cooling_off: 7d             # enforced by APPROVER devices; no trusted clock exists
peers: [home-nas, vps-fra]  # ≥2, so one peer ignoring retention is detectable
```

The laptop holds `append` and nothing else, so ransomware on it cannot delete.
Retention overrides leases (§16.3), so it cannot destroy data by going quiet
either.

### 19.5 ML datasets with DVC

```yaml
namespace: datasets
mode: e2ee
chunking: large-object      # avg 1 MiB; write-once bulk data
```
```sh
dvc remote add -d nas s3://datasets
dvc remote modify nas endpointurl http://127.0.0.1:PORT
```
DVC keeps versioning pointers in git; we chunk, dedup and encrypt underneath.
Changing one row of a 10 GB CSV now costs kilobytes rather than 10 GB.

### 19.6 A repo mirrored publicly, minus `fixes/`

```yaml
namespace: myproject
mode: e2ee
mirror:
  target: github.com/me/myproject
  direction: one-way
  rules:
    exclude_paths: ["fixes/**", "internal/**"]
    drop_empty_commits: true
    filter_messages: true
  gates:
    dry_run: required
    secret_scan: required
    approval: { rights: publish, quorum: 1 }
```
Remember §7.6: this produces a **derived** repository with its own commit SHAs,
and the `private_sha → public_sha` mapping lives in the encrypted namespace so
re-publishing is stable instead of force-pushing.

### 19.7 A laptop that moves between home, office and cafés

```yaml
peers:
  - { name: home-nas, carrier: tor }   # onion service: stable address, no NAT traversal, no VPN
  - { name: witness,  carrier: tcp, mode: witness }  # €3 VPS; no blobs, no caps
client:
  witness_exchange: opportunistic
  lease_expiry: 90d
  outbox: enabled                      # accept writes offline, replay on reconnect
```
The witness-only node is what makes fork detection converge when your second
device is rarely online (§5.3).

### 19.8 Several coding agents at once

```yaml
namespace: work
refs: { regime: cas-merge, merge: fast-forward-only }
```
One git worktree per agent, each pushing its own branch. Distinct branches are
distinct slots, so **there is no contention at all** (§7.4). Two agents on one
branch collide as a normal non-fast-forward error. Patch queues (§7.5) give review
gating without a forge.

---

## 20. Why each feature exists — requirement traceability

Read this before agreeing to build any of it. Each row traces an intuition to the
property it forces and the mechanism that provides it. If a row's *cost* is worse
than its *driver* for your situation, delete the feature.

| You said | Which actually forces | Mechanism | What it costs you |
|---|---|---|---|
| "servers only handle encrypted data" | the peer cannot read, so it cannot index, search, thumbnail, share, **or garbage-collect** | localhost daemon (§2), local listing (§4.4), lease GC (§6) | every app becomes a local adapter; no presigned URLs |
| a NAS should not store the same file twice | dedup needs identical content to be *recognisable* — **not** necessarily identically encrypted | convergent encryption (§3.2) is **one** answer; a client-side encrypted index `BLAKE3(plaintext) → addr` under random keys is another | convergent: a confirmation oracle plus generation-rotation machinery. indexed: an index to sync and recover. **Revision 4 said "forces" and was wrong** — see §20.3 |
| "post-quantum" | Shor breaks Ed25519 and X25519 | ML-DSA-65 + hybrid ML-KEM-768 (§3.7) | signatures ~50× larger → **Merkle roots everywhere** (§3.8) |
| "family photos, don't lose them" | recoverability outranks confidentiality | `passphrase` (§2.2.2) suffices for recoverability *alone* | offline brute force against the wrap |
| …plus "the family should browse them, with thumbnails" | server-side **reading** | `transit-only` (§2.2.3) | the peer reads everything; read control becomes policy, not maths |
| "locked by a simple password" | the key must live in a human head | Argon2id KEK wrapping a random DEK (§2.2.2) | offline brute force is available to the peer; needs a real passphrase |
| "append only, never delete" | a compromised client must not be able to destroy | key separation + quorum + cooling-off (§16) | approval keys must live off the laptop, or the defence is theatre |
| "read-only mount, rootless" | no kext, no root password | WebDAV now, NFSv3 later (§8) | WebDAV cannot express POSIX modes (§15.2) |
| "laptop at home, office, cafés" | two devices may never be online together | witness records relayed by the peer (§5.3) | fork detection converges only when witnesses propagate |
| "git-like" | mutable refs on a store that cannot read them | ref slots, fast-forward merge (§7.3) | force-push becomes an audited override |
| "worktrees, coding agents" | parallel pushes to different branches | one slot per ref (§7.4) | **nothing** — it falls out of the design for free |
| "patch import/export" | agents produce reviewable units | patch blobs and queues (§7.5) | reuses the §16 quorum; no new machinery |
| "mirror, minus `fixes/`" | history cannot be path-filtered without rewriting | derived repo + persisted SHA map (§7.6) | it is **not a mirror**; without the map you force-push forever |
| DVC | large files versioned alongside code | S3 gateway as a DVC remote (§17) | none — and it repairs DVC's whole-file cache for free |

### 20.3 The largest unforced choice in the design

Convergent encryption is presented throughout §3 as though deduplication demanded
it. It does not. A client-side encrypted index mapping `BLAKE3(plaintext) → addr`,
synced through the namespace like any other metadata, gives **within-tenant dedup
under ordinary random keys** — no confirmation oracle, no convergence secret, no
per-tenant salt, and no generation-rotation story for a lost device.

The genuine trade is **statelessness versus an oracle.** Convergent encryption
needs no shared index and works from cold with only a key, at the cost of the
confirmation attack and the §3.9(c) machinery required to rotate around it. The
indexed alternative removes the oracle and adds an index that must be synced,
merged and recovered.

A large fraction of §3's complexity descends from this single choice. It deserves
a deliberate decision before M0 locks a format, rather than being inherited
because revision 1 assumed it.

### 20.1 The consequences nobody signs up for on purpose

Five things in this design exist only because something else you asked for
demanded them. They are the ones worth re-reading, because they are where surprise
lives:

1. **Encryption on an untrusted peer forces lease-based GC.** The peer cannot
   traverse an encrypted DAG, so it cannot know what is garbage. Somebody has to
   keep saying "keep these", forever. This is the single largest piece of
   machinery driven by a requirement that sounds like it is only about privacy.
2. **Post-quantum signatures force Merkle trees into places that would not
   otherwise need them.** At 3.3 KB a signature, you cannot sign per object, per
   chunk, or per lease. Every "sign the set" design in this document descends from
   that one number.
3. **WORM forces retention to override leases.** Otherwise the cheapest attack on
   an append-only namespace is not deletion at all — it is silence (§16.3).
4. **A roaming laptop forces witness relay.** Client-to-client gossip assumes
   clients meet. Yours will not.
5. **Filtered mirroring forces you to accept a second, different repository.**
   There is no version of this where the public SHAs match the private ones.

### 20.2 What you may not need — candidates for deletion

Being able to cut scope matters more than being able to add it. Honest
assessments:

- **Padding (§4.2.1) costs 20–35 % of your storage.** It defends against an
  adversary who has a *candidate file* and wants to confirm you hold it. For a
  personal NAS that is a real but low-probability threat. If you are not
  individually targeted, `padding: none` and reclaim the third of your disk.
- **The witness-only node** matters only if a device is *rarely* online. Two
  regularly-used devices exchange witnesses through the peer without it.
- **Object Lock `compliance` mode** — undeletable even by you — is for regulatory
  requirements. `governance` plus the approval loop stops ransomware just as
  effectively and cannot brick your own archive through a policy mistake.
- **The doc face (M6) is the most work and probably the least used** of the three.
  CRDT engines are where projects go to die. Unless real-time multi-writer editing
  is a thing you will actually do, cut it and keep the S3 and git faces.
- ~~**The Tor carrier.**~~ **Retracted — this was wrong when written.** §19.1 and
  §19.2 both mandate `peers: [home-nas]`, explicitly *not* a rented VPS, and §5.6
  requires the roaming laptop to reach that home NAS from a café with
  port-forwarding and VPNs ruled out. Tor **is** the reachability story for those
  use cases; cutting it would silently cut §19.1 and §19.7 with it.
- **The witness-only node** is more load-bearing than first stated. §5.4 says it
  is what turns "one peer withholds forever" into "every node must collude." Two
  regularly-used devices behind a *single* malicious peer get nothing from each
  other. Cut it only if you already run more than one peer.

Cutting the doc face removes roughly a quarter of the remaining work and touches
none of §19's use cases. Padding is now off by default (§4.2.1), which costs
nothing and reclaims the storage. The other three candidates did not survive
scrutiny.

---

## 21. Change log

### Revision 2

| Change | Driver |
|---|---|
| §3.1 normative key/nonce schedule | Root key `rk` was fixed across versions with no nonce rule beside a "zero nonce is sound" claim — keystream reuse and Poly1305 forgery on the namespace anchor |
| §3.1 signature contexts, role-separated keys | KDFs were domain-separated; signatures were not, with one identity implied for handshake, slots and leases |
| §3.3 `pt_hash` in manifests | XChaCha20-Poly1305 is not key-committing; one address could map to two plaintexts |
| §3.5 `CS` in the cap, distribution, rotation | The write-cap could not write; `CS` had no distribution protocol and no revocation story |
| §3.6 BLAKE3 rationale rewritten | The tree-hashing justification was false — AEAD tag verification forces whole-chunk reads anyway |
| §2.1 gateway auth | "Localhost-only" was treated as a security boundary; it is not |
| §4.5 proof of possession | A lying peer could turn dedup-skip into silent, later-discovered data loss |
| §5 regimes, anchors, history, gossip | Fork detection failed on bootstrap, on cross-client pin divergence, and could not walk a chain the layout never stored |
| §6 deltas, grace, offline policy, quotas | Wholesale epoch renewal was O(n) in addresses; write/GC raced; offline laptops are the median case; griefing was unbounded |
| §7.1 per-key LWW inside the bucket | One slot per bucket lost writes to unrelated keys — a semantics violation, not tuning |
| §8.3 encrypted cache | Plaintext cache undid the vault's rigour and was absent from the threat model |
| §9 30–40%, six gaps | "~70%" and "five gaps" were both wrong against the actual code |
| §10 `nas-peer` | The untrusted peer server was missing from the plan entirely |
| §11 M1 split into M1/M2 | One milestone contained the peer, leases and fork semantics |
| §1 three new leaks | Lease inventories, dedup equality oracle, local plaintext |

### Revision 3

| Change | Driver |
|---|---|
| §4.2.1 deterministic size-class padding | Chunk-length fingerprinting was the one accepted leak with no mitigation; decision taken to pad |
| §3.9 three revocation paths | Revocation was one unrevocable footnote; peer blocking, device roster removal and lazy `CS` rotation are different mechanisms with different guarantees |
| §5.3 witness records + witness-only nodes | "Clients gossip" assumed clients meet; a roaming laptop and a rarely-online second device never do |
| §5.5 retain-N + skip-chain checkpoints | Compaction policy was undecided, and the peer deciding it is the one we distrust |
| §5.6 roaming section | Unstable connectivity is the primary use case, not an edge case |
| §7.2 poll-first liveness | Pubsub cannot be load-bearing against an untrusted peer; the doc face was needlessly coupled to an upstream gap |
| §14 upstream work approved | `simple-network` transcript binding and constant-time pin compare to be fixed in place |

### Revision 5

| Change | Driver |
|---|---|
| §3.5 roster becomes a plaintext, slot-chained object | It sat inside the encrypted manifest while the peer was required to check it — peer-side write enforcement was impossible as written |
| §1 three further leaks | The roster and retention sets must be plaintext; the price is stated rather than hidden |
| §2.2 "what the peer can actually enforce" table | Revision 4 claimed peer-enforced write ACLs in every mode; **semantic** append-only is not enforceable in encrypted modes |
| §16.3 retention ships addresses, extend-only under the everyday key | A Merkle root left the peer unable to decide membership when sweeping; ransomware must be able to *add* protection but never remove it |
| §16.3 precomputed challenge/response pairs | §4.5's proof of possession required holding the ciphertext — impossible for the archive it was meant to audit |
| §16.2 rolling quorum + named clock owner | `object: 1` × N deletes a namespace at quorum 1; and no trusted time source exists, so cooling-off is an approver-device convention, not a protocol guarantee |
| §2.2.2 passphrase mode fully specified | The DEK was never defined, wrap storage was unstated, recovery had no freshness anchor, and superseded wraps left the brute-force target in place |
| §2.2.3 per-tenant address salt | Global dedup on a shared peer handed every co-tenant a confirmation oracle |
| Goal, Non-goals, §12.2 rewritten mode-conditionally | Revision 4 contradicted all three the moment `transit-only` existed |
| Peer-side features explicitly deferred | A remote plaintext-serving surface was introduced in a bullet list with no identity, auth or transport model |
| §3.1 eleven more signature contexts | Six signed objects were added in revision 4 with no contexts — the exact mistake §3.1 exists to prevent |
| §15.3 directory keys reconciled with §3.1 | Convergent and hierarchical manifest keys were mutually exclusive; chunks stay convergent, manifests move to `dk` |
| §4.2.1 padding defaults to `none` | User decision; the 20–35% premium is not worth a low-probability targeted attack |
| §4.2.1 underflow note | The Lean proof holds because `Nat` truncates; Rust `usize` underflows instead |
| §7.3 fast-forward stated as advisory | The peer enforces only sequence-CAS; force-push is detectable after the fact, not preventable |
| §7.3 packfile mechanism corrected | Packs deflate per object, not as one stream; the real killers are delta-base selection and object ordering |
| §7 table + M5 corrected to `cas-merge` | Revision 4 changed §7.3 and left two other places contradicting it |
| §14 marked done, wire-break carried | The upstream fix landed and made the spec stale |
| §16.4 versioning caveat | Old versions are swept by the same compromised client's lease deltas |
| §17 DVC layout and scope of the win corrected | 3.x cache path; the saving is wire and peer, not local disk |
| §20 two causal chains corrected, §20.3 added | Dedup does **not** force convergent encryption, and recoverability does not force `transit-only` |
| §20.2 Tor cut retracted | It is the reachability story for §19.1, §19.2 and §19.7 |

### Revision 4

| Change | Driver |
|---|---|
| §2.2 three confidentiality modes | E2EE is not always the right trade — family photos should not be lost with a vault, and a NAS you own can safely read them |
| §2.2.2 passphrase wraps a random DEK | So a passphrase change re-wraps 32 bytes instead of re-encrypting a terabyte; Argon2id, never `sequential_stretch` |
| §1 per-mode framing | Only confidentiality varies; integrity, authenticity, rollback detection, leases and witnesses are identical in all modes |
| §7.3 git remote helper | Inflated loose objects (packfile compression destroys CDC); OID map never leaves the encrypted manifest |
| §7.3 refs → `cas-merge`, fast-forward merge **(reverses rev 2)** | Git already has a concurrency rule everyone knows; better than passing slot ownership between devices |
| §7.4 worktrees | Agent workflows; distinct branches are distinct slots, so parallel agents never contend |
| §7.5 patches as first-class objects | Agents produce patches; review gating reuses the §16 approval quorum |
| §7.6 rule-filtered mirroring | A filtered mirror is a *derived repo*, not a copy — needs a persisted SHA mapping, fail-closed rules, and publish gates |
| §15 four permission layers | "Permissions" conflates POSIX metadata, mount expressiveness, read control and write control |
| §15.3 per-directory keys from M0 | Subtree capabilities are impossible to retrofit without re-keying everything |
| §16 Object Lock + approval loop | Append-only requirement; key separation is what defeats ransomware |
| §16.3 retention overrides leases | Otherwise a compromised client destroys a WORM namespace by going quiet |
| §17 DVC | Its whole-file cache is exactly what our CDC fixes, at zero integration cost |
| §18 + `formal/` | Verified Lean, honest labelling of unchecked TLA+, and a CI rule against `sorry` |
| §19 use-case cookbook | Intentions mapped to concrete configuration |
