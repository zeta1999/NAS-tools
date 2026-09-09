# NAS-tools — user manual

This is the operator-facing manual. It says what `nas` does, how to drive it,
and — most importantly — what it does **not** promise. The design document is
`SPECS.md`; where this manual makes a security claim it cites the section the
claim comes from, and the section is the authority if the two ever disagree.

**Maturity.** Pre-release. What exists today is the substrate (M0) and the
networked peer protocol (M1): encrypted chunk storage, a peer you do not have to
trust, slot consistency with fork detection, lease-based garbage collection and
the deletion approval loop. The mount, the S3 face, the git face and the doc
face (M3–M6) do not exist yet. Treat every command below as a building block,
not a product. `STATUS.md` is the current state; `MANUAL-TESTING.md` records what
has actually been exercised against real processes and containers.

## 1. The one decision that matters: the confidentiality mode

A namespace is created in one of three modes and the mode never changes
(SPECS §2.2). Choose it for what you are storing, not for convenience:

| | `e2ee` | `passphrase` | `transit-only` |
|---|---|---|---|
| Who can read | holders of a capability — your devices | anyone with the passphrase | whoever the peer's ACL admits |
| Enforced by | mathematics | mathematics | the peer's cooperation |
| If the peer is hostile | still confidential | still confidential | **no read control at all** |
| Revoking a reader | re-key the namespace (§3.9c — see §4.3 below) | re-encrypt under a new key; a re-wrap alone revokes nobody who already unwrapped | delete the ACL entry — instant, if the peer honours it |
| Filenames on the peer | never visible | never visible | visible |

SPECS §15.3 puts the trade in one sentence: *cryptographic access control you
cannot easily revoke, or revocable ACLs you must trust the peer to honour.*
There is no third option. `transit-only` is the right mode for a NAS in your own
house serving your own family (SPECS §19.1); it is the wrong mode for anything
you would mind the NAS operator reading.

Key material lives in `~/.local/share/nas/<namespace>/` (`$NAS_HOME` overrides
the base). In `e2ee` mode the vault key currently sits beside the sealed vault
in `vault.key` (mode 0600) — that relocates the secret rather than protecting
it, so `e2ee` at rest is exactly as strong as your local disk (TODO.md, M0).

## 2. Commands

```
nas ns create <name> [--mode e2ee|passphrase|transit-only]
                     [--padding none|classes|fixed]
                     [--object-lock governance|compliance|legal-hold --retention 7y]
                     [--device <subject>]
nas ns list
nas ns open <name> [--passphrase <pw>] open a namespace another device created (§2, second device)
nas ns export-pub <ns> <out-dir>       keys a peer operator needs to admit <ns>
nas acl grant|revoke|check <ns> --subject <s> --right <r>
nas acl list <ns>
nas peer init <dir>
nas peer allow <dir> <subject> <transport.pub>
nas peer writer <dir> <slot.pub>
nas peer grant <dir> <subject> <right>
nas peer show <dir>
nas peer serve <dir> --listen <host:port> [--hostile <spec>] [--mode <m>]
                     [--salt <tenant.salt>] [--once] [--witness]
nas peer sync <ns> --peer <host:port> --peer-pub <transport.pub>
                   [--witness <host:port> --witness-pub <transport.pub>]
nas test …                             the acceptance substrate; see MANUAL-TESTING.md
```

`nas` with no arguments prints the list; `nas ns`, `nas acl` and `nas peer`
print their own. Passphrase-mode commands take the passphrase from
`--passphrase` or `$NAS_PASSPHRASE`; without either they refuse rather than
guess.

There are **two access lists**, and they are not synchronised today. The one
the peer enforces over the wire is the peer operator's own, kept in
`<dir>/acl` by `nas peer allow` / `nas peer writer` / `nas peer grant`. The one
`nas acl grant|revoke|list` edits is the namespace's *declared* list
(SPECS §19.1 puts it in the namespace definition), stored in the clear beside
the namespace `config`; `nas acl check` evaluates it exactly as a peer would —
including refusing to adjudicate `read` in an encrypted namespace at all (exit
`1`, not `2`: the peer has no opinion it could offer there, SPECS §15.3).

**Exit codes** are part of the contract: `0` ok, `1` error, `2` **refused by
policy**, `3` unimplemented. Exit 2 is never a bug to retry around — it is the
tool declining to do something the design says must not be done. Read the
message.

### A namespace, a peer, and a sync — the minimum

On the device:

```
nas ns create work --mode e2ee
nas ns export-pub work ./work-pub        # transport + slot public keys, no secrets
```

On the peer (a NAS, a VPS, a container — something you do **not** need to trust):

```
nas peer init /srv/nas
nas peer allow  /srv/nas laptop ./work-pub/transport.pub  # admit this device, as subject "laptop"
nas peer writer /srv/nas ./work-pub/slot.pub              # this slot key may publish
nas peer grant  /srv/nas laptop write                     # and this subject may write
nas peer serve  /srv/nas --listen 0.0.0.0:7000
```

Back on the device, every time you want the peer to have your latest state:

```
nas peer sync work --peer nas.local:7000 --peer-pub ./peer/transport.pub
```

`--peer-pub` is the peer's pinned transport key: whoever answers on that port
must prove that key or the handshake fails before any application byte moves.
Keep the file; copy it out of band the first time.

### A witness node

```
nas peer init   /srv/witness
nas peer allow  /srv/witness laptop ./work-pub/transport.pub   # admitted like any peer
nas peer writer /srv/witness ./work-pub/slot.pub               # but granted nothing
nas peer serve  /srv/witness --listen 0.0.0.0:7001 --witness
nas peer sync work --peer nas.local:7000 --peer-pub ./peer/transport.pub \
                   --witness vps.example:7001 --witness-pub ./witness/transport.pub
```

A witness-only node holds no blobs, no capabilities and no secrets; it only
relays signed observations of which record was at which sequence (SPECS §5.3).
A cheap VPS is enough. Why you want one is in §4.1 below.

### A second device (passphrase mode)

Copy the namespace's `config` and `wraps` directories from the first device
into `$NAS_HOME/<ns>/` on the second, then:

```
nas ns open work            # with --passphrase or $NAS_PASSPHRASE
nas peer sync work --peer nas.local:7000 --peer-pub ./peer/transport.pub \
                   --witness vps.example:7001 --witness-pub ./witness/transport.pub
```

A brand-new device has no memory of what the peer used to serve, so on its
first sync it can only detect a rollback through a witness — this is the blind
spot the witness node exists for (MANUAL-TESTING.md §12, "device 3").

## 3. What is protected

Content confidentiality and integrity, the authenticity of every published slot
version, and dedup safety are strong properties (SPECS §1, "What is
protected"). Rollback and replay are **detected, not prevented**, and only for
devices that eventually communicate. Confirmation attacks are defeated by the
per-tenant convergence secret `CS` — which is unrevocable once it has leaked
(SPECS §3.5).

What is **not** protected, in the design's own words: *content is protected and
behaviour is not.* The peer learns file sizes to chunk granularity, the
sequence of chunk size classes, every address you retain (lease inventories),
whether a write introduced new data, your device roster and when it changed,
which blobs are fetched together, and when you are active (SPECS §1, "What is
NOT protected"). If any of that is what you need to hide, this tool does not
hide it.

## 4. What `nas` does not promise

Three statements the design requires this manual to make plainly (SPECS §3.9,
§5.4). Each is followed by what the tool actually does today, because the gap
between the design and the binary is part of the truth.

### 4.1 Fork detection is not prevention

A hostile peer can serve one history to one of your devices and another history
to another. `nas` **detects** this — a freshness anchor in every capability, a
hash chain over slot history, and signed witness records that the peer can
withhold but cannot forge — and detection converges once witnesses propagate. It
does **not** prevent it, and it does not reach SUNDR's fork consistency
(SPECS §5.4).

The limit, stated by the design itself: *a peer that withholds every witness in
both directions, forever, can keep two devices forked.* A witness-only node
raises that bar to *every* node colluding — which is the reason to run one.
The design also counts persistent withholding as a signal in itself, since an
active device's witnesses should keep arriving. Today `nas` does not alarm
merely because witnesses have stopped; what it refuses is a peer that serves
*less* than this device has pinned or seen witnessed (the rollback and
withholding lines below).

What you will see is `nas peer sync` exiting `2` with one of:

```
fork: the peer serves a different record at seq N than the one seen here before (SPECS §5.3)
fork: the peer's checkpoint at seq N names a different record than the one seen here before (SPECS §5.3)
fork: the witness saw a different record at seq N than the chain the peer now serves (SPECS §5.3)
fork: the peer's checkpoint at seq N names a different record than the witness saw (SPECS §5.3, §5.5)
fork: the record the peer serves at seq N descends from something other than the record the witness saw at seq M (SPECS §5.3)
peer serves seq N, but seq M was seen here before (rollback)
peer serves no head, but seq N was witnessed (rollback or withholding)
… a signed pointer to nothing is withholding (SPECS §5.3)
```

There is no `--force`. When you see one of these, the peer has either lost
data, rolled you back, or is lying; the correct response is to stop trusting
that peer, not to make the message go away. Two witnesses citing incompatible
records are a self-contained, publishable proof of the fork (SPECS §5.3).

**What "incompatible" covers.** A witness names the record it saw *and* the
record that one descends from — one link of the chain. So two observations at
the same sequence disagreeing is a fork, and so is one observation whose link
does not lead back to what another observation saw at a lower sequence. That
second case is the one that matters in practice: in a real fork each device
reports its own head, and the two heads sit at different heights.

It still needs the links in between. A device that holds observations of seq 4
and seq 9 and nothing between them cannot say whether they are one history or
two, and `nas` says nothing rather than guessing — a peer that withheld one
observation could otherwise make an honest namespace look forked. This is the
same "converges once witnesses propagate" limit as above, seen from the other
side.

### 4.2 A blocked peer keeps what it already had

> A blocked peer still holds every ciphertext it already had. Blocking stops
> *future* exposure. It does nothing about the past, and there is no mechanism
> that could — the bytes left the machine. (SPECS §3.9a)

In `e2ee` and `passphrase` mode what it holds is ciphertext, and it stays
ciphertext for as long as your keys and `CS` are unleaked. In `transit-only`
mode what it holds is your plaintext, and it always did.

Today there is no `nas peer block` command and no vault-held blocklist
(SPECS §3.9a describes both; neither is built). Blocking a peer is: stop
syncing to it, stop handing out its `transport.pub`, and re-replicate what it
held somewhere else.

### 4.3 A revoked device reads old data until that data is rewritten

Removing a device from the writer roster stops it **publishing** (SPECS §3.9b).
It does not stop it **reading**: the device still holds `CS` and its read
capabilities, so everything it could already decrypt stays decryptable, and it
can still mount confirmation attacks against unrewritten data.

Stopping reads means rotating `CS` (SPECS §3.9c), and rotation is generational
and lazy by design — a full re-encrypt of a NAS is not an operation anyone will
run:

1. a new generation is created and **all new writes** use it;
2. the device is removed from the roster and any peer it controls is blocked;
3. a background rewrite moves old data forward, hot data first;
4. **data still in an old generation stays readable by the revoked device until
   its chunk is rewritten.** This is the honest security statement.

Rotation costs all cross-generation dedup for rewritten data; there is no
cheaper revocation.

Today the vault keeps `CS` generations in `e2ee` mode (so rotation is not a
data-loss event), but no CLI command performs a rotation and there is no
background rewrite. `passphrase` mode has no generation table at all: rotating
there means changing the data key, which is a re-encryption, not a vault edit.
`nas acl revoke` in either encrypted mode changes the declared list; it does
not re-key anything, so it does not by itself revoke a reader — and `nas acl
check --right read` on such a namespace tells you so by exiting `1` rather than
pretending a decision was made (SPECS §15.3). In `transit-only` mode the
peer-side list is the whole mechanism, and takes effect the moment the peer
next evaluates it — if the peer is honest.

## 5. Deletion, retention and garbage collection — in one paragraph each

**Garbage collection is by lease** (SPECS §6). Every sync renews a lease on
everything the device holds; a lease lasts 90 days by default, a lapsed lease
keeps protecting for a further 30-day notice window, and blobs younger than 24
hours are never swept regardless of leases, so a write in flight cannot lose
the race (§6.2, §6.3). On every sync the device is told which of its blobs are
protected by nothing but a lapsed lease — inside the notice window that is the
list a sweep *would* take and renewing still saves it; after the window, it is
the list of what went. Sync never releases anything; release is an explicit
act (§16.2).

**Object Lock** (`--object-lock`, SPECS §16) is what stops ransomware on your
own laptop, a mistaken `--delete`, and a bad decision at 2 a.m. It does *not*
constrain the storage provider — a malicious peer deleting your data is the
withholding attack of §4.1. The mechanism is key separation (§16.1): the
everyday key can only ever **add** protection (extend a retention set), and
shrinking it, shortening its expiry, or deleting needs a signature from a
key that is deliberately not on that laptop. Retention overrides leases: a
retained address is not swept even if nobody leases it (§16.3). Deletion is a
loop — a signed request, a 7-day cooling-off, m approvals from distinct
holders bound to that request, then execution (§16.2).

Today the request, approvals and execution records are published, served and
audited over the wire, but **execution does not delete data**: in an encrypted
namespace the peer cannot map an object name to addresses, so it records the
authorisation and the client half — releasing the leases so the sweep can run —
is not built yet (TODO.md, M2).

None of this is confidentiality: the peer sees every retention set and every
lease inventory in plaintext (SPECS §1, §6.5). That is the price of a peer that
can enforce anything at all without reading your data.
