<!-- SPDX-License-Identifier: Apache-2.0 -->
# NAS-tools — what it is for, in plain language

A companion to `SPECS.md` §19. That section gives the YAML; this one explains
what each case is actually *for*, what you are trading away, and how you would
know it works. Nothing here is new policy — if the two disagree, `SPECS.md`
wins and this file is the bug.

## The one idea underneath

You want your own storage, on machines you do not fully trust — a NAS in a
cupboard, a rented VPS, a friend's spare box — and you want that to be safe
without having to trust any of them.

So the default is: **the storage peer holds ciphertext and cannot read your
data.** It stores blobs addressed by their content, and hands them back when
asked. It never needs to know what they are.

That default is negotiable *per namespace*, and the whole design turns on
choosing honestly. Encryption is not free: a peer that cannot read your photos
also cannot make thumbnails of them. So there are three modes, and picking the
strongest one everywhere is usually the wrong answer.

| mode | who can read it | what you get | what you lose |
|---|---|---|---|
| `transit-only` | the peer | server-side browsing, thumbnails, search | the peer can read everything |
| `passphrase` | anyone with the passphrase | recovery from memory alone | offline brute force is possible |
| `e2ee` | only your key | nothing else can read it, ever | lose the key, lose the data |

---

## The cases

### 1. Family photos on the NAS in the house *(§19.1, `transit-only`)*

**The intent.** "My family should be able to browse these. I must not lose them
because I lost a laptop. They are not secret."

**Why not encrypt them.** Because you want a gallery, and thumbnails, and search
by date — and a peer that cannot read the photos cannot produce any of it. The
NAS is in your house; it is not a rented box.

**The trade, stated plainly.** The NAS can read every photo, and access control
depends on the NAS honouring it. In exchange, nothing is lost if every key you
own burns.

**Filenames stay plaintext too** — that is what makes server-side browsing
possible at all, and pretending otherwise would be theatre.

### 2. Documents locked by a password you can remember *(§19.2, `passphrase`)*

**The intent.** Passport scans, contracts. Encrypted — but recoverable from
memory, because losing them to a dead laptop is the more likely disaster.

**How it works.** Your passphrase is stretched with Argon2id into a key that
wraps a random data key. Changing the passphrase rewraps 32 bytes; it does not
re-encrypt your documents.

**The honest warning.** The peer holds the ciphertext and can attack it offline,
at leisure, forever. Argon2id makes each guess expensive; it does not save a
weak passphrase. **Use five or more diceware words.** And keep this on a machine
you own, not a rented VPS.

### 3. Work source code and secrets *(§19.3, `e2ee`)*

**The intent.** This must never be readable by the storage, full stop.

**The consequence, accepted deliberately.** There is no recovery path. Lose the
vault, lose the data. Because of that, a rented VPS is fine here — it only ever
sees ciphertext.

### 4. Legal records that must never be deleted *(§19.4, WORM)*

**The intent.** Records with a seven-year retention that must survive both
accident and attack — including an attacker who has your laptop.

**How deletion is prevented.** The laptop holds `append` rights and *nothing
else*, so ransomware running as you cannot delete. Deleting requires a quorum of
offline hardware tokens: one for a single object, two for a prefix, three for a
namespace.

**The subtle part.** A rolling window (10 objects in 30 days escalates to a
3-token quorum) exists because otherwise an attacker deletes a namespace one
object at a time, each under the weakest quorum. The cooling-off period is
enforced by the *approving devices*, because there is no clock anyone can trust.

Retention also overrides leases — so data cannot be destroyed by simply going
quiet and letting it expire.

### 5. ML datasets with DVC *(§19.5)*

**The intent.** Version 10 GB datasets without storing 10 GB per revision.

**What changes.** DVC keeps the pointers in git; underneath, data is chunked,
deduplicated and encrypted. Changing one row of a 10 GB CSV costs kilobytes
instead of a new copy.

### 6. A repo mirrored publicly, minus the private parts *(§19.6)*

**The intent.** Publish a project while keeping `fixes/` and `internal/` out of
the public history — not just out of the tip, out of the *history*.

**What you must understand.** The result is a **derived** repository with
different commit SHAs. The private-to-public SHA mapping is itself kept in the
encrypted namespace, so re-publishing is stable rather than a force-push each
time. Publishing is gated: a dry run, a secret scan, and an approval.

### 7. A laptop that moves between home, office and cafés *(§19.7)*

**The intent.** One device roaming across networks, reaching home without a VPN
and without punching holes in a router.

**How.** The home NAS is reached as a Tor onion service — stable address, no NAT
traversal. A €3 VPS acts as a *witness*: it stores no blobs and holds no
capabilities, it just observes. Writes are accepted while offline and replayed
on reconnect.

**Why the witness matters.** Fork detection needs a second observer to converge.
If your other device is rarely online, the witness is what notices a peer
serving you a rolled-back history.

### 8. Several coding agents at once *(§19.8)*

**The intent.** Multiple agents working the same repository without fighting.

**Why it works.** One git worktree per agent, each on its own branch. Distinct
branches are distinct slots, so there is **no contention at all**. Two agents on
the same branch collide as an ordinary non-fast-forward error — the failure
mode every git user already understands.

### 9. A hostile peer *(§12.4, tested as UC09)*

Not a configuration but a threat model the others rest on: what a malicious
storage peer can and cannot do. It can withhold data, serve stale history, and
observe access patterns. It cannot read `e2ee` content, forge signatures, or
roll history back undetectably once a witness has seen it.

---

## How these are tested

`tests/usecases/` turns §19 into **executable acceptance criteria**, written
before the implementation "so it cannot quietly redefine success". **106 checks
across 11 scripts**, run by `ci.sh`. Four further scripts (`uc10`–`uc13`) are
manual drills needing real processes, fixed ports or docker — excluded from the
automated run by design and documented in `MANUAL-TESTING.md` §12.

Beneath that: **614 `#[test]`s** in the crates, 10 fuzz targets over every
decoder, and `formal/` carrying Lean and TLA+ models.

The harness is worth reading (`tests/usecases/lib.sh`) because its header names
three properties it lacked in its first version, each of which would have made
it useless while still printing green:

1. **Milestone gating.** Checks are tagged `M0`–`M6`. Without gating, every
   assertion fires the moment a binary exists, CI goes permanently red, and the
   gate gets switched off — "precisely the failure the harness exists to
   prevent".
2. **A refusal contract.** "Refused by policy" is exit code **2**, specifically.
   Under a looser rule — any non-zero means refused — a stub CLI that errors on
   everything would pass every security assertion in the suite.
3. **Honest aggregation.** `$?` after an `echo` is echo's status, not the test's.
   A script that dies early and prints no summary is counted as **FAIL**, not
   skipped. And the run ends with `PENDING is not success.`

### Reading a run

    ./tests/usecases/run.sh                    # defaults to NAS_MILESTONE=M0
    NAS_MILESTONE=M6 ./tests/usecases/run.sh   # everything

A bare run on a machine with no built binary reports **0 passed, 0 failed, 106
pending**, every line reading `no nas binary`. That output looks identical
whether the project is finished or empty — so it is not evidence of anything.
Build first, then set the milestone.

## Current state, measured 2026-09-26

Run it yourself before believing any number here:

    cargo build --release -p nas-cli
    NAS_BIN="$PWD/target/release/nas" NAS_MILESTONE=M6 ./tests/usecases/run.sh

**Measured today: 89 passed, 17 failed, 0 pending.** `STATUS.md` opened with
"M0–M6 are done (106 pass, 0 fail)". That is not reproducible on andromeda.

Two things had to be fixed before the suite could run at all, and both are
worth knowing because each produced a *confident wrong answer* rather than an
error:

1. **The workspace did not compile.** `nas-crypto` and `nas-vault` were
   repointed at `rust-secure-memory-public` while `nas-transfer` still reached
   the private `rust-secure-memory` through `simple-network`. Two different
   `secure-memory v0.1.0` in one graph, and cargo refuses to resolve — so not
   one crate built. Fixed by depending on `simple-network-public`, which is
   what every other `-public` mirror already does.

2. **`NAS_BIN` must be set.** The harness reads `$NAS_BIN` or `nas` on `PATH`
   (`tests/usecases/lib.sh:20`); it does *not* look in `target/release/`.
   Without it every check reports `no nas binary` and the run prints
   **0 passed, 0 failed, 106 pending** — which is exactly what a finished
   project and an empty one both look like. `ci.sh:38` sets it; a hand-run
   does not.

### The 17 failures, which are not scattered

Every one is in **UC06** (public mirror) or **UC08** (several coding agents),
and both are the git face added in `2b6e29f`:

* `nas git` **is not a command** — the binary's help lists no `git`
  subcommand, so all nine UC08 checks fail. The git face exists in the crates
  and in `SPECS.md` §7.3–§7.6; it is not wired to the CLI.
* `nas mirror publish` without a dry run exits **1, not 2**. Under this
  project's own refusal contract exit 2 means "refused by policy" and anything
  else means broken — the harness reports it as `BROKEN, not refused`. The
  remaining UC06 checks depend on a publish having happened, so they fall with
  it.

So the honest summary is: **the storage, crypto, lease, delete, vault, peer,
WebDAV and doc faces pass their acceptance checks at M6; the git face does
not run.** 619 unit tests pass, `clippy -D warnings` is clean, and those
numbers are real — they simply never covered the CLI wiring the acceptance
suite exercises.
