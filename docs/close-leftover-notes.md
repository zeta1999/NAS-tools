# Close leftover notes

Fastest route is documentation wherever the code already matches the decision. The only file deletion is `.github/workflows/ci.yml`. No crypto reimplementation, no NFSv3, no pubsub.

- [ ] Doc only: rewrite the owner TODO section as Deployment and drop the build-blocked sentence
- [ ] Doc only: check off the stale secure-memory box; code is already on both remotes
- [ ] Delete `.github/workflows/ci.yml` and record in TODO that GitHub workflows are not used
- [ ] Doc only: drop the NFSv3 dev box; Finder WebDAV support closes it
- [ ] Doc only: check the rotation/deletion and export-key TODO boxes against MANUAL.md
- [ ] Doc only: close pubsub as a decision, not a post-M6 upgrade
- [ ] Code, separate from the doc pass: page simple-backups push/pull for a very large repo (USE-CASES case 10, SPECS §19.9). See the limits below. Do not treat "split the catalog" as the whole fix.
- [ ] Lean: lease Merkle root is a function of the set, with the count in the root (`nas-lease` `merkle::root`). Not a skip-chain membership theorem.
- [ ] TLA+: the paged push and pull, written with that code. Pages are bounded by encoded size, and a single file's chunk list may be split.

## Fastest route

Fix the sentence that still reads as unfinished work. The doc pass is that. The backup transfer does not match the decision: push and pull still put the catalog in one frame. That change is the code section below, not this doc pass.

- Deployment, secure-memory, NFSv3, rotation/export, pubsub: documentation.
- GitHub Actions: delete `.github/workflows/ci.yml` and correct the paragraph that justified restoring it.

## Deployment stays, and it is not a dev task

In `TODO.md`, replace the section "For zeta1999 — needs a human, not an agent" with a short **Deployment** section. Keep one open box: check the test NAS and deploy, including the mode choice per namespace and `NAS_MILESTONE=M6 ./tests/usecases/run.sh` against the real peer. Delete the sub-bullet that says the deploy is blocked because the build is broken.

## Secure-memory is already on both remotes

`seal_with_nonce`, `open_with_nonce`, and `SigKeyPair::from_seed` are in both trees, the source trees match (`diff -rq` is empty aside from git metadata), and both `main` branches are even with origin:

- private `rust-secure-memory` at `1b07967`
- public `rust-secure-memory-public` at `4449a80` (same sources, plus the public-mirror docs commit)

No reimplementation and no push. Check off the "three functions missing" box in one line: closed, public path, both remotes already have the functions. Drop the dead note about uncommitted `export_secret` / `from_parts`.

## No GitHub workflows

Owner choice, to be written so it is not "fixed" by restoring the file again: **do not add `.github/workflows`.** Linux CI is `docker/ci-linux.sh` (`./ci.sh` in `rust:1-bookworm`). Host `./ci.sh` stays the macOS gate.

- Delete `.github/workflows/ci.yml` (restored in `23202cf`).
- Rewrite the checked "CI on linux" paragraph in `TODO.md`. It currently says the workflow runs on every push and that deleting it was backwards. Replace that with the choice above. `docker/build.sh` stays musl compile-only. uc11 stays manual.

## NFSv3 leaves the dev list

Finder supports WebDAV (Connect to Server). Do not write an NFSv3 shim.

- Remove the open M4 box in `TODO.md`. Leave a checked line: WebDAV is the mount; NFSv3 is not a dev task.
- In `SPECS.md` §8, the sentence that says to migrate to NFSv3 when WebDAV performance is the limit becomes: Finder supports WebDAV, so v0 stays WebDAV. A later measurement is not a reason to start NFS.
- In `STATUS.md`, replace "NFSv3 is deferred until a Finder mount is measured" with the same closed line.
- `MANUAL-TESTING.md` §16 stays as an optional measurement, with one sentence that it does not gate development.

## Manual boxes

- Rotation / deletion: the commands and the deletion loop are already in `MANUAL.md` §4.3 and §5 (`nas ns rotate` appends a generation and does not rewrite; deletion is request, cooling-off, m approvals, Execute, lease release, `forget_retention`). Check the §6 box and point it at `nas ns rotate`. There is still no `nas peer block`; do not invent that command.
- Export: check the §4 box and name `nas ns export-key` (0600, refuses to overwrite, exits 2 on `passphrase`). Do not add `nas vault export`.

## Pubsub stays a closed decision

Adaptive polling is already the doc face as UC15 defines it: `poll_interval_ms` (250 ms while editing, 3 min idle) and a one-shot `nas doc get`. There is no background loop, and none is added. A push from an untrusted peer cannot be believed, and silence cannot be believed either, so every correct client fetches the slot head anyway. Building topic filtering, `SecureConnection` pubsub, durable subscriptions, or a poller daemon would not change that.

Do not upgrade `simple-network` or the doc face. Close the wording that still calls pubsub a later optimisation:

- `SPECS.md` §7.2: replace "post-M6 optimisation" with a closed decision. Pubsub is not built. A notification is not load-bearing.
- `SPECS.md` §14: replace "If the doc face later wants pubsub" with the same decision. Leave the upstream cost as history, not as a backlog item.
- `TODO.md` M6 and the upstream box: "remains post-M6" becomes "not built".
- `STATUS.md`: "Pubsub is still a post-M6 latency optimisation" becomes the same closed line.

## Very large server-to-server backup

Use case 10 in `USE-CASES.md`, cookbook `SPECS.md` §19.9. The test script `uc10` is already the three-node drill. This case does not reuse that name. The doc pass above can land without this work. This work is `simple-backups` `crates/backups-transfer`.

What already works and stays that way: one `pair` plus `serve` plus `push` or `pull` per destination. A second copy is a second cron line. No destination list in the job YAML. No `nas-peer` pulling from another `nas-peer`. Object bodies already move in 4 MiB pieces. FastCDC chunks are at most 256 KiB. A single object over 256 MiB stays refused.

### What is actually broken

Calling the fix "page the catalog" understates it.

1. **Three control messages, not one, blow the 10 MiB frame.** `PushBegin` lists every snapshot, every object id, and a challenge per object. `WantObjects` lists every id still needed, plus a proof per id the receiver claims to hold. `PushManifest` and `PullManifest` carry the whole snapshot JSON. Any one of those dies around fifty thousand chunks. A retry rebuilds the same messages, so a vault that never fitted does not resume.

2. **A repeat push re-reads the entire store.** For each object the receiver already has, `handle_push` calls `read_object` and holds the bytes to compute `SHA-256(ciphertext ‖ nonce)`. After the first successful copy of a terabyte, every later push reads that terabyte again and allocates each object whole. Paging the offer does not remove that read. Streaming it removes the allocation. The disk read stays, because a proof over the ciphertext is how a receiver that does not have the bytes fails.

3. **The sender loads every snapshot before it sends anything.** `push_over` reads every manifest into a `Vec`, then every object id, then every nonce, into RAM. A box that can parse one large snapshot can still die from holding all of them at once.

4. **The other server is handed the decryption key.** `PushBegin.convergence` is stored with `store_cs` on the receiver. A backup destination that accepts today's push can open every convergent chunk. That is acceptable for a restore machine you trust. It is a silent key copy if the destination is just spare disk.

5. **`nas peer sync` is the wrong place to "fix" this.** It already sends one blob per request and leases 256 at a time, under a 256 KiB frame. It will not hit the 10 MiB catalog wall. A photo-scale namespace is a round trip per chunk. That cost is real and it is not this change.

6. **A test that only checks "the JSON exceeded 10 MiB" does not show a large copy works.** It shows the frame split. It does not show resume, the possession read, or a manifest that spans pages.

### Remediations that are worth building

All of these, in `pushpull.rs` and `protocol.rs`. No new command, no job-file fan-out, no nas-peer replication.

- A catalog that fits in one frame still uses one `PushBegin`. Existing small pairs stay on that path.
- Above that, pages of at most 1024 object ids and their challenges. The receiver answers wants and proofs for that page only. The client sends those objects, then the next page. Nonces exist for the page in hand, not for the whole repo.
- One snapshot at a time. Do not build the full offer list first.
- Possession proofs hash from `open_object` into the digest. `read_object` is not used for the proof. The bytes still come off disk. Say that in the manual: a later push of an unchanged terabyte reads a terabyte and sends almost nothing.
- Manifests that do not fit in a control frame go out as pages whose encoded JSON stays under 1 MiB. A page may split one file's chunk list. 1024 files is not a safe bound: one video, or 1024 photos with chunk keys, can exceed 10 MiB. The receiver reassembles the same one-file snapshot JSON. A manifest the machine cannot parse locally is out of scope. Do not invent a second on-disk manifest format.
- Pull is in this change. `PullManifest` and the puller's want-list are paged the same way. New `WireMsg` variants, which an old peer's decoder rejects. `PROTOCOL_VERSION` stays 1, so a small `PushBegin` to an old peer still works. The new side is what reports that the catalog does not fit. An old peer only drops the session. A partial manifest is not a successful commit.
- A dropped session is resumed by running `push` again. Pages whose objects are already stored are skipped after a streamed proof. There is no write-ahead log.
- The convergence secret stays off the wire unless the operator passes a flag (`--send-cs` or equivalent). Default push replicates objects and snapshots. Copying `state/cs` is a separate, visible act.
- An old peer that cannot decode a page fails the session with an error that says the catalog does not fit and the peer cannot page. That failure is not an empty success. A small `PushBegin` to an old peer still works. Both ends of a large pair run this code. Same paired-upgrade rule as protocol v1: no downgrade that pretends the page was accepted.
- Tests: a catalog whose JSON exceeds 10 MiB round-trips through pages using tiny objects; a held object is skipped only when the streamed proof matches, and a bad proof causes a resend; a manifest of more than 1024 files round-trips; a catalog that fits still produces one `PushBegin`; a push without the flag leaves the receiver without `state/cs`. No terabyte fixture in CI.

## Two models, and nothing else

Cryptographic primitives stay unmodelled. So do FastCDC, the poll interval, the document merge, and `nas peer sync`. No PlusCal.

Reviewed against `verify_skip_chain` and `merkle::root`. The skip-chain walk does not do Merkle inclusion. An empty tail still verifies, and records between checkpoints are not claimed to be in hand. A theorem that says "a checkpoint that verifies names a record on the chain" is false of that function. `SlotConsistency.tla` already covers a missing witness edge. Do not change the skip walk to make the false theorem true.

- **Lease Merkle root, Lean 4.** `merkle::root` sorts, de-duplicates, promotes the odd node instead of duplicating it, and hashes the element count into the root. The theorem is those properties: the root is a function of the set, and two different sizes do not collide by the duplicated-tail construction. BLAKE3 stays abstract. The file stands alone next to `Padding.lean`, because `formal/check.sh` runs each Lean file with no imports. That gate picks the file up. It does not pick up a new TLA+ module, so the module below is named in `formal/check.sh` with a config that must find a counterexample when a defence is switched off.
- **Paged backup transfer, TLA+.** Written in the same change as the paging code, against the encoded-size rule, including a split of one file's chunk list, and including pull. TLC checks: a page is skipped only after a proof over bytes the receiver read; a peer that cannot decode a page fails the session; a short or partial manifest is not a committed snapshot; a retry does not require the whole catalog in one message. Tiny page size. Run by `formal/check.sh` inside `docker/ci-linux.sh`. Not a GitHub workflow. No terabyte fixture. Do not model the job file or FastCDC.

## Review

A review against cases 1–10 and the decisions above was done after this plan was drafted. Cases 1–9 are already built and are not work items here. Case 10 is this backup change and is not built. The doc pass can be implemented as written. The transfer and the Lean proof are implementable only with the corrections in this section: manifest pages bounded by encoded size, pull included, new wire variants at protocol version 1, and the Lean statement about `merkle::root` rather than `verify_skip_chain`.
