# Proposal: CDC + at-rest encryption in simple-backups

Aimed at `simple-backups` / `backups-store`. NAS-tools will not grow a second
store (SPECS: nas-store is not a fork). If this lands upstream, NAS-tools keeps
taking the path dep. If it does not, this document is the discussion, not a
rewrite.

## What NAS-tools already decided

Content-defined chunking (FastCDC, 64 KiB average) plus convergent
XChaCha20-Poly1305, addressing **ciphertext**. Dedup is across devices that
share a convergence secret. Size-class padding is optional and off by default
(measured premium 56–97%, not the 20–35% the first estimate claimed).

File-level CAS (hash the whole file, store one blob) is what a backup tool
usually does first. It is the wrong grain for a NAS:

- A 4 GiB VM image that changed 8 KiB in the middle re-uploads 4 GiB.
- Two photos that share a RAW header still share nothing if the unit is the
  file.
- Encryption-after-hash (plaintext address) leaks the confirmation oracle
  SPECS §2.2 exists to close. Encryption-before-hash (ciphertext address)
  needs a *convergent* scheme or dedup dies.

## FastCDC vs file-level CAS

| | File-level | FastCDC (gear, ~64 KiB) |
|---|---|---|
| Unit of transfer | whole file | chunk |
| Insert in the middle | rewrites everything after | only the touched windows |
| Dedup across similar files | none | shared chunks |
| Manifest | one digest | chunk list + size + scheme |

`backups-store` today is the file-level column. The change is: chunk first,
address each chunk, then encrypt (or encrypt then address — see below).

## Convergent / XChaCha at rest

Convergent encryption: `ck = keyed_hash(CS, padded_chunk)`, nonce derived from
`ck`, AEAD seal. Two tenants with different `CS` never collide. The same tenant
on two devices does.

XChaCha20-Poly1305 is what rust-secure-memory already speaks. A random nonce
per write would make identical plaintext different ciphertext and silently
destroy dedup. The nonce must be a function of the chunk key.

## Why address ciphertext

A store that names blobs by `hash(plaintext)` and then encrypts the payload
still *has* the plaintext hash on the wire and on disk as the filename. Anyone
who can propose a candidate file gets a confirmation. Addressing
`hash(ciphertext)` means the name is not a confirmation unless you already
hold `CS`.

That is also why padding, when used, is applied **before** `ck` is derived
(SPECS §4.2.1). Padding after the key would make the address depend on a
choice the reader cannot reconstruct.

## What would have to change in `backups-store`

1. **Chunker** — FastCDC (or a compatible CDC) in front of `put`. Average
   64 KiB, max 256 KiB, so a blob stays inside a single padded class if a
   consumer later turns padding on.
2. **Addressing mode** — `content` (ciphertext hash) vs `salted` (tenant salt
   mixed in, for a plaintext-at-rest / transit-only peer). File-level hash
   remains a valid mode for tools that do not want CDC.
3. **Manifest** — a chunk list per object, not a single digest. Versioned so
   an old whole-file object still reads.
4. **Sealer** — optional. Off means today's behaviour. On means convergent
   XChaCha under a caller-supplied `CS`. The store does not invent a secret.
5. **Proof of possession** — challenge `H(blob ‖ nonce)` on the *held
   ciphertext*, so a peer that only remembered the address cannot skip the
   upload.

None of this requires NAS-tools types. A `ChunkRef { addr, len }` and a
`put_chunk` / `get_chunk` pair is enough. NAS-tools would keep its own
manifest wrappers and take the chunk/store primitives.

## What this proposal is not

- Not a request to vendor nas-store into simple-backups.
- Not a request that backups become a NAS.
- Not an at-rest scheme that uses a random nonce (that is backup-of-one-device,
  not convergent multi-device dedup).

If the sibling repo is writable, open this as a discussion/PR there. Until
then it lives here and is linked from TODO.md.
