# Lean 4 proofs

Deliberately dependency-free: no Mathlib, so each file verifies in seconds with
nothing to install beyond the toolchain. Each file is checked *standalone*, so
they do not import one another; `unpad` is restated in `Padding.lean` rather
than imported.

```sh
lean NasVerify/Transcript.lean   # exit 0 = verified
lean NasVerify/Padding.lean
```

## Theorems

### `Transcript.lean` — encoding

| Theorem | Says | Protects |
|---|---|---|
| `decField_encField` | the decoder recovers a field *and* the exact remainder | the encoding is self-delimiting; a reader never guesses where a field ends |
| `encFields_inj` | distinct field sequences encode to distinct bytes | signature reinterpretation — `("AB","C")` cannot collide with `("A","BC")` |
| `unpad_pad` | single-class padding is reversible for **any** class size | a padding bug is a privacy regression, never data loss |

### `Padding.lean` — the ladder, and the bug the single-class model hid

`unpad_pad` above takes no hypothesis relating payload length to class size, and
that is exactly what made it dangerous. It holds *even when the class is too
small*, because Lean's `Nat` subtraction truncates at zero. The same expression
in Rust is `usize` arithmetic that underflows to ~2⁶⁴. **The model erased the
failure mode most likely to occur**, and `Padding.lean` exists to state what the
implementation actually does.

| Theorem | Says | Protects |
|---|---|---|
| `selectClass_spec` | a selected class is in the ladder and is large enough | this predicate is what makes the subtraction in `padTo` a real subtraction rather than a wrap |
| `selectClass_eq_none_iff` | selection fails **iff** every class is too small | `TooLarge` is pinned in both directions — a specification, not a fallback |
| `padTo_length` | given a class that fits, the padded length is *exactly* the class | — |
| `padTo_underpads` | given a class that does **not** fit, the length is *not* the class | the negative result that keeps the model honest: it proves the old theorem could not have caught the bug |
| `padLadder_eq_none_iff` | the ladder padder refuses exactly the unpaddable inputs | matches `PadError::TooLarge` in `padding.rs` |
| `padLadder_length_mem` | a successfully padded chunk's length is a member of the ladder | **confidentiality**: a non-class length leaks the size padding exists to hide. Enforced on the read path by `PadError::NotAClass` |
| `unpad_padLadder` | reversibility survives the added partiality | data recoverability |
| `padLadder_deterministic` | padding is a function | convergent dedup — a random fill would silently destroy it (SPECS §4.2.1) |
| `unpadStrict_padLadder` | the strict reader accepts every honest output | a check that rejected valid data would be worse than no check |
| `unpadStrict_rejects_other_classes` | **any** class but the selected one is rejected | the class-selection covert channel, ~2 bits per chunk — see below |

### The gap the M0 review found in this file

`padLadder_length_mem` proves a padded chunk's length is *a* member of the
ladder. That is weaker than it looks: nothing in it stops a writer padding a
five-byte payload into the 256 KiB class instead of the 32 KiB one. The class
index is then a covert channel invisible to a reader that only checks
membership — and it defeats the length-hiding the profile exists for, since a
writer can simply pick the class matching the true size range.

The model could not see this because every theorem reasoned only about *outputs
of `padLadder`*. `unpadStrict` models the reader as `padding.rs` now implements
it, and the two theorems above are the pair that matters: no false rejection,
and no acceptance of any other class. The lesson generalises — a model that only
quantifies over well-formed inputs cannot say anything about a malicious writer.

## Axiom gate

A `sorry` grep does not catch an `axiom` declaration, a `native_decide`, or an
`@[implemented_by]`. Every theorem above therefore ends with a `#print axioms`
line, and `../check.sh` fails on anything outside `propext`, `Classical.choice`
and `Quot.sound`. As it happens all eleven theorems use only `propext` and
`Quot.sound` — no choice.

Both gates are verified to actually bite; see `../../MANUAL-TESTING.md` §1d.
