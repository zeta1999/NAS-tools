# Lean 4 proofs

Deliberately dependency-free: no Mathlib, so `lean NasVerify/Transcript.lean`
verifies in seconds with nothing to install beyond the toolchain.

```sh
lean NasVerify/Transcript.lean   # exit 0, no output = verified
```

## Theorems

| Theorem | Says | Protects |
|---|---|---|
| `decField_encField` | the decoder recovers a field *and* the exact remainder | the encoding is self-delimiting; a reader never guesses where a field ends |
| `encFields_inj` | distinct field sequences encode to distinct bytes | signature reinterpretation — `("AB","C")` cannot collide with `("A","BC")` |
| `unpad_pad` | padding is reversible for **any** class size | a padding bug is a privacy regression, never data loss |

`unpad_pad` takes no hypothesis relating payload length to class size. That is
intentional and worth noting: it means an arithmetic error in class selection
cannot corrupt stored data, only waste space or under-pad. Confidentiality and
recoverability fail independently, which is the safer coupling.
