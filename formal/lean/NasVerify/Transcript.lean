/-!
# Transcript encoding is unambiguous

The PQC handshake (`simple-network/src/security/pqc.rs`) and every signed
NAS-tools record are signed over a **length-prefixed** concatenation of fields.

The security of that construction rests on one property: the encoding must be
*injective*. If two different field sequences could produce the same bytes, a
signature over one could be reinterpreted as a signature over the other — the
classic concatenation-ambiguity attack, e.g. `("AB","C")` vs `("A","BC")`.

This file proves injectivity, by way of the stronger and more useful statement
that a decoder recovers both the field **and** the exact remaining input.

The model uses `Nat` for the length prefix; the implementation uses a 4-byte
little-endian prefix. The argument depends only on the prefix being
fixed-width and recoverable, not on its width.
-/

namespace NasTools

/-- A field is a byte string. -/
abbrev Field := List Nat

/-- Encode one field: its length, then its contents. -/
def encField (f : Field) : List Nat := f.length :: f

/-- Encode a sequence of fields by concatenation. -/
def encFields : List Field → List Nat
  | []      => []
  | f :: fs => encField f ++ encFields fs

/-- Decode one field, returning it together with the unconsumed remainder. -/
def decField : List Nat → Option (Field × List Nat)
  | []        => none
  | n :: rest => if n ≤ rest.length then some (rest.take n, rest.drop n) else none

/-- The decoder inverts the encoder and returns the remainder untouched.
    This is what makes the encoding self-delimiting: a reader never has to
    guess where a field ends. (`simp` discharges the `take`/`drop` reasoning
    about `++` from Lean core.) -/
theorem decField_encField (f : Field) (rest : List Nat) :
    decField (encField f ++ rest) = some (f, rest) := by
  simp [encField, decField]

/-- **Main result.** Distinct field sequences encode to distinct byte strings,
    so a signature over an encoded transcript commits to exactly one reading
    of its field boundaries. -/
theorem encFields_inj : ∀ (fs gs : List Field), encFields fs = encFields gs → fs = gs := by
  intro fs
  induction fs with
  | nil =>
      intro gs h
      cases gs with
      | nil => rfl
      | cons _ _ => simp [encFields, encField] at h
  | cons f fs' ih =>
      intro gs h
      cases gs with
      | nil => simp [encFields, encField] at h
      | cons g gs' =>
          simp only [encFields] at h
          have h2 := congrArg decField h
          rw [decField_encField, decField_encField] at h2
          have h3 := Option.some.inj h2
          have hf : f = g := congrArg Prod.fst h3
          have hr : encFields fs' = encFields gs' := congrArg Prod.snd h3
          rw [hf, ih gs' hr]

/-! ## Padding (SPECS.md §4.2.1)

Chunks are padded to size classes before encryption. Padding must be
deterministic, or convergent encryption breaks: identical plaintext would
produce different bytes, different keys, and deduplication would silently
collapse to nothing. -/

/-- Pad `x` into a `cls`-byte class: length prefix, contents, zero fill. -/
def pad (cls : Nat) (x : List Nat) : List Nat :=
  x.length :: x ++ List.replicate (cls - 1 - x.length) 0

/-- Recover the payload by reading the length prefix and discarding the fill. -/
def unpad : List Nat → Option (List Nat)
  | []        => none
  | n :: rest => if n ≤ rest.length then some (rest.take n) else none

/-- **Padding never corrupts data.** Note there is no hypothesis relating
    `x.length` to `cls`: reversibility holds *even if the class arithmetic is
    wrong*. A miscomputed size class can waste space or under-pad — leaking
    more length information than intended — but it can never make a chunk
    unrecoverable. That separation is deliberate: a padding bug should be a
    privacy regression, never a data-loss event. -/
theorem unpad_pad (cls : Nat) (x : List Nat) : unpad (pad cls x) = some x := by
  simp [pad, unpad]


/-! ## Axiom gate

`formal/check.sh` greps for the token `sorry`, which an `axiom` declaration, a
`native_decide`, or an `@[implemented_by]` would all sail straight past. These
lines close that: they print what each theorem *actually* rests on, and the gate
fails on anything outside Lean's three standard axioms. `sorryAx` appears here
even when the word `sorry` does not. -/
#print axioms decField_encField
#print axioms encFields_inj
#print axioms unpad_pad

end NasTools
