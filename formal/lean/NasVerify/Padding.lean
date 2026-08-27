/-!
# Size-class padding is total, reversible, and class-exact

`Transcript.lean` proves `unpad (pad cls x) = some x` for a *single* class, and
that proof is where the implementation went wrong. It holds unconditionally —
including when `cls < x.length + HEADER` — because Lean's `Nat` subtraction
truncates at zero. Written literally in Rust, the same expression is `usize`
arithmetic that underflows to ~2⁶⁴: a panic in debug, a 16-exabyte allocation
in release. **The model erased exactly the failure mode most likely to occur.**

This file closes that gap. It models what `crates/nas-store/src/padding.rs`
actually does — select a class from a ladder, then pad — and proves three
things the single-class model cannot express:

1. `padLadder` is **partial**, and its refusal is *exactly* the case where no
   class can frame the input (`padLadder_eq_none_iff`). That is the `TooLarge`
   error, proved to fire in precisely the right circumstances.
2. When it succeeds, the output length is a member of the ladder
   (`padLadder_length_mem`). A padded chunk that is not class-sized would leak
   the length that padding exists to hide, so this is a confidentiality property
   and not merely a sanity check.
3. Reversibility survives the added partiality (`unpad_padLadder`).

And, so the model is not vacuous about the bug it exists to describe,
`padTo_underpads` proves the *negative* result: the single-class version
silently produces a non-class length when the class is too small. That is the
formal statement of "the proof constrains the design, not the code that drifts
from it".
-/

namespace NasTools

/-- Recover the payload by reading the length prefix and discarding the fill.

    Restated here rather than imported: `formal/check.sh` runs `lean` on each
    file independently, with no build system and so no search path. The
    definition is character-identical to the one in `Transcript.lean`. -/
def unpad : List Nat → Option (List Nat)
  | []        => none
  | n :: rest => if n ≤ rest.length then some (rest.take n) else none

/-- Width of the length prefix. One `Nat` here; four bytes in the
    implementation. Nothing below depends on the value. -/
def HEADER : Nat := 1

/-- Pad `x` into a `cls`-sized class. Same shape as `pad`, named separately so
    the two models can be compared in one file. -/
def padTo (cls : Nat) (x : List Nat) : List Nat :=
  x.length :: x ++ List.replicate (cls - HEADER - x.length) 0

/-- The smallest class in the ladder that can frame `need` bytes.

    The ladder is assumed ascending, as `LADDER` is in the implementation;
    ascendingness is only needed for *minimality*, which no result below
    depends on. -/
def selectClass : List Nat → Nat → Option Nat
  | [],      _    => none
  | c :: cs, need => if need ≤ c then some c else selectClass cs need

/-- Select a class, then pad into it. `none` when nothing fits. -/
def padLadder (L : List Nat) (x : List Nat) : Option (List Nat) :=
  (selectClass L (x.length + HEADER)).map (padTo · x)

/-! ### Class selection -/

/-- A selected class is in the ladder and is large enough. This is the
    predicate that makes the subtraction in `padTo` a real subtraction. -/
theorem selectClass_spec :
    ∀ (L : List Nat) (need c : Nat), selectClass L need = some c → c ∈ L ∧ need ≤ c := by
  intro L
  induction L with
  | nil => intro need c h; simp [selectClass] at h
  | cons a as ih =>
      intro need c h
      simp only [selectClass] at h
      by_cases hle : need ≤ a
      · simp [hle] at h
        subst h
        exact ⟨List.mem_cons_self, hle⟩
      · simp [hle] at h
        obtain ⟨hmem, hneed⟩ := ih need c h
        exact ⟨List.mem_cons_of_mem a hmem, hneed⟩

/-- Selection fails exactly when every class is too small. Not "fails when
    something goes wrong" — the refusal condition is pinned in both directions,
    which is what makes `TooLarge` a specification rather than a fallback. -/
theorem selectClass_eq_none_iff (L : List Nat) (need : Nat) :
    selectClass L need = none ↔ ∀ c ∈ L, c < need := by
  induction L with
  | nil => simp [selectClass]
  | cons a as ih =>
      by_cases hle : need ≤ a
      · -- `a` fits, so selection succeeds and both sides are false.
        simp only [selectClass, if_pos hle]
        constructor
        · intro h; exact absurd h (by simp)
        · intro h; exact absurd (h a List.mem_cons_self) (by omega)
      · -- `a` is too small; the question devolves to the tail.
        simp only [selectClass, if_neg hle]
        rw [ih]
        constructor
        · intro h c hc
          rcases List.mem_cons.mp hc with rfl | hmem
          · omega
          · exact h c hmem
        · intro h c hc
          exact h c (List.mem_cons_of_mem a hc)

/-! ### Padding into a class -/

/-- **The property the single-class model cannot state.** Given that the class
    fits, the padded length is *exactly* the class. -/
theorem padTo_length (cls : Nat) (x : List Nat) (h : x.length + HEADER ≤ cls) :
    (padTo cls x).length = cls := by
  simp [padTo, HEADER] at h ⊢
  omega

/-- **The negative result, so the model is not vacuous about the bug.**

    When the class is too small, the single-class padder does not error — it
    silently emits something whose length is not the class at all. In Lean the
    fill count truncates to zero; in Rust the same expression underflows. Either
    way the output is wrong, and `unpad_pad` in `Transcript.lean` still holds,
    which is precisely why that theorem could not have caught it. -/
theorem padTo_underpads (cls : Nat) (x : List Nat) (h : cls < x.length + HEADER) :
    (padTo cls x).length ≠ cls := by
  simp [padTo, HEADER] at h ⊢
  omega

/-- `padTo` is reversible whatever the class, exactly as `pad` is. Reversibility
    was never the property at risk; class-exactness was. -/
theorem unpad_padTo (cls : Nat) (x : List Nat) : unpad (padTo cls x) = some x := by
  simp [padTo, unpad]

/-! ### The ladder padder -/

/-- Refusal is exactly the case where no class fits. Corresponds to
    `PadError::TooLarge`, and to `pad(P, &vec![0u8; 256 << 10]).is_err()` in
    `padding.rs`. -/
theorem padLadder_eq_none_iff (L : List Nat) (x : List Nat) :
    padLadder L x = none ↔ ∀ c ∈ L, c < x.length + HEADER := by
  simp [padLadder, Option.map_eq_none_iff, selectClass_eq_none_iff]

/-- **Confidentiality property.** A successfully padded chunk always has a
    length drawn from the ladder, so its size reveals only which class it fell
    into. This is what `padded_length_is_always_a_class` asserts in Rust, and
    what `unpad`'s `NotAClass` check enforces on the read path. -/
theorem padLadder_length_mem (L : List Nat) (x p : List Nat) (h : padLadder L x = some p) :
    p.length ∈ L := by
  simp only [padLadder, Option.map_eq_some_iff] at h
  obtain ⟨c, hsel, hp⟩ := h
  obtain ⟨hmem, hneed⟩ := selectClass_spec L (x.length + HEADER) c hsel
  subst hp
  rw [padTo_length c x hneed]
  exact hmem

/-- **Reversibility survives partiality.** Whenever padding succeeds, the
    original bytes come back. -/
theorem unpad_padLadder (L : List Nat) (x p : List Nat) (h : padLadder L x = some p) :
    unpad p = some x := by
  simp only [padLadder, Option.map_eq_some_iff] at h
  obtain ⟨c, _, hp⟩ := h
  subst hp
  exact unpad_padTo c x

/-- **Determinism**, on which convergent encryption depends: padding is a
    function, so identical plaintext pads identically. Trivial in Lean and
    load-bearing in the implementation, where a random fill would have been an
    easy and silent way to destroy deduplication (SPECS §4.2.1). -/
theorem padLadder_deterministic (L : List Nat) (x : List Nat) :
    padLadder L x = padLadder L x := rfl


/-! ## Axiom gate

`formal/check.sh` greps for the token `sorry`, which an `axiom` declaration, a
`native_decide`, or an `@[implemented_by]` would all sail straight past. These
lines close that: they print what each theorem *actually* rests on, and the gate
fails on anything outside Lean's three standard axioms. `sorryAx` appears here
even when the word `sorry` does not. -/
#print axioms unpad_padTo
#print axioms padTo_length
#print axioms padTo_underpads
#print axioms selectClass_spec
#print axioms selectClass_eq_none_iff
#print axioms padLadder_eq_none_iff
#print axioms padLadder_length_mem
#print axioms unpad_padLadder

end NasTools
