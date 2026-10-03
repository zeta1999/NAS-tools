/-!
# The lease Merkle root is a function of the set

Models `crates/nas-lease/src/merkle.rs`. BLAKE3 is not this function. A hash is
an inductive value, so two different shapes are different, and nothing here
claims a property of the compression function.

The Rust function sorts, de-duplicates, pairs, promotes the odd node, and
mixes the element count into the root. Tail duplication is the other builder:
it is what makes `[0,1,2]` and `[0,1,2,2]` the same tree (CVE-2012-2459).
Promotion separates that pair. The count separates two different sizes even
when their trees would not.

This is not a skip-chain membership theorem. `verify_skip_chain` does not
check Merkle inclusion.
-/

namespace NasTools

inductive Hash
  | leaf : Nat → Hash
  | node : Hash → Hash → Hash
  | root : Nat → Hash → Hash
  deriving DecidableEq

def rootCount : Hash → Nat
  | .root n _ => n
  | _ => 0

def insert (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys => if x ≤ y then x :: y :: ys else y :: insert x ys

def sortList : List Nat → List Nat
  | [] => []
  | x :: xs => insert x (sortList xs)

/-- Drop adjacent duplicates. On a sorted list that is every duplicate. -/
def dedupSorted : List Nat → List Nat
  | [] => []
  | [x] => [x]
  | x :: y :: xs => if x = y then dedupSorted (y :: xs) else x :: dedupSorted (y :: xs)

def normalize (xs : List Nat) : List Nat :=
  dedupSorted (sortList xs)

/-- Pair, and leave a trailing odd node as it is. -/
def pairPromote : List Hash → List Hash
  | [] => []
  | [x] => [x]
  | x :: y :: rest => Hash.node x y :: pairPromote rest

/-- Pair, and hash a trailing odd node with itself. -/
def pairDup : List Hash → List Hash
  | [] => []
  | [x] => [Hash.node x x]
  | x :: y :: rest => Hash.node x y :: pairDup rest

def treeFuel (step : List Hash → List Hash) : Nat → List Hash → Hash
  | 0, _ => Hash.leaf 0
  | _ + 1, [] => Hash.leaf 0
  | _ + 1, [x] => x
  | n + 1, xs => treeFuel step n (step xs)

def treeOf (xs : List Hash) : Hash :=
  treeFuel pairPromote xs.length xs

def treeDup (xs : List Hash) : Hash :=
  treeFuel pairDup xs.length xs

def merkleRoot (xs : List Nat) : Hash :=
  let norm := normalize xs
  Hash.root norm.length (treeOf (norm.map Hash.leaf))

def dupRoot (xs : List Nat) : Hash :=
  treeDup (xs.map Hash.leaf)

/-! ### The root depends only on the normalized list -/

theorem count_is_length (xs : List Nat) :
    rootCount (merkleRoot xs) = (normalize xs).length := by
  rfl

theorem root_eq_of_eq_normalize (xs ys : List Nat) (h : normalize xs = normalize ys) :
    merkleRoot xs = merkleRoot ys := by
  simp [merkleRoot, h]

/-- Order and a repeated element do not change the root. -/
theorem order_and_duplicates_do_not_matter :
    merkleRoot [2, 1, 2, 0] = merkleRoot [0, 1, 2] := by
  rfl

theorem different_count (xs ys : List Nat)
    (h : (normalize xs).length ≠ (normalize ys).length) :
    merkleRoot xs ≠ merkleRoot ys := by
  intro eq
  apply h
  have hc := congrArg rootCount eq
  rw [count_is_length, count_is_length] at hc
  exact hc

/-- Two different sizes do not share a root. The count is what makes this
    immediate: the trees are not consulted. -/
theorem different_sizes_do_not_collide :
    merkleRoot [0, 1, 2] ≠ merkleRoot [0, 1, 2, 3] := by
  decide

/-! ### Duplication collides. Promotion does not. -/

/-- CVE-2012-2459, on the tree before the count is mixed in. -/
theorem duplicated_tail_collides :
    dupRoot [0, 1, 2] = dupRoot [0, 1, 2, 2] := by
  rfl

theorem promotion_separates_the_duplicated_tail :
    treeOf ([0, 1, 2].map Hash.leaf) ≠ treeOf ([0, 1, 2, 2].map Hash.leaf) := by
  decide

end NasTools
