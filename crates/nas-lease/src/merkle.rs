//! The Merkle root a lease checkpoint commits to (SPECS §6.1).
//!
//! ```text
//! LeaseCheckpoint { holder_pk, epoch, root = merkle(sorted full set), count, prev, sig }
//! ```
//!
//! # Why the count is inside the root
//!
//! The textbook way to handle an odd level is to duplicate the last node. That
//! is the Bitcoin CVE-2012-2459 shape: a set and a *different* set whose tail is
//! repeated produce the same root, so "the root commits to the set" stops being
//! true. Promoting the odd node instead moves the ambiguity rather than
//! removing it — a one-element level and a promoted single node are still
//! indistinguishable.
//!
//! So the tree is built by promotion *and* the element count is hashed into the
//! final root. Two sets of different sizes then cannot collide however their
//! levels line up, which is checked directly in
//! [`tests::a_duplicated_tail_does_not_collide`].
//!
//! Leaves and interior nodes carry distinct tag bytes, so a leaf hash can never
//! be mistaken for an interior node — the other half of the same problem.

use nas_core::Addr;

const TAG_LEAF: u8 = 0x00;
const TAG_NODE: u8 = 0x01;
const TAG_ROOT: &[u8] = b"nas-tools/lease-merkle/v1";

fn leaf(a: &Addr) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[TAG_LEAF]);
    h.update(a.as_bytes());
    *h.finalize().as_bytes()
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[TAG_NODE]);
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

/// Root over a set of addresses.
///
/// The input is sorted and de-duplicated first, so the root is a function of
/// the *set* and not of the order a caller happened to accumulate it in. A
/// holder that added the same address twice must not get a different root from
/// one that added it once.
pub fn root(addrs: &[Addr]) -> [u8; 32] {
    let mut sorted: Vec<[u8; 32]> = addrs.iter().map(|a| *a.as_bytes()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let count = sorted.len() as u64;

    let mut level: Vec<[u8; 32]> = sorted.iter().map(|b| leaf(&Addr::from_bytes(*b))).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(node(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            // Promote, never duplicate. Duplication is the classic collision.
            next.push(level[i]);
        }
        level = next;
    }

    let tree = level.first().copied().unwrap_or([0u8; 32]);
    let mut h = blake3::Hasher::new();
    h.update(TAG_ROOT);
    h.update(&count.to_le_bytes());
    h.update(&tree);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn addr(n: u8) -> Addr {
        Addr::of_ciphertext(&[n])
    }

    #[test]
    fn order_does_not_matter() {
        // The root commits to a set. A holder that accumulated addresses in a
        // different order must publish the same checkpoint.
        let a: Vec<Addr> = (0..7).map(addr).collect();
        let mut b = a.clone();
        b.reverse();
        assert_eq!(root(&a), root(&b));
    }

    #[test]
    fn duplicates_do_not_matter() {
        let a: Vec<Addr> = (0..5).map(addr).collect();
        let mut b = a.clone();
        b.push(addr(3));
        b.push(addr(0));
        assert_eq!(root(&a), root(&b));
    }

    #[test]
    fn a_different_set_gives_a_different_root() {
        let a: Vec<Addr> = (0..5).map(addr).collect();
        let b: Vec<Addr> = (0..6).map(addr).collect();
        assert_ne!(root(&a), root(&b));
    }

    #[test]
    fn the_empty_set_has_its_own_root() {
        // Distinct from every non-empty set, and stable, so "I lease nothing"
        // is a statement a holder can actually make.
        let e = root(&[]);
        assert_eq!(e, root(&[]));
        for n in 1..8u8 {
            let s: Vec<Addr> = (0..n).map(addr).collect();
            assert_ne!(e, root(&s));
        }
    }

    #[test]
    fn a_duplicated_tail_does_not_collide() {
        // CVE-2012-2459 in miniature. With tail duplication, [a,b,c] and
        // [a,b,c,c] build identical trees. Here they must not -- and since
        // dedup would erase the second, the test uses distinct sets whose
        // levels line up the same way.
        for n in 1..24usize {
            let a: Vec<Addr> = (0..n as u8).map(addr).collect();
            let b: Vec<Addr> = (0..(n as u8 + 1)).map(addr).collect();
            assert_ne!(root(&a), root(&b), "sizes {n} and {} collide", n + 1);
        }
    }

    #[test]
    fn a_leaf_cannot_be_mistaken_for_an_interior_node() {
        // Without distinct tags, a caller who knew two leaf hashes could
        // present them as a set whose root was an interior node of another.
        let l = leaf(&addr(1));
        let n = node(&l, &l);
        assert_ne!(l, n);
    }

    #[test]
    fn one_element_and_two_elements_differ() {
        assert_ne!(root(&[addr(1)]), root(&[addr(1), addr(2)]));
    }

    proptest! {
        #[test]
        fn root_is_a_function_of_the_set(
            mut xs in proptest::collection::vec(any::<u8>(), 0..40),
            seed in any::<u64>()
        ) {
            let a: Vec<Addr> = xs.iter().copied().map(addr).collect();
            // A deterministic shuffle: no RNG, and the property is order
            // independence rather than any particular permutation.
            let n = xs.len();
            if n > 1 {
                for i in 0..n {
                    let j = ((seed as usize).wrapping_mul(i + 1)) % n;
                    xs.swap(i, j);
                }
            }
            let b: Vec<Addr> = xs.into_iter().map(addr).collect();
            prop_assert_eq!(root(&a), root(&b));
        }
    }
}
