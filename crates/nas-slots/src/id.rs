//! Slot and writer identifiers (SPECS §5).

use nas_crypto::key_id;

/// `slot_id = BLAKE3(namespace_pk ‖ label)` (SPECS §5).
///
/// Derived rather than chosen, so two namespaces cannot collide on a label and
/// a peer holding many tenants' slots cannot be tricked into serving one
/// tenant's slot for another's request.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId([u8; 32]);

impl SlotId {
    pub fn new(namespace_pk: &[u8], label: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        // Length-prefixed, so ("ab", "c") and ("a", "bc") cannot collide -- the
        // same concatenation ambiguity `encFields_inj` rules out for signatures.
        h.update(&(namespace_pk.len() as u64).to_le_bytes());
        h.update(namespace_pk);
        h.update(label);
        Self(*h.finalize().as_bytes())
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SlotId({}…)", &self.to_hex()[..12])
    }
}

/// `BLAKE3(verifying_key)` — what a record carries instead of a 1952-byte key.
///
/// A roster maps this back to the key. Records already spend 3309 bytes on a
/// signature (SPECS §3.8); repeating the key the roster holds would nearly
/// double every record for nothing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WriterId([u8; 32]);

impl WriterId {
    pub fn of_key(verifying_key: &[u8]) -> Self {
        Self(key_id(verifying_key))
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl std::fmt::Debug for WriterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WriterId({}…)", &self.to_hex()[..12])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_ids_are_label_and_namespace_separated() {
        let a = SlotId::new(b"ns-a", b"refs/heads/main");
        let b = SlotId::new(b"ns-b", b"refs/heads/main");
        let c = SlotId::new(b"ns-a", b"refs/heads/dev");
        assert_ne!(a, b, "two namespaces collided on one label");
        assert_ne!(a, c);
    }

    #[test]
    fn the_namespace_label_boundary_is_unambiguous() {
        // Without the length prefix, ("ab","c") and ("a","bc") would be the
        // same bytes -- one tenant could pick a label that made their slot id
        // equal another tenant's.
        assert_ne!(SlotId::new(b"ab", b"c"), SlotId::new(b"a", b"bc"));
    }

    #[test]
    fn writer_ids_follow_the_key() {
        let a = WriterId::of_key(&[1u8; 1952]);
        let b = WriterId::of_key(&[2u8; 1952]);
        assert_ne!(a, b);
        assert_eq!(a, WriterId::of_key(&[1u8; 1952]));
    }

    #[test]
    fn debug_is_abbreviated() {
        let s = format!("{:?}", SlotId::new(b"ns", b"l"));
        assert!(s.len() < 32, "{s}");
    }
}
