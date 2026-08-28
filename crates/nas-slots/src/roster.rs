//! Who may write (SPECS §5, §10).
//!
//! Records carry a 32-byte [`WriterId`] rather than a 1952-byte key, so
//! verifying one needs a map back to the key. That map is the roster.
//!
//! At M1 this is an in-memory map built by the client from its vault. The
//! *signed, slot-chained, plaintext* roster the peer serves — and the leak that
//! comes with it being plaintext — is SPECS §10 and lands with `nas-peer`.

use crate::id::WriterId;
use nas_crypto::VERIFYING_KEY_LEN;
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub enum RosterError {
    BadKeyLength {
        got: usize,
    },
    /// Two entries for one writer. A roster that could hold two keys for one id
    /// would make "which key verifies this record" ambiguous.
    Duplicate {
        id: WriterId,
    },
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadKeyLength { got } => {
                write!(f, "verifying key is {got} B, want {VERIFYING_KEY_LEN} B")
            }
            Self::Duplicate { id } => write!(f, "roster already holds {id:?}"),
        }
    }
}
impl std::error::Error for RosterError {}

/// The set of keys permitted to write a slot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Roster {
    keys: BTreeMap<WriterId, Vec<u8>>,
}

impl Roster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a verifying key. The id is *derived*, never supplied, so a roster
    /// cannot file a key under an id that is not its own.
    pub fn add(&mut self, verifying_key: &[u8]) -> Result<WriterId, RosterError> {
        if verifying_key.len() != VERIFYING_KEY_LEN {
            return Err(RosterError::BadKeyLength {
                got: verifying_key.len(),
            });
        }
        let id = WriterId::of_key(verifying_key);
        if self.keys.contains_key(&id) {
            return Err(RosterError::Duplicate { id });
        }
        self.keys.insert(id, verifying_key.to_vec());
        Ok(id)
    }

    pub fn get(&self, id: &WriterId) -> Option<&[u8]> {
        self.keys.get(id).map(|v| v.as_slice())
    }

    pub fn contains(&self, id: &WriterId) -> bool {
        self.keys.contains_key(id)
    }

    /// Remove a writer — SPECS §3.9's roster-removal revocation path.
    ///
    /// Removal stops *future* records from verifying. It cannot un-sign the
    /// past: records the removed writer already published still carry a valid
    /// signature, which is why §3.9 keeps roster removal, peer blocking and
    /// `CS` rotation as three separate paths rather than one.
    pub fn remove(&mut self, id: &WriterId) -> bool {
        self.keys.remove(id).is_some()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn ids(&self) -> impl Iterator<Item = &WriterId> {
        self.keys.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nas_crypto::{Identity, Role};

    fn ident(seed: u8) -> Identity {
        Identity::derive(&[seed; 32], Role::Slot).unwrap()
    }

    #[test]
    fn add_then_look_up() {
        let mut r = Roster::new();
        let id = ident(1);
        let w = r.add(id.verifying_key()).unwrap();
        assert_eq!(r.get(&w).unwrap(), id.verifying_key());
        assert!(r.contains(&w));
    }

    #[test]
    fn the_id_is_derived_not_supplied() {
        // A roster that let a caller choose the id could file writer A's key
        // under writer B's id, and every record B ever signed would then be
        // verified against A's key.
        let mut r = Roster::new();
        let a = ident(1);
        let w = r.add(a.verifying_key()).unwrap();
        assert_eq!(w, WriterId::of_key(a.verifying_key()));
    }

    #[test]
    fn duplicates_are_refused() {
        let mut r = Roster::new();
        let a = ident(1);
        r.add(a.verifying_key()).unwrap();
        assert!(matches!(
            r.add(a.verifying_key()),
            Err(RosterError::Duplicate { .. })
        ));
    }

    #[test]
    fn a_wrong_length_key_is_refused() {
        let mut r = Roster::new();
        assert_eq!(
            r.add(&[0u8; 32]),
            Err(RosterError::BadKeyLength { got: 32 })
        );
    }

    #[test]
    fn removal_affects_only_lookups() {
        let mut r = Roster::new();
        let a = ident(1);
        let w = r.add(a.verifying_key()).unwrap();
        assert!(r.remove(&w));
        assert!(!r.contains(&w));
        assert!(!r.remove(&w), "removing twice must report nothing removed");
    }
}
