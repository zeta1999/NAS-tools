//! Chunking, padding, blob storage and manifests (SPECS §4).
//!
//! Holds no keys and no network. It turns bytes into addressed, encrypted
//! blobs plus a manifest, and back again — the layer both the daemon and the
//! CLI sit on top of.

pub mod blobs;
pub mod chunker;
pub mod manifest;
pub mod object;
pub mod padding;
pub mod tree;

pub use blobs::{Addressing, BlobStore, StoreError};
pub use chunker::{Chunker, ChunkerConfig, ConfigError};
pub use manifest::{ChunkRef, Kind, Manifest, ManifestError};
pub use object::{read_object, salted_addr, ObjectError, ObjectWriter, Sealer, CHUNK_AAD};
pub use padding::{pad, unpad, PadError, FIXED_CHUNK, FIXED_CLASS, HEADER, LADDER};
pub use tree::{DirManifest, Entry, TreeError, TreeStore};
