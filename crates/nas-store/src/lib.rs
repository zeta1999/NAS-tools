//! Chunking, padding, blob storage and manifests (SPECS §4).
//!
//! Holds no keys and no network. It turns bytes into addressed, encrypted
//! blobs plus a manifest, and back again — the layer both the daemon and the
//! CLI sit on top of.

pub mod blobs;
pub mod bucket;
pub mod cache;
pub mod chunker;
pub mod manifest;
pub mod object;
pub mod padding;
pub mod root;
pub mod tree;

pub use blobs::{Addressing, BlobStore, StoreError};
pub use bucket::{BucketError, BucketManifest, BucketStore, KeyObject, BUCKET_AAD, BUCKET_MAGIC};
pub use cache::{CacheError, ChunkCache, CACHE_AAD, DEFAULT_CAP};
pub use chunker::{Chunker, ChunkerConfig, ConfigError};
pub use manifest::{ChunkRef, Kind, Manifest, ManifestError};
pub use object::{
    read_object, read_object_range, salted_addr, ObjectError, ObjectWriter, ReadStats, Sealer,
    CHUNK_AAD,
};
pub use padding::{pad, unpad, PadError, FIXED_CHUNK, FIXED_CLASS, HEADER, LADDER};
pub use root::{root_aad, RootError, RootManifest, ROOT_AAD};
pub use tree::{DirManifest, Entry, TreeError, TreeStore};
