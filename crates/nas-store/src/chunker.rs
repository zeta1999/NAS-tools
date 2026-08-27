//! Content-defined chunking, FastCDC (SPECS §4.2).
//!
//! # Why this is not a dependency
//!
//! The gear table and the masks are not implementation details — they are part
//! of the storage format. Two writers that disagree about them produce
//! different cut points for the same file, so every chunk address differs and
//! deduplication silently drops to zero against data already stored. A crate
//! that changed its table in a minor release would do exactly that, with no
//! error anywhere: the repository would simply start growing twice as fast.
//! A format constant belongs under version control with a golden test pinning
//! it, which is what [`tests::gear_table_is_pinned`] and
//! [`tests::cut_points_are_pinned`] are for.
//!
//! # Normalized chunking
//!
//! Plain CDC's chunk sizes are exponentially distributed: many tiny chunks,
//! some enormous ones. FastCDC's normalization uses a *harder* mask before the
//! average size is reached and an *easier* one after, concentrating the
//! distribution around the target. `NORMALIZATION = 2` is the level the paper
//! recommends.

use std::io::{self, Read};

/// Domain string for deriving the gear table. Changing it is a format break.
const GEAR_CONTEXT: &str = "NAS-tools 2026 gear table v1";

/// Bits of divergence between the two masks (FastCDC normalization level).
const NORMALIZATION: u32 = 2;

/// 256 pseudorandom words, derived rather than pasted so the table is
/// reproducible from the context string above and reviewable at a glance.
fn gear_table() -> [u64; 256] {
    let mut xof = blake3::Hasher::new_derive_key(GEAR_CONTEXT).finalize_xof();
    let mut buf = [0u8; 256 * 8];
    xof.fill(&mut buf);
    let mut t = [0u64; 256];
    for (i, w) in t.iter_mut().enumerate() {
        *w = u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
    }
    t
}

fn gear() -> &'static [u64; 256] {
    static T: std::sync::OnceLock<[u64; 256]> = std::sync::OnceLock::new();
    T.get_or_init(gear_table)
}

/// Chunker configuration.
///
/// The knob is read amplification: a 4 KiB read costs one whole chunk fetched,
/// verified and decrypted — 16× at a 64 KiB average, 256× at 1 MiB. Backup
/// workloads want large chunks; a mount wants small ones (SPECS §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkerConfig {
    pub min: usize,
    pub avg: usize,
    pub max: usize,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConfigError {
    /// `min <= avg <= max` is what makes the two-stage scan well defined.
    Unordered { min: usize, avg: usize, max: usize },
    /// The masks are built from `log2(avg)`, so a non-power-of-two average
    /// would silently round and produce a different distribution than asked for.
    AvgNotPowerOfTwo { avg: usize },
    /// `log2(avg) + NORMALIZATION` must stay inside a u64.
    AvgOutOfRange { avg: usize },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unordered { min, avg, max } => {
                write!(
                    f,
                    "chunk sizes must satisfy min<=avg<=max, got {min}/{avg}/{max}"
                )
            }
            Self::AvgNotPowerOfTwo { avg } => {
                write!(f, "average chunk size {avg} is not a power of two")
            }
            Self::AvgOutOfRange { avg } => write!(f, "average chunk size {avg} out of range"),
        }
    }
}
impl std::error::Error for ConfigError {}

impl Default for ChunkerConfig {
    /// SPECS §4.2 defaults: min 16 KiB / avg 64 KiB / max 256 KiB.
    fn default() -> Self {
        Self {
            min: 16 << 10,
            avg: 64 << 10,
            max: 256 << 10,
        }
    }
}

impl ChunkerConfig {
    /// The `large-object` profile for write-once bulk data (SPECS §4.2).
    pub fn large_object() -> Self {
        Self {
            min: 256 << 10,
            avg: 1 << 20,
            max: 4 << 20,
        }
    }

    /// Fixed-size cutting for [`nas_core::PaddingProfile::Fixed`]: no CDC at
    /// all, so there is no length fingerprint left to hide.
    pub fn fixed(size: usize) -> Self {
        Self {
            min: size,
            avg: size,
            max: size,
        }
    }

    /// A configuration whose maximum chunk is guaranteed to be paddable under
    /// `profile`.
    ///
    /// [`PaddingProfile::Fixed`] ignores `base` entirely — fixed cutting is the
    /// point of that profile. [`PaddingProfile::Classes`] clamps the maximum to
    /// the largest plaintext the top class can frame; without the clamp the
    /// default 256 KiB maximum collides with the 256 KiB top class.
    pub fn for_profile(profile: nas_core::PaddingProfile, base: Self) -> Self {
        match profile {
            nas_core::PaddingProfile::None => base,
            nas_core::PaddingProfile::Fixed => Self::fixed(crate::padding::FIXED_CHUNK),
            nas_core::PaddingProfile::Classes => {
                let cap = crate::padding::max_plaintext(profile).expect("Classes pads");
                let max = base.max.min(cap);
                Self {
                    min: base.min.min(max),
                    avg: base.avg.min(max),
                    max,
                }
            }
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !(self.min <= self.avg && self.avg <= self.max) || self.min == 0 {
            return Err(ConfigError::Unordered {
                min: self.min,
                avg: self.avg,
                max: self.max,
            });
        }
        // Fixed cutting never evaluates a mask, so the power-of-two constraint
        // -- which exists only so log2(avg) is exact -- does not apply to it.
        if self.min != self.max {
            if !self.avg.is_power_of_two() {
                return Err(ConfigError::AvgNotPowerOfTwo { avg: self.avg });
            }
            if self.avg.trailing_zeros() + NORMALIZATION >= 64 {
                return Err(ConfigError::AvgOutOfRange { avg: self.avg });
            }
        }
        Ok(())
    }
}

/// A validated chunker.
#[derive(Clone, Debug)]
pub struct Chunker {
    cfg: ChunkerConfig,
    /// Harder mask, used before `avg` — makes an early cut less likely.
    mask_s: u64,
    /// Easier mask, used after `avg` — makes a late cut more likely.
    mask_l: u64,
    fixed: bool,
}

impl Chunker {
    pub fn new(cfg: ChunkerConfig) -> Result<Self, ConfigError> {
        cfg.validate()?;
        // Meaningless for fixed cutting, and unused there.
        let bits = cfg.avg.trailing_zeros().min(63);
        Ok(Self {
            cfg,
            mask_s: mask(bits + NORMALIZATION),
            mask_l: mask(bits - NORMALIZATION.min(bits)),
            fixed: cfg.min == cfg.max,
        })
    }

    pub fn config(&self) -> ChunkerConfig {
        self.cfg
    }

    /// Length of the next chunk at the start of `buf`.
    ///
    /// `buf` must hold either at least `max` bytes or the whole remaining
    /// input; a shorter buffer would cut early and produce boundaries that
    /// depend on the *reader's* buffering rather than the content.
    pub fn cut(&self, buf: &[u8]) -> usize {
        if self.fixed {
            return buf.len().min(self.cfg.max);
        }
        let n = buf.len().min(self.cfg.max);
        if n <= self.cfg.min {
            return n;
        }
        let g = gear();
        let mut fp: u64 = 0;
        let mut i = self.cfg.min;

        // Stage one: the harder mask, up to the average.
        let normal = n.min(self.cfg.avg);
        while i < normal {
            fp = (fp << 1).wrapping_add(g[buf[i] as usize]);
            if fp & self.mask_s == 0 {
                return i + 1;
            }
            i += 1;
        }
        // Stage two: the easier mask, up to the maximum.
        while i < n {
            fp = (fp << 1).wrapping_add(g[buf[i] as usize]);
            if fp & self.mask_l == 0 {
                return i + 1;
            }
            i += 1;
        }
        n
    }

    /// Chunk an in-memory slice.
    pub fn split<'a>(&'a self, data: &'a [u8]) -> Split<'a> {
        Split {
            ch: self,
            rest: data,
        }
    }

    /// Chunk a reader using a bounded window.
    ///
    /// Peak resident bytes are `2 × max` regardless of input size — 512 KiB at
    /// the default profile. The whole-file alternative is what makes naive
    /// backup tools unusable on a NAS-sized corpus.
    pub fn stream<R: Read>(&self, reader: R) -> Stream<R> {
        Stream {
            ch: self.clone(),
            reader,
            buf: Vec::with_capacity(self.cfg.max * 2),
            start: 0,
            eof: false,
        }
    }
}

fn mask(bits: u32) -> u64 {
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Iterator over the chunks of a slice.
pub struct Split<'a> {
    ch: &'a Chunker,
    rest: &'a [u8],
}

impl<'a> Iterator for Split<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.rest.is_empty() {
            return None;
        }
        let n = self.ch.cut(self.rest);
        debug_assert!(n > 0, "a zero-length cut would loop forever");
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Some(head)
    }
}

/// Iterator over the chunks of a reader, bounded memory.
pub struct Stream<R> {
    ch: Chunker,
    reader: R,
    buf: Vec<u8>,
    start: usize,
    eof: bool,
}

impl<R: Read> Stream<R> {
    /// Drop consumed bytes and top the window back up to `2 × max`.
    fn refill(&mut self) -> io::Result<()> {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let want = self.ch.cfg.max * 2;
        let mut tmp = [0u8; 64 << 10];
        while !self.eof && self.buf.len() < want {
            let n = self.reader.read(&mut tmp)?;
            if n == 0 {
                self.eof = true;
                break;
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    }
}

impl<R: Read> Iterator for Stream<R> {
    type Item = io::Result<Vec<u8>>;
    fn next(&mut self) -> Option<io::Result<Vec<u8>>> {
        // Only refill when the window can no longer guarantee a content-defined
        // cut: fewer than `max` bytes left and more still to read.
        if !self.eof && self.buf.len() - self.start < self.ch.cfg.max {
            if let Err(e) = self.refill() {
                return Some(Err(e));
            }
        }
        let avail = &self.buf[self.start..];
        if avail.is_empty() {
            return None;
        }
        let n = self.ch.cut(avail);
        let chunk = avail[..n].to_vec();
        self.start += n;
        Some(Ok(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(n: usize, seed: u8) -> Vec<u8> {
        // Deterministic pseudo-random bytes; blake3 XOF keeps the test stable
        // across platforms, which a `rand` thread RNG would not.
        let mut out = vec![0u8; n];
        blake3::Hasher::new_keyed(&[seed; 32])
            .finalize_xof()
            .fill(&mut out);
        out
    }

    fn dflt() -> Chunker {
        Chunker::new(ChunkerConfig::default()).unwrap()
    }

    #[test]
    fn gear_table_is_pinned() {
        // A format constant. If this changes, every chunk boundary in every
        // existing repository moves and dedup silently drops to zero.
        let g = gear_table();
        assert_eq!(g[0], 11247554160543536310);
        assert_eq!(g[255], 11547447256838634055);
    }

    #[test]
    fn cut_points_are_pinned() {
        let sizes: Vec<usize> = dflt().split(&corpus(1 << 20, 1)).map(|c| c.len()).collect();
        assert_eq!(sizes.iter().sum::<usize>(), 1 << 20);
        assert_eq!(&sizes[..4], &[83553, 74390, 21730, 80539]);
    }

    #[test]
    fn every_chunk_respects_min_and_max() {
        let cfg = ChunkerConfig::default();
        let data = corpus(4 << 20, 2);
        let ch = dflt();
        let chunks: Vec<_> = ch.split(&data).collect();
        for (i, c) in chunks.iter().enumerate() {
            assert!(c.len() <= cfg.max, "chunk {i} of {} B exceeds max", c.len());
            if i + 1 < chunks.len() {
                assert!(c.len() >= cfg.min, "chunk {i} of {} B below min", c.len());
            }
        }
    }

    #[test]
    fn chunks_reassemble_into_the_original() {
        let data = corpus(3 << 20, 3);
        let joined: Vec<u8> = dflt().split(&data).flatten().copied().collect();
        assert_eq!(joined, data);
    }

    #[test]
    fn streaming_and_slicing_agree() {
        // The whole point of a bounded window is that it changes nothing. If
        // these diverge, chunk boundaries depend on the reader's buffering and
        // dedup breaks between a streamed write and an in-memory one.
        let data = corpus(5 << 20, 4);
        let a: Vec<Vec<u8>> = dflt().split(&data).map(|c| c.to_vec()).collect();
        let b: Vec<Vec<u8>> = dflt().stream(&data[..]).map(|r| r.unwrap()).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn streaming_agrees_across_reader_chunk_sizes() {
        struct Dribble<'a>(&'a [u8], usize);
        impl Read for Dribble<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let n = self.0.len().min(out.len()).min(self.1);
                out[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let data = corpus(1 << 20, 5);
        let want: Vec<Vec<u8>> = dflt().split(&data).map(|c| c.to_vec()).collect();
        for step in [1usize, 7, 4096, 100_000] {
            let got: Vec<Vec<u8>> = dflt()
                .stream(Dribble(&data, step))
                .map(|r| r.unwrap())
                .collect();
            assert_eq!(got, want, "reader delivering {step} B at a time");
        }
    }

    #[test]
    fn an_insertion_only_disturbs_chunks_near_it() {
        // The property CDC exists for. Fixed-size chunking would shift every
        // subsequent boundary and re-upload the whole file.
        let base = corpus(2 << 20, 6);
        let mut edited = base.clone();
        edited.splice(1000..1000, [0xFFu8; 5]);

        let a: Vec<Vec<u8>> = dflt().split(&base).map(|c| c.to_vec()).collect();
        let b: Vec<Vec<u8>> = dflt().stream(&edited[..]).map(|r| r.unwrap()).collect();

        let shared = a.iter().filter(|c| b.contains(c)).count();
        assert!(
            shared * 10 >= a.len() * 8,
            "only {shared}/{} chunks survived a 5-byte insertion",
            a.len()
        );
    }

    #[test]
    fn fixed_mode_cuts_at_exactly_the_configured_size() {
        let ch = Chunker::new(ChunkerConfig::fixed(1000)).unwrap();
        let sizes: Vec<usize> = ch.split(&corpus(3500, 7)).map(|c| c.len()).collect();
        assert_eq!(sizes, vec![1000, 1000, 1000, 500]);
    }

    #[test]
    fn short_inputs_are_a_single_chunk() {
        for n in [0usize, 1, 100, (16 << 10) - 1] {
            let data = corpus(n, 8);
            let ch = dflt();
            let chunks: Vec<_> = ch.split(&data).collect();
            assert_eq!(chunks.len(), usize::from(n > 0), "{n} bytes");
            let streamed: Vec<_> = dflt().stream(&data[..]).map(|r| r.unwrap()).collect();
            assert_eq!(streamed.len(), usize::from(n > 0), "{n} bytes streamed");
        }
    }

    #[test]
    fn for_profile_produces_a_paddable_maximum() {
        use crate::padding::{max_plaintext, pad};
        use nas_core::PaddingProfile;
        for profile in [
            PaddingProfile::None,
            PaddingProfile::Classes,
            PaddingProfile::Fixed,
        ] {
            let cfg = ChunkerConfig::for_profile(profile, ChunkerConfig::default());
            Chunker::new(cfg).expect("for_profile must produce a valid config");
            if let Some(cap) = max_plaintext(profile) {
                assert!(cfg.max <= cap, "{profile:?}: max {} exceeds {cap}", cfg.max);
                // The chunk that would have failed with the unclamped default.
                assert!(pad(profile, &vec![0u8; cfg.max]).is_ok());
            }
        }
    }

    #[test]
    fn bad_configs_are_refused_not_silently_rounded() {
        assert!(matches!(
            Chunker::new(ChunkerConfig {
                min: 100,
                avg: 50,
                max: 200
            }),
            Err(ConfigError::Unordered { .. })
        ));
        assert!(matches!(
            Chunker::new(ChunkerConfig {
                min: 10,
                avg: 100,
                max: 200
            }),
            Err(ConfigError::AvgNotPowerOfTwo { .. })
        ));
        assert!(matches!(
            Chunker::new(ChunkerConfig {
                min: 0,
                avg: 64,
                max: 200
            }),
            Err(ConfigError::Unordered { .. })
        ));
    }

    #[test]
    fn average_chunk_size_is_near_the_target() {
        let data = corpus(8 << 20, 9);
        let ch = dflt();
        let chunks: Vec<_> = ch.split(&data).collect();
        let avg = data.len() / chunks.len();
        let target = ChunkerConfig::default().avg;
        assert!(
            avg > target / 2 && avg < target * 2,
            "average chunk {avg} B is far from the {target} B target"
        );
    }
}
