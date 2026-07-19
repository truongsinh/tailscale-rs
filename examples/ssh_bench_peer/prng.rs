//! Deterministic payload generator shared by `ssh_bench_peer` and `ssh_bench`.
//!
//! xorshift64* seeded stream; the byte stream is the successive `u64` outputs in
//! little-endian order. Both ends of a transfer construct the same stream from the
//! same seed, so integrity is verified without shipping the expected bytes.
//!
//! Included verbatim (via `#[path]`) from both example binaries and the
//! `bench_harness` integration test — one implementation, cross-checked by a
//! fixed fixture in the test.

/// xorshift64* generator (Vigna). Period 2^64-1; state must never be zero, so a
/// zero seed is remapped to a fixed odd constant.
pub struct XorShift64Star {
    state: u64,
}

impl XorShift64Star {
    /// Create a generator from `seed` (zero is remapped — see type docs).
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    /// Next 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Byte-stream view over [`XorShift64Star`]: fills buffers of ANY length with the
/// canonical stream (successive `u64`s little-endian), carrying leftover bytes
/// across calls so chunk boundaries never change the stream.
pub struct PrngStream {
    rng: XorShift64Star,
    leftover: [u8; 8],
    /// Number of still-unconsumed bytes at the END of `leftover`.
    leftover_len: usize,
}

impl PrngStream {
    /// Create a byte stream from `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: XorShift64Star::new(seed),
            leftover: [0; 8],
            leftover_len: 0,
        }
    }

    /// Fill `out` entirely with the next bytes of the stream.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut pos = 0;
        // Drain leftover from a previous partial u64 first.
        while self.leftover_len > 0 && pos < out.len() {
            out[pos] = self.leftover[8 - self.leftover_len];
            self.leftover_len -= 1;
            pos += 1;
        }
        // Whole u64s.
        while out.len() - pos >= 8 {
            out[pos..pos + 8].copy_from_slice(&self.rng.next_u64().to_le_bytes());
            pos += 8;
        }
        // Final partial u64: stash the tail for the next call.
        if pos < out.len() {
            let word = self.rng.next_u64().to_le_bytes();
            let take = out.len() - pos;
            out[pos..].copy_from_slice(&word[..take]);
            self.leftover.copy_from_slice(&word);
            // Rotate so unconsumed bytes sit at the end (consumed from index 8-len).
            self.leftover_len = 8 - take;
        }
    }
}
