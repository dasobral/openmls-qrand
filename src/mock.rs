//! A deterministic in-process [`EntropyBackend`] for development and tests.
//!
//! **`MockEntropy` is a MOCK, not an entropy source.** Its bytes come from a seeded
//! SplitMix64 counter stream: anyone who knows the seed can predict every byte. It lets
//! an application run its real `QrngRand` / `QrngOpenMlsProvider` wiring without a QRNG
//! endpoint. It is compiled only with the `mock` feature, and it is never used as a
//! fallback: a consumer gets it only by constructing it explicitly.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::backend::EntropyBackend;
use crate::error::QrngError;
use crate::health::ProviderMetricsSnapshot;

/// Deterministic, seeded mock backend. NOT random.
pub struct MockEntropy {
    /// SplitMix64 state. A draw holds the lock for its whole length, so concurrent
    /// draws never interleave inside one result.
    state: Mutex<u64>,
    available: AtomicBool,
    requests: AtomicU64,
    bytes: AtomicU64,
    failures: AtomicU64,
}

impl MockEntropy {
    /// A mock stream for `seed`. The same seed always replays the same bytes.
    pub fn new(seed: u64) -> Self {
        Self {
            state: Mutex::new(seed),
            available: AtomicBool::new(true),
            requests: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }

    /// Simulates an outage (`false`) or its end (`true`). While unavailable, every
    /// non-empty draw fails with [`QrngError::EntropyUnavailable`] and consumes nothing.
    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::SeqCst);
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

impl EntropyBackend for MockEntropy {
    fn fetch_entropy(&self, len: usize) -> Result<Vec<u8>, QrngError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        if !self.available.load(Ordering::SeqCst) {
            self.failures.fetch_add(1, Ordering::Relaxed);
            return Err(QrngError::EntropyUnavailable);
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let word = splitmix64(&mut state).to_be_bytes();
            let take = word.len().min(len - out.len());
            out.extend_from_slice(&word[..take]);
        }
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
        Ok(out)
    }

    fn metrics_snapshot(&self) -> ProviderMetricsSnapshot {
        ProviderMetricsSnapshot {
            entropy_requests_total: self.requests.load(Ordering::Relaxed),
            entropy_bytes_total: self.bytes.load(Ordering::Relaxed),
            entropy_failures_total: self.failures.load(Ordering::Relaxed),
            health_polls_total: 0,
            health_poll_failures_total: 0,
        }
    }
}
