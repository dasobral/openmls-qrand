//! `EntropyRng`: the backend as a `rand` 0.10 `TryCryptoRng`, for crypto backends that take
//! an entropy source.
//!
//! These tests use `MockEntropy`, a deterministic MOCK stream, not an entropy source.

#![cfg(feature = "mock")]

use std::sync::Arc;

use openmls_qrand::{EntropyBackend, EntropyRng, MockEntropy, QrngError};
use rand_core::TryRng;

#[test]
fn entropy_rng_yields_the_backend_stream() {
    let mut rng = EntropyRng::new(Arc::new(MockEntropy::new(7)));
    let mut drawn = [0u8; 48];
    rng.try_fill_bytes(&mut drawn).expect("mock draw");

    let expected = MockEntropy::new(7).fetch_entropy(48).expect("mock draw");
    assert_eq!(drawn.as_slice(), expected.as_slice());
}

#[test]
fn entropy_rng_fails_closed_during_an_outage() {
    let mock = Arc::new(MockEntropy::new(7));
    let mut rng = EntropyRng::new(Arc::clone(&mock));

    mock.set_available(false);
    let mut out = [0u8; 32];
    assert!(matches!(
        rng.try_fill_bytes(&mut out),
        Err(QrngError::EntropyUnavailable)
    ));
    assert!(matches!(
        rng.try_next_u64(),
        Err(QrngError::EntropyUnavailable)
    ));
    assert_eq!(out, [0u8; 32], "a refused draw writes nothing");
    assert_eq!(mock.metrics_snapshot().entropy_failures_total, 2);

    mock.set_available(true);
    rng.try_fill_bytes(&mut out).expect("draw after the outage");
}

#[test]
fn entropy_rng_does_not_fetch_for_an_empty_request() {
    let mock = Arc::new(MockEntropy::new(7));
    let mut rng = EntropyRng::new(Arc::clone(&mock));
    rng.try_fill_bytes(&mut []).expect("empty draw");
    assert_eq!(mock.metrics_snapshot().entropy_requests_total, 0);
}
