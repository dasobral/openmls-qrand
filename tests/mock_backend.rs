//! `EntropyBackend` seam and the `mock` feature's `MockEntropy` backend.
//!
//! `MockEntropy` is a MOCK. Its bytes are a deterministic, seeded stream, predictable by
//! design. It exists so OpenMLS consumers can run their real provider wiring in
//! development and tests without a QRNG endpoint. Nothing here claims entropy quality.

#![cfg(feature = "mock")]

use std::sync::Arc;

use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use openmls::prelude::Ciphersuite;
use openmls_basic_credential::SignatureKeyPair;
use openmls_qrand::{
    EntropyBackend, MockEntropy, QrngClient, QrngError, QrngOpenMlsProvider, QrngRand,
};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;

fn mock_rand(seed: u64) -> (QrngRand<MockEntropy>, Arc<MockEntropy>) {
    let mock = Arc::new(MockEntropy::new(seed));
    (QrngRand::new(Arc::clone(&mock)), mock)
}

#[test]
fn mock_stream_is_deterministic_per_seed_and_does_not_repeat() {
    let (a, _) = mock_rand(7);
    let (b, _) = mock_rand(7);
    let (c, _) = mock_rand(8);

    let a1: [u8; 32] = a.random_array().expect("mock draw");
    let a2: [u8; 32] = a.random_array().expect("mock draw");
    let b1: [u8; 32] = b.random_array().expect("mock draw");
    let c1: [u8; 32] = c.random_array().expect("mock draw");

    assert_eq!(a1, b1, "the same seed must replay the same stream");
    assert_ne!(a1, c1, "different seeds must give different streams");
    assert_ne!(a1, a2, "successive draws must differ");
    assert_ne!(a1, [0u8; 32], "the stream must not be all zeros");

    // Draw sizes that are not a multiple of the internal word still continue the stream.
    let odd = a.random_vec(13).expect("mock draw");
    assert_eq!(odd.len(), 13);
    assert_ne!(&odd[..], &a2[..13]);
}

#[test]
fn mock_outage_fails_closed_without_substitute_bytes_and_recovers() {
    let (rand, mock) = mock_rand(3);
    let (reference, _) = mock_rand(3);
    let expected: [u8; 32] = reference.random_array().expect("reference draw");

    mock.set_available(false);
    assert!(matches!(
        rand.random_array::<32>(),
        Err(QrngError::EntropyUnavailable)
    ));
    assert!(matches!(
        rand.random_vec(16),
        Err(QrngError::EntropyUnavailable)
    ));
    let metrics = mock.metrics_snapshot();
    assert_eq!(metrics.entropy_failures_total, 2);
    assert_eq!(metrics.entropy_requests_total, 0);
    assert_eq!(metrics.entropy_bytes_total, 0);

    mock.set_available(true);
    let restored: [u8; 32] = rand.random_array().expect("draw after restore");
    assert_eq!(
        restored, expected,
        "a refused draw must not consume or substitute stream bytes"
    );
}

#[test]
fn mock_metrics_count_requests_and_bytes_like_the_client() {
    let (rand, mock) = mock_rand(1);
    rand.random_vec(32).expect("draw");
    rand.random_vec(16).expect("draw");
    assert_eq!(rand.random_vec(0).expect("empty draw"), Vec::<u8>::new());

    let metrics = mock.metrics_snapshot();
    assert_eq!(
        metrics.entropy_requests_total, 2,
        "an empty draw is not a request"
    );
    assert_eq!(metrics.entropy_bytes_total, 48);
    assert_eq!(metrics.entropy_failures_total, 0);
    assert_eq!(metrics.health_polls_total, 0);
}

#[test]
fn dyn_backend_selects_mock_or_client_at_run_time() {
    fn is_backend<B: EntropyBackend + ?Sized>() {}
    is_backend::<QrngClient>();
    is_backend::<MockEntropy>();
    is_backend::<dyn EntropyBackend>();

    let backend: Arc<dyn EntropyBackend> = Arc::new(MockEntropy::new(5));
    let rand: QrngRand<dyn EntropyBackend> = QrngRand::new(Arc::clone(&backend));
    let (typed, _) = mock_rand(5);
    assert_eq!(
        rand.random_array::<32>().expect("dyn draw"),
        typed.random_array::<32>().expect("typed draw")
    );
    assert_eq!(backend.metrics_snapshot().entropy_requests_total, 1);
}

fn create_group<P: OpenMlsProvider>(provider: &P) -> Result<MlsGroup, String> {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    // SignatureKeyPair::new uses RustCrypto's internal RNG, not OpenMlsRand.
    let signer =
        SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("SignatureKeyPair::new");
    signer
        .store(provider.storage())
        .expect("store signature key pair");
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(b"alice".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();
    MlsGroup::new(provider, &signer, &config, credential_with_key).map_err(|err| format!("{err:?}"))
}

#[test]
fn mls_group_new_draws_from_the_mock_backend_and_fails_closed_without_it() {
    let mock = Arc::new(MockEntropy::new(11));
    let backend: Arc<dyn EntropyBackend> = Arc::clone(&mock) as Arc<dyn EntropyBackend>;
    let provider: QrngOpenMlsProvider<RustCrypto, MemoryStorage, dyn EntropyBackend> =
        QrngOpenMlsProvider::new(
            RustCrypto::default(),
            MemoryStorage::default(),
            QrngRand::new(backend),
        );

    let group = create_group(&provider).expect("MlsGroup::new with the mock backend");
    assert_eq!(group.members().count(), 1);
    let metrics = mock.metrics_snapshot();
    assert!(
        metrics.entropy_requests_total > 0,
        "MlsGroup::new must draw through the mock backend"
    );

    // OpenMLS 0.9.2 panics ("Not enough randomness") when `GroupId::random` cannot draw,
    // instead of returning an error. Either outcome is fail-closed; a group is not.
    mock.set_available(false);
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| create_group(&provider)));
    assert!(
        !matches!(outcome, Ok(Ok(_))),
        "MlsGroup::new must fail closed while the backend is unavailable"
    );
    assert!(mock.metrics_snapshot().entropy_failures_total > 0);
    assert_eq!(
        mock.metrics_snapshot().entropy_requests_total,
        metrics.entropy_requests_total
    );
}
