//! Real OpenMLS 0.9.0 integration (spec 20.9).
//!
//! Exercises `QrngOpenMlsProvider` through the public OpenMLS group-creation API
//! and asserts that OpenMLS consumed `provider.rand()` as `POST /v1/entropy`.
//! Does not claim that randomness internal to `OpenMlsCrypto` is QRNG-backed.

mod common;

use std::sync::Arc;
use std::time::Duration;

use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use openmls::prelude::Ciphersuite;
use openmls_basic_credential::SignatureKeyPair;
use openmls_qrand::{
    ApiAuth, QrngClient, QrngConfig, QrngOpenMlsProvider, QrngRand, TransportMode,
};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use serde_json::json;

use common::TestServer;

fn plain_http_config(base_url: &str) -> QrngConfig {
    QrngConfig {
        base_url: base_url.parse().expect("valid URL"),
        transport: TransportMode::PlainHttp,
        auth: ApiAuth::None,
        entropy_type: None,
        request_timeout: Duration::from_secs(5),
        health_poll_interval: Some(Duration::from_secs(5)),
    }
}

fn valid_capabilities_json() -> serde_json::Value {
    json!({
        "entropy": {
            "min_block_size": 16,
            "max_block_size": 1024,
            "min_block_count": 2,
            "max_block_count": 8,
            "entropy_types": ["raw"]
        },
        "source_count": 2
    })
}

fn entropy_post_count(server: &TestServer) -> usize {
    server
        .recorded_requests()
        .into_iter()
        .filter(|req| {
            req.method.eq_ignore_ascii_case("POST")
                && (req.path == "/v1/entropy" || req.path.ends_with("/v1/entropy"))
        })
        .count()
}

#[test]
fn mls_group_new_invokes_qrng_entropy() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());

    let client = QrngClient::connect(plain_http_config(&server.origin())).expect("connect");
    let rand = QrngRand::new(Arc::new(client));
    let provider = QrngOpenMlsProvider::new(RustCrypto::default(), MemoryStorage::default(), rand);

    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    // SignatureKeyPair::new uses RustCrypto's internal RNG, not OpenMlsRand.
    let signer =
        SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("SignatureKeyPair::new");
    signer
        .store(provider.storage())
        .expect("store signature key pair");

    let credential = BasicCredential::new(b"alice".to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    let entropy_before = entropy_post_count(&server);
    assert_eq!(
        entropy_before, 0,
        "connect and signature-key generation must not POST /v1/entropy"
    );

    let group = MlsGroup::new(
        &provider,
        &signer,
        &mls_group_create_config,
        credential_with_key,
    )
    .expect("MlsGroup::new must succeed with QrngOpenMlsProvider");

    let entropy_after = entropy_post_count(&server);
    assert!(
        entropy_after > entropy_before,
        "MlsGroup::new must invoke POST /v1/entropy via OpenMlsRand; before={entropy_before} after={entropy_after}"
    );

    assert!(
        !group.group_id().as_slice().is_empty(),
        "created group must have a group ID"
    );
    assert_eq!(group.ciphersuite(), ciphersuite);
    assert_eq!(
        group.members().count(),
        1,
        "creator-only group must have one member"
    );
    assert!(group.is_active());
}
