//! Live Entropy Core MLS smoke tests.
//!
//! Not run in the default suite. Requires a reachable QRNG Open API:
//!
//! ```text
//! QRNG_LIVE_BASE_URL=http://192.168.76.25:443 \
//! cargo test --test live_ec_mls -- --ignored --nocapture
//! ```
//!
//! Hits Entropy Core routes `GET /capabilities`, `POST /entropy`, and
//! `GET /healthtest` (no `/v1` or `/api` prefix).

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls::framing::{MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent};
use openmls::group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::prelude::Ciphersuite;
use openmls_basic_credential::SignatureKeyPair;
use openmls_qrand::{
    ApiAuth, QrngClient, QrngConfig, QrngOpenMlsProvider, QrngRand, TransportMode,
};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

type LiveProvider = QrngOpenMlsProvider<RustCrypto, MemoryStorage>;

fn live_config() -> QrngConfig {
    let base_url = env::var("QRNG_LIVE_BASE_URL").expect(
        "QRNG_LIVE_BASE_URL is required for --ignored live tests \
         (example: http://192.168.76.25:443)",
    );
    let parsed: reqwest::Url = base_url
        .parse()
        .expect("QRNG_LIVE_BASE_URL must be a valid URL");
    let transport = match parsed.scheme() {
        "http" => TransportMode::PlainHttp,
        "https" => TransportMode::Tls {
            ca_cert_pem: env::var("QRNG_LIVE_CA_CERT").ok().map(PathBuf::from),
        },
        other => panic!("unsupported URL scheme {other}"),
    };
    QrngConfig {
        base_url: parsed,
        transport,
        auth: ApiAuth::None,
        entropy_type: None,
        request_timeout: Duration::from_secs(15),
        health_poll_interval: Some(Duration::from_secs(5)),
    }
}

fn make_provider(client: &Arc<QrngClient>) -> LiveProvider {
    QrngOpenMlsProvider::new(
        RustCrypto::default(),
        MemoryStorage::default(),
        QrngRand::new(Arc::clone(client)),
    )
}

fn credential_and_signer(
    identity: &[u8],
    ciphersuite: Ciphersuite,
    provider: &LiveProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("signature key");
    signer
        .store(provider.storage())
        .expect("store signature key");
    let credential = BasicCredential::new(identity.to_vec());
    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        },
        signer,
    )
}

#[test]
#[ignore = "requires a live Entropy Core (QRNG_LIVE_BASE_URL)"]
fn live_connect_and_fetch_entropy() {
    let client = QrngClient::connect(live_config()).expect("connect to live QRNG Open API");
    let caps = client.capabilities();
    println!(
        "capabilities: min_block_size={} max_block_size={} types={:?}",
        caps.entropy.min_block_size, caps.entropy.max_block_size, caps.entropy.entropy_types
    );
    assert!(caps.entropy.min_block_size >= 1);
    assert!(caps.entropy.max_block_size >= caps.entropy.min_block_size);

    let bytes = client.fetch_entropy(32).expect("fetch 32 entropy bytes");
    assert_eq!(bytes.len(), 32);
    assert!(
        bytes.iter().any(|&b| b != 0),
        "entropy block must not be all zeros"
    );

    match client.fetch_health() {
        Ok(report) => {
            assert!(
                !report.test_result.is_empty(),
                "live GET /healthtest must return at least one test_result"
            );
            println!(
                "healthtest: {} result(s), {} extension(s), time_stamp={:?}",
                report.test_result.len(),
                report.extensions.len(),
                report.test_result[0].time_stamp
            );
        }
        Err(err) => panic!("live GET /healthtest must parse: {err}"),
    }

    let metrics = client.metrics_snapshot();
    assert_eq!(metrics.entropy_requests_total, 1);
    assert_eq!(metrics.entropy_bytes_total, 32);
    assert_eq!(metrics.entropy_failures_total, 0);
}

#[test]
#[ignore = "requires a live Entropy Core (QRNG_LIVE_BASE_URL)"]
fn live_mls_single_member_group() {
    let client = Arc::new(QrngClient::connect(live_config()).expect("connect"));
    let provider = make_provider(&client);
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let (credential_with_key, signer) = credential_and_signer(b"alice", ciphersuite, &provider);
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    let before = client.metrics_snapshot().entropy_requests_total;
    let group = MlsGroup::new(&provider, &signer, &config, credential_with_key)
        .expect("MlsGroup::new against live QRNG");
    let after = client.metrics_snapshot().entropy_requests_total;

    assert!(
        after > before,
        "group creation must consume QRNG entropy; before={before} after={after}"
    );
    assert!(group.is_active());
    assert_eq!(group.members().count(), 1);
    assert_eq!(group.ciphersuite(), ciphersuite);
    println!(
        "single-member group ok; entropy_requests {before} -> {after}; group_id_len={}",
        group.group_id().as_slice().len()
    );
}

#[test]
#[ignore = "requires a live Entropy Core (QRNG_LIVE_BASE_URL)"]
fn live_mls_two_party_group_and_message() {
    let client = Arc::new(QrngClient::connect(live_config()).expect("connect"));
    let alice_provider = make_provider(&client);
    let bob_provider = make_provider(&client);
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let (alice_cred, alice_signer) = credential_and_signer(b"alice", ciphersuite, &alice_provider);
    let (bob_cred, bob_signer) = credential_and_signer(b"bob", ciphersuite, &bob_provider);

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .build();

    let mut alice_group = MlsGroup::new(&alice_provider, &alice_signer, &create_config, alice_cred)
        .expect("alice MlsGroup::new");

    let bob_key_package = KeyPackage::builder()
        .build(ciphersuite, &bob_provider, &bob_signer, bob_cred)
        .expect("bob KeyPackage");

    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            &alice_provider,
            &alice_signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .expect("alice add_members(bob)");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("alice merge add commit");

    let welcome_in: MlsMessageIn = welcome.into();
    let welcome = match welcome_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        other => panic!("expected Welcome, got {other:?}"),
    };
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("bob staged welcome")
    .into_group(&bob_provider)
    .expect("bob join group");

    assert_eq!(alice_group.members().count(), 2);
    assert_eq!(bob_group.members().count(), 2);
    assert_eq!(
        alice_group.export_ratchet_tree(),
        bob_group.export_ratchet_tree()
    );

    let plaintext = b"hello from alice, via QRNG-backed MLS";
    let encrypted = alice_group
        .create_message(&alice_provider, &alice_signer, plaintext)
        .expect("alice create_message");
    let encrypted_in: MlsMessageIn = encrypted.into();
    let processed = bob_group
        .process_message(
            &bob_provider,
            encrypted_in
                .try_into_protocol_message()
                .expect("protocol message"),
        )
        .expect("bob process_message");
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            assert_eq!(message.into_bytes(), plaintext);
        }
        other => panic!("expected application message, got {other:?}"),
    }

    let metrics = client.metrics_snapshot();
    assert!(
        metrics.entropy_requests_total > 0,
        "two-party MLS must have fetched QRNG entropy"
    );
    assert_eq!(metrics.entropy_failures_total, 0);
    println!(
        "two-party MLS ok; entropy_requests={} entropy_bytes={}",
        metrics.entropy_requests_total, metrics.entropy_bytes_total
    );
}
