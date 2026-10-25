//! Post quantum TLS key exchange contract tests.
//!
//! Every TLS and mTLS connection to the QRNG Open API carries the entropy that keys are
//! derived from. An attacker who records it today and breaks the key exchange later
//! recovers those keys, so the client negotiates the hybrid group `X25519MLKEM768`
//! (ML-KEM-768 with X25519). `KeyExchange::PostQuantumOnly`, the default, offers only
//! that group; `KeyExchange::PostQuantumPreferred` offers it first and accepts a
//! classical group from a server that has no post quantum group.

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use openmls_qrand::{
    ApiAuth, KeyExchange, NegotiatedKeyExchange, QrngClient, QrngConfig, QrngError, TransportMode,
};
use serde_json::json;

use common::test_server::{IssuedIdentity, ServerGroups, ServerSan, TestCa};
use common::TestServer;

const HYBRID: &str = "X25519MLKEM768";

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

fn config(base_url: &str, transport: TransportMode, key_exchange: KeyExchange) -> QrngConfig {
    QrngConfig {
        base_url: base_url.parse().expect("valid URL"),
        transport,
        auth: ApiAuth::None,
        entropy_type: None,
        request_timeout: Duration::from_secs(5),
        health_poll_interval: Some(Duration::from_secs(5)),
        key_exchange,
    }
}

struct PemScratch {
    dir: PathBuf,
}

impl PemScratch {
    fn new() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "openmls-qrng-pq-tls-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("temp pem dir");
        Self { dir }
    }

    fn write(&self, name: &str, pem: &str) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, pem).expect("write pem");
        path
    }
}

impl Drop for PemScratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn tls(scratch: &PemScratch, ca: &TestCa) -> TransportMode {
    TransportMode::Tls {
        ca_cert_pem: Some(scratch.write("ca.pem", &ca.cert_pem)),
    }
}

fn serve(server_id: &IssuedIdentity, groups: ServerGroups) -> TestServer {
    let server = TestServer::start_tls_with_groups(server_id, groups);
    server.set_capabilities_json(valid_capabilities_json());
    server
}

fn assert_all_hybrid(server: &TestServer) {
    let groups = server.negotiated_groups();
    assert!(!groups.is_empty(), "at least one TLS connection was made");
    assert!(groups.iter().all(|group| group == HYBRID), "{groups:?}");
}

#[test]
fn the_default_key_exchange_is_post_quantum_only() {
    assert_eq!(KeyExchange::default(), KeyExchange::PostQuantumOnly);
}

#[test]
fn tls_negotiates_the_hybrid_group_and_fetches_entropy() {
    let ca = TestCa::generate("pq-tls-ca");
    let server = serve(
        &ca.issue_server(ServerSan::LoopbackIp),
        ServerGroups::Default,
    );
    let scratch = PemScratch::new();
    let client = QrngClient::connect(config(
        &server.origin(),
        tls(&scratch, &ca),
        KeyExchange::default(),
    ))
    .expect("post quantum TLS connect");
    let entropy = client
        .fetch_entropy(32)
        .expect("entropy over post quantum TLS");
    assert_eq!(entropy.len(), 32);
    assert_all_hybrid(&server);
}

#[test]
fn mtls_negotiates_the_hybrid_group() {
    let ca = TestCa::generate("pq-mtls-ca");
    let server_id = ca.issue_server(ServerSan::LoopbackIp);
    let client_id = ca.issue_client("pq-client");
    let server = TestServer::start_mtls(&server_id, &ca);
    server.set_capabilities_json(valid_capabilities_json());
    let scratch = PemScratch::new();
    let transport = TransportMode::MutualTls {
        ca_cert_pem: scratch.write("ca.pem", &ca.cert_pem),
        client_cert_pem: scratch.write("client.pem", &client_id.cert_pem),
        client_key_pem: scratch.write("client.key", &client_id.key_pem),
    };
    QrngClient::connect(config(&server.origin(), transport, KeyExchange::default()))
        .expect("post quantum mTLS connect");
    assert_all_hybrid(&server);
}

#[test]
fn post_quantum_only_refuses_a_classical_server_and_preferred_falls_back() {
    let ca = TestCa::generate("pq-classical-ca");
    let server = serve(
        &ca.issue_server(ServerSan::LoopbackIp),
        ServerGroups::ClassicalOnly,
    );
    let scratch = PemScratch::new();

    // Negative: no common group, no connection, no entropy.
    match QrngClient::connect(config(
        &server.origin(),
        tls(&scratch, &ca),
        KeyExchange::PostQuantumOnly,
    )) {
        Ok(_) => panic!("a post quantum only client must refuse a classical-only server"),
        Err(QrngError::Transport(_)) => {}
        Err(other) => panic!("expected a transport error, got {other:?}"),
    }
    assert!(server.negotiated_groups().is_empty());

    // Positive control on the same server: the preferred mode connects with X25519.
    QrngClient::connect(config(
        &server.origin(),
        tls(&scratch, &ca),
        KeyExchange::PostQuantumPreferred,
    ))
    .expect("preferred mode falls back to a classical group");
    assert_eq!(server.negotiated_groups(), vec!["X25519".to_string()]);
}

#[test]
fn preferred_mode_still_uses_the_hybrid_group_when_offered() {
    let ca = TestCa::generate("pq-preferred-ca");
    let server = serve(
        &ca.issue_server(ServerSan::LoopbackIp),
        ServerGroups::Default,
    );
    let scratch = PemScratch::new();
    QrngClient::connect(config(
        &server.origin(),
        tls(&scratch, &ca),
        KeyExchange::PostQuantumPreferred,
    ))
    .expect("preferred mode connect");
    assert_all_hybrid(&server);
}

#[test]
fn key_exchange_names_parse() {
    assert_eq!(
        KeyExchange::parse("pq-only"),
        Ok(KeyExchange::PostQuantumOnly)
    );
    assert_eq!(
        KeyExchange::parse("pq-preferred"),
        Ok(KeyExchange::PostQuantumPreferred)
    );
    assert_eq!(KeyExchange::PostQuantumOnly.name(), "pq-only");
    assert_eq!(KeyExchange::PostQuantumPreferred.name(), "pq-preferred");
    for bad in ["", "classical", "PQ-ONLY", "x25519"] {
        assert!(KeyExchange::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_client_reports_the_negotiated_group() {
    let ca = TestCa::generate("pq-report-ca");
    let scratch = PemScratch::new();
    let hybrid = NegotiatedKeyExchange::Group(HYBRID.to_string());

    // Post quantum only: the hybrid group is the only one offered.
    let pq = serve(
        &ca.issue_server(ServerSan::LoopbackIp),
        ServerGroups::Default,
    );
    let client = QrngClient::connect(config(
        &pq.origin(),
        tls(&scratch, &ca),
        KeyExchange::PostQuantumOnly,
    ))
    .expect("post quantum only connect");
    assert_eq!(client.key_exchange(), &hybrid);
    assert!(client.key_exchange().is_post_quantum());

    // Preferred, against a server with the hybrid group: the probe sees it.
    let client = QrngClient::connect(config(
        &pq.origin(),
        tls(&scratch, &ca),
        KeyExchange::PostQuantumPreferred,
    ))
    .expect("preferred connect");
    assert_eq!(client.key_exchange(), &hybrid);
    assert!(client.key_exchange().is_post_quantum());

    // Preferred, against a classical server: the downgrade is visible.
    let classical = serve(
        &ca.issue_server(ServerSan::LoopbackIp),
        ServerGroups::ClassicalOnly,
    );
    let client = QrngClient::connect(config(
        &classical.origin(),
        tls(&scratch, &ca),
        KeyExchange::PostQuantumPreferred,
    ))
    .expect("preferred mode falls back to a classical group");
    assert_eq!(
        client.key_exchange(),
        &NegotiatedKeyExchange::Group("X25519".to_string())
    );
    assert!(!client.key_exchange().is_post_quantum());
}

#[test]
fn the_client_reports_the_group_over_mtls() {
    let ca = TestCa::generate("pq-report-mtls-ca");
    let server = TestServer::start_mtls(&ca.issue_server(ServerSan::LoopbackIp), &ca);
    server.set_capabilities_json(valid_capabilities_json());
    let client_id = ca.issue_client("pq-report-client");
    let scratch = PemScratch::new();
    let transport = TransportMode::MutualTls {
        ca_cert_pem: scratch.write("ca.pem", &ca.cert_pem),
        client_cert_pem: scratch.write("client.pem", &client_id.cert_pem),
        client_key_pem: scratch.write("client.key", &client_id.key_pem),
    };
    let client = QrngClient::connect(config(
        &server.origin(),
        transport,
        KeyExchange::PostQuantumPreferred,
    ))
    .expect("preferred mTLS connect");
    assert_eq!(
        client.key_exchange(),
        &NegotiatedKeyExchange::Group(HYBRID.to_string())
    );
}

#[test]
fn plain_http_reports_no_key_exchange() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());
    let client = QrngClient::connect(config(
        &server.origin(),
        TransportMode::PlainHttp,
        KeyExchange::PostQuantumPreferred,
    ))
    .expect("plain HTTP connect");
    assert_eq!(client.key_exchange(), &NegotiatedKeyExchange::PlainHttp);
    assert!(!client.key_exchange().is_post_quantum());
}

#[test]
fn negotiated_key_exchange_names() {
    assert_eq!(
        NegotiatedKeyExchange::PlainHttp.to_string(),
        "none (plain HTTP)"
    );
    assert_eq!(
        NegotiatedKeyExchange::Group(HYBRID.to_string()).to_string(),
        HYBRID
    );
    assert_eq!(
        NegotiatedKeyExchange::Unknown("timed out".to_string()).to_string(),
        "unknown (timed out)"
    );
    assert!(!NegotiatedKeyExchange::Unknown(HYBRID.to_string()).is_post_quantum());
}
