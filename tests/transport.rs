//! TLS and mTLS handshake contract tests (spec 20.5 / Task 9).
//!
//! These tests speak a real rustls handshake against the loopback server.
//! Production `QrngClient::connect` must install the configured CA and mTLS
//! identity; this file does not change that construction.

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use openmls_qrng_provider::{ApiAuth, QrngClient, QrngConfig, QrngError, TransportMode};
use serde_json::json;

use common::test_server::{IssuedIdentity, ServerSan, TestCa};
use common::TestServer;

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

fn connect_config(base_url: &str, transport: TransportMode) -> QrngConfig {
    QrngConfig {
        base_url: base_url.parse().expect("valid URL"),
        transport,
        auth: ApiAuth::None,
        entropy_type: None,
        request_timeout: Duration::from_secs(5),
        health_poll_interval: Some(Duration::from_secs(5)),
    }
}

fn assert_connect_failure(result: Result<QrngClient, QrngError>) {
    match result {
        Ok(_) => panic!("expected QrngError from failed handshake, got Ok"),
        Err(QrngError::Transport(_) | QrngError::TlsMaterial(_) | QrngError::HttpStatus(_)) => {}
        Err(other) => panic!("expected Transport, TlsMaterial, or HttpStatus; got {other:?}"),
    }
}

struct PemScratch {
    dir: PathBuf,
}

impl PemScratch {
    fn new() -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "openmls-qrng-transport-{}-{}",
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

fn write_ca(scratch: &PemScratch, ca: &TestCa) -> PathBuf {
    scratch.write("ca.pem", &ca.cert_pem)
}

fn write_identity(scratch: &PemScratch, id: &IssuedIdentity) -> (PathBuf, PathBuf) {
    (
        scratch.write("client.pem", &id.cert_pem),
        scratch.write("client.key", &id.key_pem),
    )
}

fn serve_https(server_id: &IssuedIdentity) -> TestServer {
    let server = TestServer::start_tls(server_id);
    server.set_capabilities_json(valid_capabilities_json());
    server
}

fn serve_mtls(server_id: &IssuedIdentity, client_ca: &TestCa) -> TestServer {
    let server = TestServer::start_mtls(server_id, client_ca);
    server.set_capabilities_json(valid_capabilities_json());
    server
}

#[test]
fn plain_http_connect_succeeds() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());

    QrngClient::connect(connect_config(&server.origin(), TransportMode::PlainHttp))
        .expect("PlainHttp connect to loopback QRNG must succeed");
}

#[test]
fn tls_with_trusted_test_ca_succeeds() {
    let ca = TestCa::generate("qrng-test-ca-a");
    let server_id = ca.issue_server(ServerSan::LoopbackIp);
    let server = serve_https(&server_id);
    let scratch = PemScratch::new();
    let ca_path = write_ca(&scratch, &ca);

    QrngClient::connect(connect_config(
        &server.origin(),
        TransportMode::Tls {
            ca_cert_pem: Some(ca_path),
        },
    ))
    .expect("TLS connect with the issuing test CA must succeed");
}

#[test]
fn tls_with_untrusted_ca_fails() {
    let server_ca = TestCa::generate("qrng-test-ca-a");
    let untrusted_ca = TestCa::generate("qrng-test-ca-b");
    let server_id = server_ca.issue_server(ServerSan::LoopbackIp);
    let server = serve_https(&server_id);
    let scratch = PemScratch::new();
    let wrong_ca = write_ca(&scratch, &untrusted_ca);

    assert_connect_failure(QrngClient::connect(connect_config(
        &server.origin(),
        TransportMode::Tls {
            ca_cert_pem: Some(wrong_ca),
        },
    )));
}

#[test]
fn mtls_with_trusted_client_certificate_succeeds() {
    let ca = TestCa::generate("qrng-test-mtls-ca");
    let server_id = ca.issue_server(ServerSan::LoopbackIp);
    let client_id = ca.issue_client("qrng-test-client");
    let server = serve_mtls(&server_id, &ca);
    let scratch = PemScratch::new();
    let ca_path = write_ca(&scratch, &ca);
    let (client_cert, client_key) = write_identity(&scratch, &client_id);

    QrngClient::connect(connect_config(
        &server.origin(),
        TransportMode::MutualTls {
            ca_cert_pem: ca_path,
            client_cert_pem: client_cert,
            client_key_pem: client_key,
        },
    ))
    .expect("mTLS connect with a client cert from the required CA must succeed");
}

#[test]
fn mtls_without_client_identity_fails() {
    let ca = TestCa::generate("qrng-test-mtls-ca");
    let server_id = ca.issue_server(ServerSan::LoopbackIp);
    let server = serve_mtls(&server_id, &ca);
    let scratch = PemScratch::new();
    let ca_path = write_ca(&scratch, &ca);

    assert_connect_failure(QrngClient::connect(connect_config(
        &server.origin(),
        TransportMode::Tls {
            ca_cert_pem: Some(ca_path),
        },
    )));
}

#[test]
fn mtls_with_client_certificate_from_wrong_ca_fails() {
    let server_ca = TestCa::generate("qrng-test-mtls-ca-a");
    let other_ca = TestCa::generate("qrng-test-mtls-ca-b");
    let server_id = server_ca.issue_server(ServerSan::LoopbackIp);
    let wrong_client = other_ca.issue_client("qrng-test-client-wrong-ca");
    let server = serve_mtls(&server_id, &server_ca);
    let scratch = PemScratch::new();
    let ca_path = write_ca(&scratch, &server_ca);
    let (client_cert, client_key) = write_identity(&scratch, &wrong_client);

    assert_connect_failure(QrngClient::connect(connect_config(
        &server.origin(),
        TransportMode::MutualTls {
            ca_cert_pem: ca_path,
            client_cert_pem: client_cert,
            client_key_pem: client_key,
        },
    )));
}

#[test]
fn https_certificate_hostname_mismatch_fails() {
    let ca = TestCa::generate("qrng-test-ca-hostname");
    let server_id = ca.issue_server(ServerSan::LocalhostDns);
    let server = serve_https(&server_id);
    let scratch = PemScratch::new();
    let ca_path = write_ca(&scratch, &ca);

    // Server cert SAN is `localhost` only; origin is `https://127.0.0.1:<port>`.
    assert_connect_failure(QrngClient::connect(connect_config(
        &server.origin(),
        TransportMode::Tls {
            ca_cert_pem: Some(ca_path),
        },
    )));
}

#[test]
fn generated_client_identity_pem_is_readable() {
    // Guardrail: ephemeral PEMs must be acceptable to `QrngConfig::validate`
    // so mTLS success cannot fail as `TlsMaterial` before the handshake.
    let ca = TestCa::generate("qrng-test-ca-validate");
    let client_id = ca.issue_client("qrng-test-client-validate");
    let scratch = PemScratch::new();
    let ca_path = write_ca(&scratch, &ca);
    let (client_cert, client_key) = write_identity(&scratch, &client_id);

    connect_config(
        "https://127.0.0.1:1",
        TransportMode::MutualTls {
            ca_cert_pem: ca_path,
            client_cert_pem: client_cert,
            client_key_pem: client_key,
        },
    )
    .validate()
    .expect("generated CA and client identity PEM must parse");
}
