mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use openmls_qrng_provider::{ApiAuth, QrngConfig, QrngError, TransportMode};

use common::test_server::TestCa;

static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);

fn fixture_dir() -> PathBuf {
    // Unique per call so parallel tests do not overwrite shared PEM fixtures.
    let dir = std::env::temp_dir().join(format!(
        "openmls-qrng-provider-config-tests-{}-{}",
        std::process::id(),
        FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create fixture directory");
    dir
}

fn write_fixture(name: &str, contents: &str) -> PathBuf {
    let path = fixture_dir().join(name);
    fs::write(&path, contents).expect("write PEM fixture");
    path
}

fn missing_path(name: &str) -> PathBuf {
    let path = fixture_dir().join(name);
    let _ = fs::remove_file(&path);
    assert!(!path.exists());
    path
}

fn mtls_paths() -> (PathBuf, PathBuf, PathBuf) {
    let ca = TestCa::generate("Test QRNG CA");
    let client = ca.issue_client("Test QRNG Client");
    (
        write_fixture("ca.crt", &ca.cert_pem),
        write_fixture("client.crt", &client.cert_pem),
        write_fixture("client.key", &client.key_pem),
    )
}

fn config(base_url: &str, transport: TransportMode) -> QrngConfig {
    QrngConfig {
        base_url: base_url.parse().expect("valid URL"),
        transport,
        auth: ApiAuth::None,
        entropy_type: None,
        request_timeout: Duration::from_secs(5),
        health_poll_interval: Some(Duration::from_secs(5)),
    }
}

#[test]
fn plain_http_accepts_http_url() {
    let cfg = config("http://127.0.0.1:8002", TransportMode::PlainHttp);
    assert!(cfg.validate().is_ok());
}

#[test]
fn tls_accepts_https_url_without_custom_ca() {
    let cfg = config(
        "https://entropy.example.net/qrng",
        TransportMode::Tls { ca_cert_pem: None },
    );
    assert!(cfg.validate().is_ok());
}

#[test]
fn mutual_tls_accepts_https_url_with_readable_pem_files() {
    let (ca, cert, key) = mtls_paths();
    let cfg = config(
        "https://entropy.example.net",
        TransportMode::MutualTls {
            ca_cert_pem: ca,
            client_cert_pem: cert,
            client_key_pem: key,
        },
    );
    assert!(cfg.validate().is_ok());
}

#[test]
fn accepts_disabled_health_poll_interval() {
    let mut cfg = config("http://127.0.0.1:8002", TransportMode::PlainHttp);
    cfg.health_poll_interval = None;
    assert!(cfg.validate().is_ok());
}

#[test]
fn plain_http_rejects_https_url() {
    let err = config("https://entropy.example.net", TransportMode::PlainHttp)
        .validate()
        .expect_err("https must be rejected with PlainHttp");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn tls_rejects_http_url() {
    let err = config(
        "http://127.0.0.1:8002",
        TransportMode::Tls { ca_cert_pem: None },
    )
    .validate()
    .expect_err("http must be rejected with Tls");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn mutual_tls_rejects_http_url() {
    let (ca, cert, key) = mtls_paths();
    let err = config(
        "http://127.0.0.1:8002",
        TransportMode::MutualTls {
            ca_cert_pem: ca,
            client_cert_pem: cert,
            client_key_pem: key,
        },
    )
    .validate()
    .expect_err("http must be rejected with MutualTls");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn rejects_zero_request_timeout() {
    let mut cfg = config("http://127.0.0.1:8002", TransportMode::PlainHttp);
    cfg.request_timeout = Duration::ZERO;
    let err = cfg
        .validate()
        .expect_err("zero request_timeout must be rejected");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn rejects_zero_health_poll_interval() {
    let mut cfg = config("http://127.0.0.1:8002", TransportMode::PlainHttp);
    cfg.health_poll_interval = Some(Duration::ZERO);
    let err = cfg
        .validate()
        .expect_err("zero health_poll_interval must be rejected");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn rejects_url_with_query_string() {
    let err = config(
        "https://entropy.example.net/?foo=bar",
        TransportMode::Tls { ca_cert_pem: None },
    )
    .validate()
    .expect_err("query string must be rejected");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn rejects_url_with_fragment() {
    let err = config(
        "https://entropy.example.net/#section",
        TransportMode::Tls { ca_cert_pem: None },
    )
    .validate()
    .expect_err("fragment must be rejected");
    assert!(matches!(err, QrngError::InvalidConfig(_)));
}

#[test]
fn tls_rejects_missing_ca_cert_file() {
    let missing = missing_path("missing-ca.pem");
    let err = config(
        "https://entropy.example.net",
        TransportMode::Tls {
            ca_cert_pem: Some(missing),
        },
    )
    .validate()
    .expect_err("missing CA file must be rejected");
    assert!(
        matches!(err, QrngError::TlsMaterial(_) | QrngError::InvalidConfig(_)),
        "expected TlsMaterial (preferred) or InvalidConfig, got {err:?}"
    );
}

#[test]
fn tls_rejects_non_pem_ca_cert_file() {
    let not_pem = write_fixture("not-a-cert.txt", "this is not pem material\n");
    let err = config(
        "https://entropy.example.net",
        TransportMode::Tls {
            ca_cert_pem: Some(not_pem),
        },
    )
    .validate()
    .expect_err("non-PEM CA file must be rejected");
    assert!(
        matches!(err, QrngError::TlsMaterial(_) | QrngError::InvalidConfig(_)),
        "expected TlsMaterial (preferred) or InvalidConfig, got {err:?}"
    );
}

#[test]
fn mutual_tls_rejects_missing_client_key_file() {
    let (ca, cert, _) = mtls_paths();
    let missing_key = missing_path("missing-client.key");
    let err = config(
        "https://entropy.example.net",
        TransportMode::MutualTls {
            ca_cert_pem: ca,
            client_cert_pem: cert,
            client_key_pem: missing_key,
        },
    )
    .validate()
    .expect_err("missing client key must be rejected");
    assert!(
        matches!(err, QrngError::TlsMaterial(_) | QrngError::InvalidConfig(_)),
        "expected TlsMaterial (preferred) or InvalidConfig, got {err:?}"
    );
}
