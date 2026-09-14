//! OpenMlsRand contract tests (spec 20.6).
//!
//! These tests target `QrngRand` (Task 5). They compile only after `src/rand.rs`
//! exists and `QrngRand` is re-exported from `lib.rs`.

mod common;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use openmls_qrng_provider::{ApiAuth, QrngClient, QrngConfig, QrngError, QrngRand, TransportMode};
use openmls_traits::random::OpenMlsRand;
use serde_json::json;

use common::test_server::default_entropy_block;
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

fn connect_rand(server: &TestServer) -> QrngRand {
    server.set_capabilities_json(valid_capabilities_json());
    let client = QrngClient::connect(plain_http_config(&server.origin())).expect("connect");
    QrngRand::new(Arc::new(client))
}

#[test]
fn random_array_32_returns_mock_qrng_bytes() {
    let server = TestServer::start();
    let rand = connect_rand(&server);

    let bytes = rand
        .random_array::<32>()
        .expect("random_array::<32> must succeed against the mock");
    assert_eq!(bytes.len(), 32);
    assert_eq!(&bytes[..], default_entropy_block(32).as_slice());
}

#[test]
fn random_vec_64_returns_mock_qrng_bytes() {
    let server = TestServer::start();
    let rand = connect_rand(&server);

    let bytes = rand
        .random_vec(64)
        .expect("random_vec(64) must succeed against the mock");
    assert_eq!(bytes.len(), 64);
    assert_eq!(bytes, default_entropy_block(64));
}

#[test]
fn qrng_http_503_propagates_as_qrng_error() {
    let server = TestServer::start();
    let rand = connect_rand(&server);
    server.set_entropy_status(503);

    let err = rand
        .random_vec(32)
        .expect_err("HTTP 503 must not return Ok");
    assert!(
        matches!(err, QrngError::EntropyUnavailable) || matches!(err, QrngError::HttpStatus(_)),
        "QRNG failure must surface as QrngError::EntropyUnavailable or a client QrngError, got {err:?}"
    );
}

#[test]
fn qrng_failure_does_not_fall_back_to_os_rng() {
    let server = TestServer::start();
    let rand = connect_rand(&server);
    server.set_entropy_status(503);

    let first = rand
        .random_array::<32>()
        .expect_err("first call with entropy endpoint down must be Err");
    assert!(
        matches!(first, QrngError::EntropyUnavailable) || matches!(first, QrngError::HttpStatus(_)),
        "expected QrngError after QRNG failure, got {first:?}"
    );

    let second = rand
        .random_vec(64)
        .expect_err("second call must remain Err; success would mean OS-RNG fallback");
    assert!(
        matches!(second, QrngError::EntropyUnavailable)
            || matches!(second, QrngError::HttpStatus(_)),
        "no OS-RNG fallback after QRNG failure, got {second:?}"
    );
}

#[test]
fn concurrent_random_vec_callers_receive_expected_pattern_bytes() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());
    let client =
        Arc::new(QrngClient::connect(plain_http_config(&server.origin())).expect("connect"));

    let left_len = 32usize;
    let right_len = 64usize;
    let left_rand = QrngRand::new(Arc::clone(&client));
    let right_rand = QrngRand::new(Arc::clone(&client));

    let left = thread::spawn(move || {
        left_rand
            .random_vec(left_len)
            .expect("concurrent left random_vec must succeed")
    });
    let right = thread::spawn(move || {
        right_rand
            .random_vec(right_len)
            .expect("concurrent right random_vec must succeed")
    });

    let left_bytes = left.join().expect("left thread");
    let right_bytes = right.join().expect("right thread");

    assert_eq!(left_bytes.len(), left_len);
    assert_eq!(right_bytes.len(), right_len);
    assert_eq!(left_bytes, default_entropy_block(left_len));
    assert_eq!(right_bytes, default_entropy_block(right_len));
}
