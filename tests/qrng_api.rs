//! QRNG Open API contract tests: capabilities, entropy, auth, and health parsing.

mod common;

use std::time::Duration;

use openmls_qrand::{
    ApiAuth, Capabilities, HealthReport, QrngClient, QrngConfig, QrngError, TransportMode,
};
use serde_json::json;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

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

/// Live Entropy Core `GET /capabilities` shape (nspawn QRNG Open API).
fn entropy_core_capabilities_json() -> serde_json::Value {
    json!({
        "entropy": {
            "entropy_types": ["processed", "raw"],
            "extensions": [{
                "Quside QRNG Entropy Quality Extension": [
                    "Q-Factor", "H-min", "QES-ID", "timestamp", "unix_timestamp_ms"
                ]
            }],
            "max_block_count": 16,
            "max_block_size": 524288,
            "min_block_count": 1,
            "min_block_size": 32
        },
        "healthtest": {
            "extensions": [{
                "Quside QRNG Entropy Test Extension": [
                    "Q-Factor", "H-min", "QES-ID", "test-detail", "timestamp", "unix_timestamp_ms"
                ]
            }],
            "test_threshold": [{
                "error": 0.93,
                "good": 0.98,
                "test_type": "NIST SP 800-22 Rev. 1 - Frequency Monobit",
                "warning": 0.96
            }]
        }
    })
}

fn assert_valid_capabilities(caps: &Capabilities) {
    assert_eq!(caps.entropy.min_block_size, 16);
    assert_eq!(caps.entropy.max_block_size, 1024);
    assert_eq!(caps.entropy.min_block_count, 2);
    assert_eq!(caps.entropy.max_block_count, 8);
    assert_eq!(caps.entropy.entropy_types, vec!["raw".to_string()]);
    assert!(caps.entropy.extensions.is_empty());
    assert!(caps.healthtest.is_none());
    assert_eq!(caps.source_count, Some(2));
    assert!(caps.extensions.is_empty());
}

#[test]
fn connect_accepts_valid_capabilities() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());

    let client = QrngClient::connect(plain_http_config(&server.origin()))
        .expect("valid capabilities must be accepted");
    assert_valid_capabilities(client.capabilities());
}

#[test]
fn connect_defaults_missing_min_block_size_to_one() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "max_block_size": 1024,
            "min_block_count": 2,
            "max_block_count": 8
        }
    }));

    let client = QrngClient::connect(plain_http_config(&server.origin()))
        .expect("missing min_block_size must default to 1");
    assert_eq!(client.capabilities().entropy.min_block_size, 1);
    assert_eq!(client.capabilities().entropy.max_block_size, 1024);
}

#[test]
fn connect_defaults_missing_min_block_count_to_one() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "min_block_size": 16,
            "max_block_size": 1024,
            "max_block_count": 8
        }
    }));

    let client = QrngClient::connect(plain_http_config(&server.origin()))
        .expect("missing min_block_count must default to 1");
    assert_eq!(client.capabilities().entropy.min_block_count, 1);
    assert_eq!(client.capabilities().entropy.max_block_count, 8);
}

#[test]
fn connect_rejects_missing_max_block_size() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "min_block_size": 16,
            "min_block_count": 1,
            "max_block_count": 8
        }
    }));

    let err = QrngClient::connect(plain_http_config(&server.origin()))
        .expect_err("missing max_block_size must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
}

#[test]
fn connect_rejects_missing_max_block_count() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "min_block_size": 16,
            "max_block_size": 1024,
            "min_block_count": 1
        }
    }));

    let err = QrngClient::connect(plain_http_config(&server.origin()))
        .expect_err("missing max_block_count must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
}

#[test]
fn connect_rejects_impossible_min_max_block_size() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "min_block_size": 64,
            "max_block_size": 32,
            "min_block_count": 1,
            "max_block_count": 8
        }
    }));

    let err = QrngClient::connect(plain_http_config(&server.origin()))
        .expect_err("min_block_size > max_block_size must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
}

#[test]
fn connect_rejects_impossible_min_max_block_count() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "min_block_size": 16,
            "max_block_size": 1024,
            "min_block_count": 8,
            "max_block_count": 2
        }
    }));

    let err = QrngClient::connect(plain_http_config(&server.origin()))
        .expect_err("min_block_count > max_block_count must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
}

#[test]
fn connect_accepts_configured_supported_entropy_type() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "min_block_size": 16,
            "max_block_size": 1024,
            "min_block_count": 1,
            "max_block_count": 8,
            "entropy_types": ["raw", "conditioned"]
        }
    }));

    let mut cfg = plain_http_config(&server.origin());
    cfg.entropy_type = Some("raw".to_string());
    let client = QrngClient::connect(cfg).expect("supported entropy type must be accepted");
    assert_eq!(
        client.capabilities().entropy.entropy_types,
        vec!["raw".to_string(), "conditioned".to_string()]
    );
}

#[test]
fn connect_rejects_unsupported_advertised_entropy_type() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "min_block_size": 16,
            "max_block_size": 1024,
            "min_block_count": 1,
            "max_block_count": 8,
            "entropy_types": ["conditioned"]
        }
    }));

    let mut cfg = plain_http_config(&server.origin());
    cfg.entropy_type = Some("raw".to_string());
    let err =
        QrngClient::connect(cfg).expect_err("unsupported advertised entropy type must be rejected");
    assert!(
        matches!(err, QrngError::UnsupportedEntropyType),
        "expected UnsupportedEntropyType, got {err:?}"
    );
}

#[test]
fn connect_ignores_unknown_json_fields() {
    let server = TestServer::start();
    server.set_capabilities_json(json!({
        "entropy": {
            "min_block_size": 16,
            "max_block_size": 1024,
            "min_block_count": 2,
            "max_block_count": 8,
            "entropy_types": ["raw"],
            "vendor_entropy_flag": true
        },
        "source_count": 2,
        "future_top_level": {"ok": 1}
    }));

    let client = QrngClient::connect(plain_http_config(&server.origin()))
        .expect("unknown JSON fields must be ignored");
    assert_valid_capabilities(client.capabilities());
}

#[test]
fn connect_sends_exactly_one_get_to_capabilities_path() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());

    QrngClient::connect(plain_http_config(&server.origin())).expect("connect");

    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 1, "connect must send exactly one request");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/capabilities");
}

#[test]
fn connect_joins_base_url_path_prefix_to_capabilities_path() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());

    let base = format!("{}/qrng", server.origin());
    QrngClient::connect(plain_http_config(&base)).expect("connect with path prefix");

    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 1, "connect must send exactly one request");
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/qrng/capabilities");
}

#[test]
fn connect_maps_http_500_to_http_status() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());
    server.set_capabilities_status(500);

    let err = QrngClient::connect(plain_http_config(&server.origin()))
        .expect_err("HTTP 500 must fail connect");
    assert!(
        matches!(err, QrngError::HttpStatus(_)),
        "prefer HttpStatus when a status code is available, got {err:?}"
    );
}

#[test]
fn connect_rejects_malformed_json_as_protocol() {
    let server = TestServer::start();
    server.set_capabilities_raw(b"this is not json".to_vec());
    server.set_capabilities_status(200);

    let err = QrngClient::connect(plain_http_config(&server.origin()))
        .expect_err("malformed JSON must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    header_value(headers, name).is_some()
}

#[test]
fn connect_with_api_auth_none_sends_no_authorization_or_x_api_key_header() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());

    QrngClient::connect(plain_http_config(&server.origin())).expect("connect");

    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 1, "connect must send exactly one request");
    let headers = &requests[0].headers;
    assert!(
        !has_header(headers, "Authorization"),
        "ApiAuth::None must not send Authorization, got {headers:?}"
    );
    assert!(
        !has_header(headers, "X-API-KEY"),
        "ApiAuth::None must not send X-API-KEY, got {headers:?}"
    );
}

#[test]
fn connect_with_api_auth_bearer_sets_authorization_header() {
    const TOKEN: &str = "super-secret-token-42";
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());

    let mut cfg = plain_http_config(&server.origin());
    cfg.auth = ApiAuth::Bearer(TOKEN.to_string());
    QrngClient::connect(cfg).expect("connect");

    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 1, "connect must send exactly one request");
    assert_eq!(
        header_value(&requests[0].headers, "Authorization"),
        Some("Bearer super-secret-token-42"),
        "Authorization must be exactly `Bearer <token>` with one space"
    );
}

#[test]
fn connect_with_api_auth_x_api_key_sets_x_api_key_header() {
    const KEY: &str = "super-secret-key-99";
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());

    let mut cfg = plain_http_config(&server.origin());
    cfg.auth = ApiAuth::XApiKey(KEY.to_string());
    QrngClient::connect(cfg).expect("connect");

    let requests = server.recorded_requests();
    assert_eq!(requests.len(), 1, "connect must send exactly one request");
    assert_eq!(
        header_value(&requests[0].headers, "X-API-KEY"),
        Some("super-secret-key-99"),
        "X-API-KEY must be exactly the configured value"
    );
}

#[test]
fn api_auth_bearer_debug_does_not_contain_token() {
    const TOKEN: &str = "super-secret-token-42";
    let debug = format!("{:?}", ApiAuth::Bearer(TOKEN.to_string()));
    assert!(
        !debug.contains(TOKEN),
        "ApiAuth::Bearer Debug must not contain the token, got {debug:?}"
    );
}

#[test]
fn api_auth_x_api_key_debug_does_not_contain_key() {
    const KEY: &str = "super-secret-key-99";
    let debug = format!("{:?}", ApiAuth::XApiKey(KEY.to_string()));
    assert!(
        !debug.contains(KEY),
        "ApiAuth::XApiKey Debug must not contain the key, got {debug:?}"
    );
}

const LEAK_BYTES: &[u8] = b"QRNG-LEAK-TEST-BLOCK-AA";
const LEAK_TEXT: &str = "QRNG-LEAK-TEST-BLOCK-AA";
const INVALID_B64: &str = "!!!NOT-VALID-BASE64-QRNG-LEAK!!!";

fn capabilities_with_block_limits(
    min_block_size: usize,
    max_block_size: usize,
) -> serde_json::Value {
    json!({
        "entropy": {
            "min_block_size": min_block_size,
            "max_block_size": max_block_size,
            "min_block_count": 1,
            "max_block_count": 8,
            "entropy_types": ["raw"]
        }
    })
}

fn connect_plain(server: &TestServer, caps: serde_json::Value) -> QrngClient {
    server.set_capabilities_json(caps);
    QrngClient::connect(plain_http_config(&server.origin())).expect("connect")
}

fn entropy_posts(
    requests: &[common::test_server::RecordedRequest],
) -> Vec<&common::test_server::RecordedRequest> {
    requests
        .iter()
        .filter(|request| {
            request.method.eq_ignore_ascii_case("POST")
                && (request.path == "/entropy" || request.path.ends_with("/entropy"))
        })
        .collect()
}

fn entropy_body(request: &common::test_server::RecordedRequest) -> serde_json::Value {
    serde_json::from_slice(&request.body).expect("entropy POST body must be JSON")
}

fn assert_entropy_post_contract(request: &common::test_server::RecordedRequest) {
    assert_eq!(request.path, "/entropy");
    let body = entropy_body(request);
    assert_eq!(body["block_count"], json!(1));
    assert!(
        body.get("block_size").and_then(|v| v.as_u64()).is_some(),
        "block_size must be present, got {body}"
    );
}

fn assert_no_entropy_leak(err: &QrngError, distinctive: &[&str]) {
    let display = format!("{err}");
    let debug = format!("{err:?}");
    for needle in distinctive {
        assert!(
            !display.contains(needle),
            "error Display must not contain {needle:?}, got {display:?}"
        );
        assert!(
            !debug.contains(needle),
            "error Debug must not contain {needle:?}, got {debug:?}"
        );
    }
}

fn leak_b64() -> String {
    BASE64.encode(LEAK_BYTES)
}

#[test]
fn fetch_entropy_zero_performs_no_request() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    let after_connect = server.recorded_requests().len();
    assert_eq!(
        after_connect, 1,
        "connect must have sent one capabilities GET"
    );

    let bytes = client
        .fetch_entropy(0)
        .expect("fetch_entropy(0) must succeed");
    assert!(bytes.is_empty(), "fetch_entropy(0) must return empty vec");
    assert_eq!(
        server.recorded_requests().len(),
        after_connect,
        "fetch_entropy(0) must not send any additional request"
    );
}

#[test]
fn fetch_entropy_exact_single_block() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());

    let bytes = client
        .fetch_entropy(32)
        .expect("exact 32-byte block must succeed");
    assert_eq!(bytes, default_entropy_block(32));

    let requests = server.recorded_requests();
    let posts = entropy_posts(&requests);
    assert_eq!(posts.len(), 1, "exact single block must send one POST");
    assert_entropy_post_contract(posts[0]);
    assert_eq!(entropy_body(posts[0])["block_size"], json!(32));
}

#[test]
fn fetch_entropy_larger_than_max_block_size_sends_multiple_posts() {
    let server = TestServer::start();
    let client = connect_plain(&server, capabilities_with_block_limits(16, 32));

    let bytes = client
        .fetch_entropy(80)
        .expect("request larger than max_block_size must succeed");
    assert_eq!(bytes.len(), 80);

    let requests = server.recorded_requests();
    let posts = entropy_posts(&requests);
    assert_eq!(posts.len(), 3, "80 bytes with max 32 must be three POSTs");
    let sizes: Vec<u64> = posts
        .iter()
        .map(|request| {
            assert_entropy_post_contract(request);
            entropy_body(request)["block_size"]
                .as_u64()
                .expect("block_size")
        })
        .collect();
    assert_eq!(sizes, vec![32, 32, 16]);

    let mut expected = Vec::new();
    for size in sizes {
        expected.extend_from_slice(&default_entropy_block(size as usize));
    }
    assert_eq!(bytes, expected);
}

#[test]
fn fetch_entropy_remainder_smaller_than_min_fetches_min_and_discards_tail() {
    let server = TestServer::start();
    let client = connect_plain(&server, capabilities_with_block_limits(16, 1024));

    let bytes = client
        .fetch_entropy(8)
        .expect("remainder smaller than min_block_size must succeed");
    assert_eq!(bytes.len(), 8);
    assert_eq!(
        bytes,
        default_entropy_block(16)[..8].to_vec(),
        "must keep the prefix and discard the unused tail"
    );
    assert_ne!(bytes, default_entropy_block(16)[8..].to_vec());

    let requests = server.recorded_requests();
    let posts = entropy_posts(&requests);
    assert_eq!(posts.len(), 1);
    assert_entropy_post_contract(posts[0]);
    assert_eq!(entropy_body(posts[0])["block_size"], json!(16));
}

#[test]
fn fetch_entropy_http_422_maps_to_invalid_request() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.enqueue_entropy_json(422, json!({ "entropy": [leak_b64()], "error": LEAK_TEXT }));

    let err = client.fetch_entropy(32).expect_err("HTTP 422 must fail");
    assert!(
        matches!(err, QrngError::InvalidRequest),
        "expected InvalidRequest, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[LEAK_TEXT, &leak_b64()]);
}

#[test]
fn fetch_entropy_http_503_maps_to_entropy_unavailable() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.enqueue_entropy_json(503, json!({ "entropy": [leak_b64()], "error": LEAK_TEXT }));

    let err = client.fetch_entropy(32).expect_err("HTTP 503 must fail");
    assert!(
        matches!(err, QrngError::EntropyUnavailable),
        "expected EntropyUnavailable, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[LEAK_TEXT, &leak_b64()]);
}

#[test]
fn fetch_entropy_http_500_maps_to_http_status() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.enqueue_entropy_json(500, json!({ "entropy": [leak_b64()], "error": LEAK_TEXT }));

    let err = client.fetch_entropy(32).expect_err("HTTP 500 must fail");
    assert!(
        matches!(err, QrngError::HttpStatus(_)),
        "expected HttpStatus, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[LEAK_TEXT, &leak_b64()]);
}

#[test]
fn fetch_entropy_malformed_json_rejected_as_protocol() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.enqueue_entropy_raw(
        200,
        format!("not-json {LEAK_TEXT} {INVALID_B64}").into_bytes(),
    );

    let err = client
        .fetch_entropy(32)
        .expect_err("malformed JSON must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[LEAK_TEXT, INVALID_B64]);
}

#[test]
fn fetch_entropy_empty_entropy_array_rejected() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.enqueue_entropy_json(200, json!({ "entropy": [], "unused": LEAK_TEXT }));

    let err = client
        .fetch_entropy(32)
        .expect_err("empty entropy array must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[LEAK_TEXT]);
}

#[test]
fn fetch_entropy_multiple_entropy_blocks_rejected() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    let encoded = leak_b64();
    server.enqueue_entropy_json(200, json!({ "entropy": [encoded, encoded] }));

    let err = client
        .fetch_entropy(32)
        .expect_err("multiple entropy blocks must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[LEAK_TEXT, &leak_b64()]);
}

#[test]
fn fetch_entropy_invalid_base64_rejected() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.enqueue_entropy_json(200, json!({ "entropy": [INVALID_B64] }));

    let err = client
        .fetch_entropy(32)
        .expect_err("invalid Base64 must be rejected");
    assert!(
        matches!(err, QrngError::Base64(_) | QrngError::Protocol(_)),
        "expected Base64 or Protocol, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[INVALID_B64, LEAK_TEXT]);
}

#[test]
fn fetch_entropy_decoded_block_shorter_than_requested_rejected() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.enqueue_entropy_json(200, json!({ "entropy": [leak_b64()] }));

    let err = client
        .fetch_entropy(32)
        .expect_err("decoded block shorter than requested must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[LEAK_TEXT, &leak_b64()]);
}

#[test]
fn fetch_entropy_decoded_block_longer_than_requested_rejected() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    let long = BASE64.encode([LEAK_BYTES, LEAK_BYTES].concat());
    server.enqueue_entropy_json(200, json!({ "entropy": [long] }));

    let err = client
        .fetch_entropy(32)
        .expect_err("decoded block longer than requested must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
    assert_no_entropy_leak(&err, &[LEAK_TEXT, &leak_b64()]);
}

#[test]
fn fetch_entropy_bytes_never_appear_in_error_text() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    let encoded = leak_b64();
    server.enqueue_entropy_json(
        200,
        json!({
            "entropy": [encoded],
            "note": LEAK_TEXT
        }),
    );

    let err = client
        .fetch_entropy(32)
        .expect_err("wrong-length distinctive block must fail");
    assert_no_entropy_leak(&err, &[LEAK_TEXT, &leak_b64()]);
}

#[test]
fn fetch_entropy_includes_entropy_type_when_configured() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());
    let mut cfg = plain_http_config(&server.origin());
    cfg.entropy_type = Some("raw".to_string());
    let client = QrngClient::connect(cfg).expect("connect");

    client.fetch_entropy(32).expect("fetch");
    let requests = server.recorded_requests();
    let posts = entropy_posts(&requests);
    assert_eq!(posts.len(), 1);
    assert_entropy_post_contract(posts[0]);
    assert_eq!(entropy_body(posts[0])["entropy_type"], json!("raw"));
}

#[test]
fn fetch_entropy_omits_entropy_type_when_not_configured() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());

    client.fetch_entropy(32).expect("fetch");
    let requests = server.recorded_requests();
    let posts = entropy_posts(&requests);
    assert_eq!(posts.len(), 1);
    assert_entropy_post_contract(posts[0]);
    assert!(
        entropy_body(posts[0]).get("entropy_type").is_none(),
        "entropy_type must be absent when not configured, got {}",
        entropy_body(posts[0])
    );
}

fn health_gets(
    requests: &[common::test_server::RecordedRequest],
) -> Vec<&common::test_server::RecordedRequest> {
    requests
        .iter()
        .filter(|request| {
            request.method.eq_ignore_ascii_case("GET")
                && (request.path == "/healthtest" || request.path.ends_with("/healthtest"))
        })
        .collect()
}

fn default_health_json() -> serde_json::Value {
    json!({
        "test_result": [
            {
                "test_type": "nist_90b",
                "test_result": 0.94,
                "time_stamp": "2026-09-14T10:00:00Z",
                "report_link": "https://example.test/health/nist_90b"
            },
            {
                "test_type": "vendor_status",
                "test_result": "ok",
                "time_stamp": "2026-09-14T10:00:01Z"
            }
        ]
    })
}

fn assert_parsed_default_health(report: &HealthReport) {
    assert_eq!(report.test_result.len(), 2);
    assert_eq!(report.test_result[0].test_type, "nist_90b");
    assert_eq!(report.test_result[0].test_result, json!(0.94));
    assert_eq!(report.test_result[0].time_stamp, "2026-09-14T10:00:00Z");
    assert_eq!(
        report.test_result[0].report_link.as_deref(),
        Some("https://example.test/health/nist_90b")
    );
    assert_eq!(report.test_result[1].test_type, "vendor_status");
    assert_eq!(report.test_result[1].test_result, json!("ok"));
    assert_eq!(report.test_result[1].time_stamp, "2026-09-14T10:00:01Z");
    assert_eq!(report.test_result[1].report_link, None);
    assert!(report.extensions.is_empty());
}

#[test]
fn fetch_health_parses_successful_response() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.set_health_json(default_health_json());

    let report = client
        .fetch_health()
        .expect("successful health JSON must parse");
    assert_parsed_default_health(&report);
}

#[test]
fn connect_accepts_entropy_core_capabilities() {
    let server = TestServer::start();
    server.set_capabilities_json(entropy_core_capabilities_json());

    let client = QrngClient::connect(plain_http_config(&server.origin()))
        .expect("Entropy Core capabilities must be accepted");
    let caps = client.capabilities();
    assert_eq!(caps.entropy.min_block_size, 32);
    assert_eq!(caps.entropy.max_block_size, 524_288);
    assert_eq!(caps.entropy.min_block_count, 1);
    assert_eq!(caps.entropy.max_block_count, 16);
    assert_eq!(
        caps.entropy.entropy_types,
        vec!["processed".to_string(), "raw".to_string()]
    );
    assert!(
        caps.healthtest.is_some(),
        "Entropy Core advertises healthtest"
    );
}

#[test]
fn fetch_entropy_parses_entropy_core_open_api_response() {
    let server = TestServer::start();
    let client = connect_plain(&server, entropy_core_capabilities_json());
    let block = vec![0x11u8; 32];
    server.enqueue_entropy_json(
        200,
        json!({
            "entropy": [BASE64.encode(&block)],
            "extensions": [{
                "H-min": 0.0,
                "Q-factor": 0.0,
                "QES-ID": "0",
                "timestamp": "2026-09-16T13:37:46+02:00",
                "unix_timestamp_ms": 1_789_558_666_492u64
            }]
        }),
    );

    let got = client
        .fetch_entropy(32)
        .expect("Entropy Core POST /entropy JSON must parse");
    assert_eq!(got, block);
}

/// Live Entropy Core `GET /healthtest` omits Open API `time_stamp` on each
/// result and places RFC 3339 `timestamp` in `extensions` instead.
fn entropy_core_health_json() -> serde_json::Value {
    json!({
        "test_result": [
            {
                "test_type": "NIST SP 800-22 Rev. 1 - Frequency Monobit",
                "test_result": 0.995
            }
        ],
        "extensions": [
            {
                "QES-ID": "0",
                "Q-factor": 0.0,
                "H-min": 0.0,
                "test-detail": "995/1000 Frequency",
                "timestamp": "2026-09-15T22:28:14+02:00",
                "unix_timestamp_ms": 1_789_504_094_160u64
            }
        ]
    })
}

#[test]
fn fetch_health_parses_entropy_core_response() {
    let server = TestServer::start();
    let client = connect_plain(&server, entropy_core_capabilities_json());
    server.set_health_json(entropy_core_health_json());

    let report = client
        .fetch_health()
        .expect("Entropy Core healthtest JSON must parse");
    assert_eq!(report.test_result.len(), 1);
    assert_eq!(
        report.test_result[0].test_type,
        "NIST SP 800-22 Rev. 1 - Frequency Monobit"
    );
    assert_eq!(report.test_result[0].test_result, json!(0.995));
    assert_eq!(
        report.test_result[0].time_stamp,
        "2026-09-15T22:28:14+02:00"
    );
    assert_eq!(report.extensions.len(), 1);
    assert_eq!(
        report.extensions[0]["timestamp"],
        json!("2026-09-15T22:28:14+02:00")
    );
    assert_eq!(report.extensions[0]["Q-factor"], json!(0.0));
}

#[test]
fn fetch_health_accepts_timestamp_alias_on_result() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.set_health_json(json!({
        "test_result": [
            {
                "test_type": "nist_90b",
                "test_result": 0.94,
                "timestamp": "2026-09-15T22:28:14+02:00"
            }
        ]
    }));

    let report = client
        .fetch_health()
        .expect("timestamp must be accepted as time_stamp");
    assert_eq!(
        report.test_result[0].time_stamp,
        "2026-09-15T22:28:14+02:00"
    );
}

#[test]
fn fetch_health_preserves_unknown_extensions() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.set_health_json(json!({
        "test_result": [
            {
                "test_type": "nist_90b",
                "test_result": 0.94,
                "time_stamp": "2026-09-14T10:00:00Z"
            }
        ],
        "extensions": [
            { "vendor_health_flag": true, "detail": "keep-me" }
        ],
        "future_top_level": { "ignored": true }
    }));

    let report = client
        .fetch_health()
        .expect("unknown extensions must be preserved");
    assert_eq!(report.test_result.len(), 1);
    assert_eq!(report.test_result[0].test_type, "nist_90b");
    assert_eq!(
        report.extensions,
        vec![json!({ "vendor_health_flag": true, "detail": "keep-me" })]
    );
}

#[test]
fn fetch_health_test_result_supports_numeric_and_string_json() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.set_health_json(json!({
        "test_result": [
            {
                "test_type": "nist_90b",
                "test_result": 0.94,
                "time_stamp": "2026-09-14T10:00:00Z"
            },
            {
                "test_type": "vendor_status",
                "test_result": "ok",
                "time_stamp": "2026-09-14T10:00:01Z"
            }
        ]
    }));

    let report = client
        .fetch_health()
        .expect("numeric and string test_result values must parse");
    assert_eq!(report.test_result[0].test_result, json!(0.94));
    assert!(
        report.test_result[0].test_result.is_number(),
        "numeric test_result must remain JSON number, got {}",
        report.test_result[0].test_result
    );
    assert_eq!(report.test_result[1].test_result, json!("ok"));
    assert!(
        report.test_result[1].test_result.is_string(),
        "string test_result must remain JSON string, got {}",
        report.test_result[1].test_result
    );
}

#[test]
fn fetch_health_http_503_maps_to_health_unavailable() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.set_health_json(json!({ "error": "temporarily down" }));
    server.set_health_status(503);

    let err = client.fetch_health().expect_err("HTTP 503 must fail");
    assert!(
        matches!(err, QrngError::HealthUnavailable),
        "expected HealthUnavailable, got {err:?}"
    );
}

#[test]
fn fetch_health_malformed_json_rejected_as_protocol() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.set_health_raw(b"this is not json".to_vec());
    server.set_health_status(200);

    let err = client
        .fetch_health()
        .expect_err("malformed health JSON must be rejected");
    assert!(
        matches!(err, QrngError::Protocol(_)),
        "expected Protocol, got {err:?}"
    );
}

#[test]
fn fetch_health_sends_get_to_healthtest_path() {
    let server = TestServer::start();
    let client = connect_plain(&server, valid_capabilities_json());
    server.set_health_json(default_health_json());

    client.fetch_health().expect("fetch_health");

    let requests = server.recorded_requests();
    let gets = health_gets(&requests);
    assert_eq!(gets.len(), 1, "fetch_health must send exactly one GET");
    assert_eq!(gets[0].method, "GET");
    assert_eq!(gets[0].path, "/healthtest");
}

#[test]
fn fetch_health_joins_base_url_path_prefix_to_healthtest_path() {
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());
    server.set_health_json(default_health_json());

    let base = format!("{}/qrng", server.origin());
    let client = QrngClient::connect(plain_http_config(&base)).expect("connect with path prefix");
    client.fetch_health().expect("fetch_health");

    let requests = server.recorded_requests();
    let gets = health_gets(&requests);
    assert_eq!(gets.len(), 1, "fetch_health must send exactly one GET");
    assert_eq!(gets[0].method, "GET");
    assert_eq!(gets[0].path, "/qrng/healthtest");
}

#[test]
fn fetch_health_with_api_auth_bearer_sets_authorization_header() {
    const TOKEN: &str = "super-secret-token-42";
    let server = TestServer::start();
    server.set_capabilities_json(valid_capabilities_json());
    server.set_health_json(default_health_json());

    let mut cfg = plain_http_config(&server.origin());
    cfg.auth = ApiAuth::Bearer(TOKEN.to_string());
    let client = QrngClient::connect(cfg).expect("connect");
    client.fetch_health().expect("fetch_health");

    let requests = server.recorded_requests();
    let gets = health_gets(&requests);
    assert_eq!(gets.len(), 1);
    assert_eq!(
        header_value(&gets[0].headers, "Authorization"),
        Some("Bearer super-secret-token-42"),
        "health GET must reuse apply_auth Bearer header"
    );
}
