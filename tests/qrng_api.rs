//! QRNG Open API contract tests. This file starts with capabilities bootstrap;
//! later tasks add entropy, auth, and health cases here.

mod common;

use std::time::Duration;

use openmls_qrng_provider::{
    ApiAuth, Capabilities, QrngClient, QrngConfig, QrngError, TransportMode,
};
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
    assert_eq!(requests[0].path, "/v1/capabilities");
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
    assert_eq!(requests[0].path, "/qrng/v1/capabilities");
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
