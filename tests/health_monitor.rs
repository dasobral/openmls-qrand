//! Health monitor and provider metrics contract tests (spec 15, 20.7, 20.8).
//!
//! These tests target `HealthMonitor` (Task 7). They compile only after
//! `src/health.rs` exists, types are re-exported from `lib.rs`, and
//! `QrngClient::metrics_snapshot` is available.

mod common;

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use openmls_qrand::{ApiAuth, HealthMonitor, QrngClient, QrngConfig, QrngError, TransportMode};
use serde_json::json;

use common::test_server::RecordedRequest;
use common::TestServer;

const BEARER_TOKEN: &str = "super-secret-health-token-7";

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

fn entropy_capabilities() -> serde_json::Value {
    json!({
        "min_block_size": 16,
        "max_block_size": 1024,
        "min_block_count": 2,
        "max_block_count": 8,
        "entropy_types": ["raw"]
    })
}

/// Presence of `healthtest` (even `{}`) advertises health-test support.
fn capabilities_with_healthtest() -> serde_json::Value {
    json!({
        "entropy": entropy_capabilities(),
        "healthtest": {},
        "source_count": 2
    })
}

fn capabilities_without_healthtest() -> serde_json::Value {
    json!({
        "entropy": entropy_capabilities(),
        "source_count": 2
    })
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

fn health_with_extension() -> serde_json::Value {
    json!({
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
    })
}

fn connect_plain(server: &TestServer, caps: serde_json::Value) -> QrngClient {
    server.set_capabilities_json(caps);
    QrngClient::connect(plain_http_config(&server.origin())).expect("connect")
}

fn start_monitor(client: QrngClient, interval: Duration) -> HealthMonitor {
    HealthMonitor::start(Arc::new(client), interval).expect("HealthMonitor::start")
}

fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if pred() {
            return true;
        }
        if Instant::now() >= deadline {
            return pred();
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn health_gets(requests: &[RecordedRequest]) -> Vec<&RecordedRequest> {
    requests
        .iter()
        .filter(|request| {
            request.method.eq_ignore_ascii_case("GET")
                && (request.path == "/healthtest" || request.path.ends_with("/healthtest"))
        })
        .collect()
}

fn health_get_count(server: &TestServer) -> usize {
    health_gets(&server.recorded_requests()).len()
}

fn wait_for_first_successful_poll(monitor: &HealthMonitor) {
    let populated = wait_until(Duration::from_millis(200), || {
        let snap = monitor.snapshot();
        snap.report.is_some() && snap.consecutive_failures == 0 && snap.last_error.is_none()
    });
    assert!(
        populated,
        "first health poll must populate the snapshot within 200ms"
    );
}

fn assert_last_error_sanitized(last_error: &str) {
    assert!(
        !last_error.contains(BEARER_TOKEN),
        "last_error must not contain API tokens, got {last_error:?}"
    );
    assert!(
        !last_error.to_ascii_lowercase().contains("entropy"),
        "last_error must not contain entropy material, got {last_error:?}"
    );
}

#[test]
fn successful_health_response_stored_in_snapshot() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let monitor = start_monitor(client, Duration::from_millis(80));

    wait_for_first_successful_poll(&monitor);
    let snap = monitor.snapshot();
    let report = snap.report.expect("successful poll stores a report");
    assert_eq!(report.test_result.len(), 2);
    assert_eq!(report.test_result[0].test_type, "nist_90b");
    assert_eq!(report.test_result[0].test_result, json!(0.94));
    assert_eq!(report.test_result[1].test_type, "vendor_status");
    assert_eq!(report.test_result[1].test_result, json!("ok"));
    assert_eq!(snap.consecutive_failures, 0);
    assert!(snap.last_error.is_none());
}

#[test]
fn unknown_extension_preserved_in_snapshot() {
    let server = TestServer::start();
    server.set_health_json(health_with_extension());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let monitor = start_monitor(client, Duration::from_millis(80));

    wait_for_first_successful_poll(&monitor);
    let report = monitor
        .snapshot()
        .report
        .expect("successful poll stores a report");
    assert_eq!(report.test_result.len(), 1);
    assert_eq!(report.test_result[0].test_type, "nist_90b");
    assert_eq!(
        report.extensions,
        vec![json!({ "vendor_health_flag": true, "detail": "keep-me" })]
    );
}

#[test]
fn test_result_supports_numeric_and_string_json() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let monitor = start_monitor(client, Duration::from_millis(80));

    wait_for_first_successful_poll(&monitor);
    let report = monitor
        .snapshot()
        .report
        .expect("successful poll stores a report");
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
fn immediate_first_poll_populates_snapshot_without_waiting_full_interval() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let interval = Duration::from_secs(5);
    let started = Instant::now();
    let monitor = start_monitor(client, interval);

    wait_for_first_successful_poll(&monitor);
    assert!(
        started.elapsed() < interval,
        "first poll must not wait the full interval ({interval:?})"
    );
    assert!(
        health_get_count(&server) >= 1,
        "immediate first poll must GET /healthtest"
    );
}

#[test]
fn repeated_poll_happens_after_interval() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let interval = Duration::from_millis(60);
    let monitor = start_monitor(client, interval);

    let repeated = wait_until(Duration::from_millis(400), || {
        health_get_count(&server) >= 2
    });
    assert!(
        repeated,
        "monitor must poll again after the interval; got {} health GETs",
        health_get_count(&server)
    );
    drop(monitor);
}

#[test]
fn failed_poll_increments_consecutive_failures() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let mut cfg = plain_http_config(&server.origin());
    cfg.auth = ApiAuth::Bearer(BEARER_TOKEN.to_string());
    server.set_capabilities_json(capabilities_with_healthtest());
    let client = QrngClient::connect(cfg).expect("connect");
    let monitor = start_monitor(client, Duration::from_millis(50));

    wait_for_first_successful_poll(&monitor);
    server.set_health_status(503);

    let failed = wait_until(Duration::from_millis(400), || {
        monitor.snapshot().consecutive_failures >= 1
    });
    assert!(failed, "failed poll must increment consecutive_failures");
    let snap = monitor.snapshot();
    let last_error = snap.last_error.expect("failed poll records last_error");
    assert_last_error_sanitized(&last_error);
}

#[test]
fn failed_poll_retains_last_successful_report() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let monitor = start_monitor(client, Duration::from_millis(50));

    wait_for_first_successful_poll(&monitor);
    let success_report = monitor
        .snapshot()
        .report
        .expect("successful poll stores a report");

    server.set_health_status(503);
    let failed = wait_until(Duration::from_millis(400), || {
        monitor.snapshot().consecutive_failures >= 1
    });
    assert!(failed, "failed poll must increment consecutive_failures");

    let snap = monitor.snapshot();
    let retained = snap
        .report
        .expect("failed poll must retain the last successful report");
    assert_eq!(retained.test_result.len(), success_report.test_result.len());
    assert_eq!(
        retained.test_result[0].test_type,
        success_report.test_result[0].test_type
    );
    assert_eq!(
        retained.test_result[0].test_result,
        success_report.test_result[0].test_result
    );
    assert_eq!(
        retained.test_result[1].test_result,
        success_report.test_result[1].test_result
    );
}

#[test]
fn later_success_resets_consecutive_failures() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let monitor = start_monitor(client, Duration::from_millis(50));

    wait_for_first_successful_poll(&monitor);
    server.set_health_status(503);
    let failed = wait_until(Duration::from_millis(400), || {
        monitor.snapshot().consecutive_failures >= 1
    });
    assert!(failed, "failed poll must increment consecutive_failures");

    server.set_health_status(200);
    let recovered = wait_until(Duration::from_millis(400), || {
        let snap = monitor.snapshot();
        snap.consecutive_failures == 0 && snap.last_error.is_none() && snap.report.is_some()
    });
    assert!(
        recovered,
        "later success must reset consecutive_failures and clear last_error"
    );
}

#[test]
fn drop_shuts_thread_down_promptly() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let interval = Duration::from_secs(2);
    let monitor = start_monitor(client, interval);
    wait_for_first_successful_poll(&monitor);

    let started = Instant::now();
    drop(monitor);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "Drop must join promptly (elapsed {elapsed:?}, interval {interval:?})"
    );
    let _ = &server;
}

#[test]
fn unsupported_health_capability_returns_health_unsupported() {
    let server = TestServer::start();
    let client = connect_plain(&server, capabilities_without_healthtest());
    let err = HealthMonitor::start(Arc::new(client), Duration::from_millis(80))
        .expect_err("missing healthtest capability must reject start");
    assert!(
        matches!(err, QrngError::HealthUnsupported),
        "expected HealthUnsupported, got {err:?}"
    );
    assert_eq!(health_get_count(&server), 0);
}

#[test]
fn zero_interval_rejected_as_invalid_config() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = connect_plain(&server, capabilities_with_healthtest());
    let err = HealthMonitor::start(Arc::new(client), Duration::ZERO)
        .expect_err("zero interval must be rejected");
    assert!(
        matches!(err, QrngError::InvalidConfig(_)),
        "expected InvalidConfig, got {err:?}"
    );
}

#[test]
fn successful_entropy_increments_request_and_byte_counters() {
    let server = TestServer::start();
    let client = connect_plain(&server, capabilities_with_healthtest());
    let before = client.metrics_snapshot();

    let bytes = client.fetch_entropy(32).expect("entropy");
    assert_eq!(bytes.len(), 32);

    let after = client.metrics_snapshot();
    assert_eq!(
        after.entropy_requests_total,
        before.entropy_requests_total + 1
    );
    assert_eq!(after.entropy_bytes_total, before.entropy_bytes_total + 32);
}

#[test]
fn failed_entropy_increments_failure_counter() {
    let server = TestServer::start();
    let client = connect_plain(&server, capabilities_with_healthtest());
    server.set_entropy_status(503);
    let before = client.metrics_snapshot();

    let err = client
        .fetch_entropy(32)
        .expect_err("HTTP 503 entropy must fail");
    assert!(
        matches!(err, QrngError::EntropyUnavailable),
        "expected EntropyUnavailable, got {err:?}"
    );

    let after = client.metrics_snapshot();
    assert_eq!(
        after.entropy_failures_total,
        before.entropy_failures_total + 1
    );
}

#[test]
fn health_poll_increments_health_polls_total() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = Arc::new(connect_plain(&server, capabilities_with_healthtest()));
    let before = client.metrics_snapshot().health_polls_total;
    let monitor = HealthMonitor::start(Arc::clone(&client), Duration::from_millis(80))
        .expect("HealthMonitor::start");

    let incremented = wait_until(Duration::from_millis(200), || {
        client.metrics_snapshot().health_polls_total > before
    });
    assert!(
        incremented,
        "successful health poll must increment health_polls_total"
    );
    drop(monitor);
}

#[test]
fn failed_health_poll_increments_health_poll_failures_total() {
    let server = TestServer::start();
    server.set_health_json(default_health_json());
    let client = Arc::new(connect_plain(&server, capabilities_with_healthtest()));
    let monitor = HealthMonitor::start(Arc::clone(&client), Duration::from_millis(50))
        .expect("HealthMonitor::start");
    wait_for_first_successful_poll(&monitor);

    let before = client.metrics_snapshot().health_poll_failures_total;
    server.set_health_status(503);
    let incremented = wait_until(Duration::from_millis(400), || {
        client.metrics_snapshot().health_poll_failures_total > before
    });
    assert!(
        incremented,
        "failed health poll must increment health_poll_failures_total"
    );
    drop(monitor);
}
