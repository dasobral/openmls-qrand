# openmls-qrand

OpenMLS randomness provider backed by a QRNG Open API.

[![CI](https://github.com/dasobral/openmls-qrand/actions/workflows/ci.yml/badge.svg)](https://github.com/dasobral/openmls-qrand/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.91-orange.svg)](Cargo.toml)

A small, reusable Rust library that supplies QRNG-backed randomness to [OpenMLS](https://github.com/openmls/openmls).

The crate is generic and independent of agent-trust. Any OpenMLS consumer that can reach a QRNG Open API endpoint can use it. The provider implements OpenMLS `OpenMlsRand`, retrieves entropy from that endpoint, and composes with an existing OpenMLS crypto implementation and storage implementation rather than reimplementing them.

It is intended for applications that want OpenMLS protocol randomness to come from a hardware QRNG service such as Quside Entropy Core, and to fail closed if that entropy source is unavailable.

## Status

Version **0.1.0**. Consume it from git; it is not published to crates.io yet.

Minimum supported Rust version (MSRV): **1.91**. Production code is pinned to `openmls_traits = "0.6.0"` (OpenMLS 0.9.0).

## Features

- Implements the OpenMLS `OpenMlsRand` contract with QRNG Open API entropy
- Explicit transport selection: plain HTTP, TLS, or mTLS
- Optional Bearer or `X-API-KEY` authentication, independent of transport
- Fail-closed: no fallback to OS RNG, `/dev/urandom`, `getrandom`, or cached entropy
- Optional background health polling via `GET /healthtest`
- Composes with `openmls_rust_crypto` (or any `OpenMlsCrypto` + `StorageProvider`)

## Installation

```toml
[dependencies]
openmls_qrand = { git = "https://github.com/dasobral/openmls-qrand.git" }
openmls_traits = "0.6.0"
```

Consumers typically also depend on OpenMLS `0.9.0` with `openmls_rust_crypto` `0.6.0` (and, when needed, `openmls_basic_credential` `0.6.0`):

```toml
[dependencies]
openmls = "0.9.0"
openmls_rust_crypto = "0.6.0"
```

## Quick start

Compose `QrngOpenMlsProvider` with `RustCrypto` and `MemoryStorage`. Pass `&provider` to OpenMLS APIs.

```rust
use std::sync::Arc;
use std::time::Duration;

use openmls_qrand::{
    ApiAuth, HealthMonitor, QrngClient, QrngConfig, QrngOpenMlsProvider, QrngRand,
    TransportMode,
};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};

let config = QrngConfig {
    base_url: "http://127.0.0.1:8002".parse()?,
    transport: TransportMode::PlainHttp,
    auth: ApiAuth::None,
    entropy_type: None,
    request_timeout: Duration::from_secs(5),
    health_poll_interval: Some(Duration::from_secs(5)),
};

let client = Arc::new(QrngClient::connect(config)?);
let health = HealthMonitor::start(client.clone(), Duration::from_secs(5))?;
let rand = QrngRand::new(client.clone());

let provider = QrngOpenMlsProvider::new(
    RustCrypto::default(),
    MemoryStorage::default(),
    rand,
);

// Pass `&provider` to OpenMLS APIs.
let _ = (&provider, &health);
```

## Transport modes

Transport is selected explicitly. The library does not infer the security mode from the URL alone.

| Mode | Type | Base URL | Trust |
| --- | --- | --- | --- |
| Plain HTTP | `TransportMode::PlainHttp` | `http://` | No TLS |
| TLS | `TransportMode::Tls { ca_cert_pem }` | `https://` | Server authentication; HTTPS always verifies the server certificate |
| mTLS | `TransportMode::MutualTls { ca_cert_pem, client_cert_pem, client_key_pem }` | `https://` | Server authentication plus a client certificate |

There is no insecure-TLS option. `Tls { ca_cert_pem: None }` uses the rustls webpki-roots bundle (Mozilla CA set). The OS trust store is not consulted. `Tls { ca_cert_pem: Some(path) }` adds that CA PEM to the client trust store. `MutualTls` always loads a CA, client certificate, and client key.

### TLS

```rust
use std::time::Duration;

use openmls_qrand::{ApiAuth, QrngConfig, TransportMode};

let config = QrngConfig {
    base_url: "https://entropy.example.net".parse()?,
    transport: TransportMode::Tls {
        ca_cert_pem: Some("/etc/qrng/ca.pem".into()),
    },
    auth: ApiAuth::None,
    entropy_type: None,
    request_timeout: Duration::from_secs(5),
    health_poll_interval: Some(Duration::from_secs(5)),
};
```

webpki-roots only, with no extra CA file:

```rust
transport: TransportMode::Tls { ca_cert_pem: None },
```

### mTLS

```rust
use std::time::Duration;

use openmls_qrand::{ApiAuth, QrngConfig, TransportMode};

let config = QrngConfig {
    base_url: "https://entropy.example.net".parse()?,
    transport: TransportMode::MutualTls {
        ca_cert_pem: "/etc/qrng/ca.pem".into(),
        client_cert_pem: "/etc/qrng/client.crt".into(),
        client_key_pem: "/etc/qrng/client.key".into(),
    },
    auth: ApiAuth::None,
    entropy_type: None,
    request_timeout: Duration::from_secs(5),
    health_poll_interval: Some(Duration::from_secs(5)),
};
```

## Authentication

HTTP authentication is independent of transport. `ApiAuth::None` sends no auth header. Bearer sends `Authorization: Bearer …`. X-API-KEY sends `X-API-KEY`.

```rust
auth: ApiAuth::Bearer("token".to_owned()),
```

```rust
auth: ApiAuth::XApiKey("key".to_owned()),
```

These can be combined with `PlainHttp`, `Tls`, or `MutualTls`.

## Supported QRNG Open API

`QrngClient::connect` talks to the QRNG Open API over a blocking HTTP client:

- `GET /capabilities` — discovered at connect time
- `POST /entropy` — entropy retrieval for `OpenMlsRand`
- `GET /healthtest` — health reporting for `QrngClient::fetch_health` and `HealthMonitor`

The first target service is [Quside Entropy Core](https://www.quside.com/), using those routes without a `/v1` or `/api` prefix.

## Fail-closed behavior

If entropy cannot be obtained, decoded, or validated, `OpenMlsRand` returns an error.

There is no fallback to OS RNG, `/dev/urandom`, `getrandom`, `thread_rng`, RustCrypto RNG, cached entropy, or deterministic substitute data.

## Health monitoring

`HealthMonitor::start` requires the endpoint to advertise `healthtest`. Otherwise it returns `QrngError::HealthUnsupported`.

There is no `HealthMonitor::metrics_snapshot`. Health state is `health.snapshot()`. Provider activity counters live on `QrngClient::metrics_snapshot()`.

```rust
use std::sync::Arc;
use std::time::Duration;

use openmls_qrand::{HealthMonitor, QrngClient};

let client = Arc::new(QrngClient::connect(config)?);
let health = HealthMonitor::start(client.clone(), Duration::from_secs(5))?;

let snapshot = health.snapshot();
let metrics = client.metrics_snapshot();

let _ = (
    snapshot.observed_at,
    snapshot.report,
    snapshot.consecutive_failures,
    snapshot.last_error,
    metrics.entropy_requests_total,
    metrics.entropy_bytes_total,
    metrics.entropy_failures_total,
    metrics.health_polls_total,
    metrics.health_poll_failures_total,
);
```

`QrngConfig::health_poll_interval` is validated when `Some` (it must be greater than zero). The background monitor interval is the value passed to `HealthMonitor::start`, not an automatically started config side effect.

## Security claim

The library replaces the OpenMLS `OpenMlsRand` randomness source with QRNG Open API entropy.

It does not replace randomness internal to every cryptographic backend, including randomness that may be used internally by `OpenMlsCrypto` implementations such as RustCrypto (`signature_key_gen`).

It does not claim that all OpenMLS, RustCrypto, HPKE, TLS, or host-application randomness comes from the QRNG.

Implementing `OpenMlsRand` means that randomness requested by OpenMLS through that trait comes from the configured QRNG Open API entropy endpoint. It does not prove that every random choice in the full cryptographic stack comes from the QRNG.

The current `openmls_rust_crypto::RustCrypto` implementation owns an internal RNG and uses it when `signature_key_gen()` generates signature keys. Other cryptographic dependencies may also have internal randomness paths.

Auditing or replacing randomness internal to `OpenMlsCrypto` implementations is out of scope for this crate.

## Development

```bash
cargo test
cargo fmt --all -- --check
```

Live Entropy Core smoke tests are ignored by default and need a reachable QRNG Open API:

```bash
QRNG_LIVE_BASE_URL=http://127.0.0.1:8002 \
  cargo test --test live_ec_mls -- --ignored --nocapture
```

The design and API contract are in [`OPENMLS_QRNG_PROVIDER_IMPLEMENTATION_SPEC.md`](OPENMLS_QRNG_PROVIDER_IMPLEMENTATION_SPEC.md).

## Ownership

This project is maintained by **Daniel SB** ([@dasobral](https://github.com/dasobral)).

| | |
| --- | --- |
| GitHub | [@dasobral](https://github.com/dasobral) |
| Email | [dasobral93@gmail.com](mailto:dasobral93@gmail.com) |
| Code owners | [`.github/CODEOWNERS`](.github/CODEOWNERS) |
| Authors | [`AUTHORS`](AUTHORS) |

Code review requests go to `@dasobral`. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose changes and [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## License

Licensed under the [MIT License](LICENSE). Copyright (c) 2026 Daniel SB.
