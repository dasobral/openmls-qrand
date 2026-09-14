# openmls-qrng-provider

A small, reusable Rust library that supplies QRNG-backed randomness to OpenMLS.

This crate is generic and independent of agent-trust. Any OpenMLS consumer that can reach a QRNG Open API endpoint can use it.

The provider implements OpenMLS `OpenMlsRand`, retrieves entropy from a QRNG Open API endpoint, and composes with an existing OpenMLS crypto implementation and storage implementation rather than reimplementing them.

## Security claim

The library replaces the OpenMLS `OpenMlsRand` randomness source with QRNG Open API entropy.

It does not replace randomness internal to every cryptographic backend, including randomness that may be used internally by `OpenMlsCrypto` implementations such as RustCrypto (`signature_key_gen`).

It does not claim that all OpenMLS, RustCrypto, HPKE, TLS, or host-application randomness comes from the QRNG. See [Scope boundary](#scope-boundary).

## Installation

This crate is unpublished. Depend on it via path or git, not crates.io.

```toml
[dependencies]
openmls_qrng_provider = { path = "../openmls-qrng-provider" }
# or: openmls_qrng_provider = { git = "<repository-url>" }

openmls_traits = "0.6.0"
```

Production code in this crate is pinned to `openmls_traits = "0.6.0"`. Consumers typically use OpenMLS `0.9.0` with `openmls_rust_crypto` `0.6.0` (and, when needed, `openmls_basic_credential` `0.6.0`) as additional dependencies of the host application:

```toml
[dependencies]
openmls = "0.9.0"
openmls_rust_crypto = "0.6.0"
```

## Transport modes

Transport is selected explicitly. The library does not infer the security mode from the URL alone.

| Mode | Type | Base URL | Trust |
| --- | --- | --- | --- |
| Plain HTTP | `TransportMode::PlainHttp` | `http://` | No TLS |
| TLS | `TransportMode::Tls { ca_cert_pem }` | `https://` | Server authentication; HTTPS always verifies the server certificate |
| mTLS | `TransportMode::MutualTls { ca_cert_pem, client_cert_pem, client_key_pem }` | `https://` | Server authentication plus a client certificate |

There is no insecure-TLS option. `Tls { ca_cert_pem: None }` uses the webpki/system roots. `Tls { ca_cert_pem: Some(path) }` adds that CA PEM to the client trust store. `MutualTls` always loads a CA, client certificate, and client key.

## Supported QRNG Open API

`QrngClient::connect` talks to the QRNG Open API over a blocking HTTP client:

- `GET /v1/capabilities` — discovered at connect time
- `POST /v1/entropy` — entropy retrieval for `OpenMlsRand`
- `GET /v1/healthtest` — health reporting for `QrngClient::fetch_health` and `HealthMonitor`

## Fail-closed behavior

If entropy cannot be obtained, decoded, or validated, `OpenMlsRand` returns an error.

There is no fallback to OS RNG, `/dev/urandom`, `getrandom`, `thread_rng`, RustCrypto RNG, cached entropy, or deterministic substitute data.

## Examples

### Plain HTTP

```rust
use std::time::Duration;

use openmls_qrng_provider::{ApiAuth, QrngConfig, TransportMode};

let config = QrngConfig {
    base_url: "http://127.0.0.1:8002".parse()?,
    transport: TransportMode::PlainHttp,
    auth: ApiAuth::None,
    entropy_type: None,
    request_timeout: Duration::from_secs(5),
    health_poll_interval: Some(Duration::from_secs(5)),
};
```

### TLS

```rust
use std::time::Duration;

use openmls_qrng_provider::{ApiAuth, QrngConfig, TransportMode};

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

System or webpki roots, with no extra CA file:

```rust
transport: TransportMode::Tls { ca_cert_pem: None },
```

### mTLS

```rust
use std::time::Duration;

use openmls_qrng_provider::{ApiAuth, QrngConfig, TransportMode};

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

### Optional Bearer / X-API-KEY

HTTP authentication is independent of transport. `ApiAuth::None` sends no auth header. Bearer sends `Authorization: Bearer …`. X-API-KEY sends `X-API-KEY`.

```rust
auth: ApiAuth::Bearer("token".to_owned()),
```

```rust
auth: ApiAuth::XApiKey("key".to_owned()),
```

These can be combined with `PlainHttp`, `Tls`, or `MutualTls`.

### OpenMLS composition

Compose `QrngOpenMlsProvider` with `RustCrypto` and `MemoryStorage`. Pass `&provider` to OpenMLS APIs.

```rust
use std::sync::Arc;
use std::time::Duration;

use openmls_qrng_provider::{
    HealthMonitor, QrngClient, QrngOpenMlsProvider, QrngRand,
};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};

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

### Health monitoring

`HealthMonitor::start` requires the endpoint to advertise `healthtest`. Otherwise it returns `QrngError::HealthUnsupported`.

There is no `HealthMonitor::metrics_snapshot`. Health state is `health.snapshot()`. Provider activity counters live on `QrngClient::metrics_snapshot()`.

```rust
use std::sync::Arc;
use std::time::Duration;

use openmls_qrng_provider::{HealthMonitor, QrngClient};

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

## Scope boundary

Implementing `OpenMlsRand` means that randomness requested by OpenMLS through that trait comes from the configured QRNG Open API entropy endpoint.

It does not prove that every random choice in the full cryptographic stack comes from the QRNG.

The current `openmls_rust_crypto::RustCrypto` implementation owns an internal RNG and uses it when `signature_key_gen()` generates signature keys. Other cryptographic dependencies may also have internal randomness paths.

Auditing or replacing randomness internal to `OpenMlsCrypto` implementations is out of scope for this crate.

## License

MIT
