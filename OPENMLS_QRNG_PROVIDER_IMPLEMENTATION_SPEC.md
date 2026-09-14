# OpenMLS QRNG Provider — Implementation Design and Development Specification

**Status:** implementation-ready design  
**Date:** 2026-09-14  
**Target language:** Rust  
**Primary target:** OpenMLS 0.9.0 / `openmls_traits` 0.6.0  
**External entropy interface:** QRNG Open API over HTTP/HTTPS  
**Target entropy service:** Quside Entropy Core  
**Development model:** sub-agent-driven, test-first, minimal implementation

---

## 1. Purpose

This document specifies a small, reusable Rust library that supplies QRNG-backed randomness to OpenMLS.

The library is **not agent-trust-specific**. It must be usable by any Rust application that uses OpenMLS and has access to a QRNG Open API endpoint. Agent-trust is one consumer.

The provider must:

1. implement the current OpenMLS randomness contract, `OpenMlsRand`;
2. retrieve entropy from an Entropy Core through the QRNG Open API;
3. support three transport modes:
   - plain HTTP, with no TLS;
   - HTTPS with server-authenticated TLS;
   - HTTPS with mutual TLS (mTLS);
4. support the standard QRNG Open API calls required for:
   - capabilities discovery;
   - entropy retrieval;
   - entropy health reporting;
5. continuously poll and retain health information for real-time monitoring;
6. fail explicitly rather than silently falling back to another RNG;
7. remain small, generic, synchronous, and easy to audit;
8. compose with an existing OpenMLS crypto implementation and storage implementation rather than reimplementing them.

The first version must **not** implement a local DRBG, entropy mixing, entropy caching, automatic retries, a Prometheus server, vendor-specific policy logic, or agent-trust policy.

---

## 2. Baseline and compatibility contract

At the time this specification was written, the current stable OpenMLS release is **0.9.0**, released on 2026-08-25. Its RustCrypto backend is `openmls_rust_crypto` **0.6.0**, which depends on `openmls_traits` **0.6.0**.

The provider shall compile against:

```toml
openmls_traits = "0.6.0"
```

OpenMLS itself is required only by integration tests and examples:

```toml
[dev-dependencies]
openmls = "0.9.0"
openmls_rust_crypto = "0.6.0"
openmls_basic_credential = "0.6.0"
```

Do not depend on OpenMLS internals. The only OpenMLS production contract this crate shall rely on is the public `openmls_traits` API.

The current relevant traits are conceptually:

```rust
pub trait OpenMlsRand {
    type Error: std::error::Error + std::fmt::Debug;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error>;
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error>;
}
```

and:

```rust
pub trait OpenMlsProvider {
    type CryptoProvider: OpenMlsCrypto;
    type RandProvider: OpenMlsRand;
    type StorageProvider: StorageProvider<{ storage::CURRENT_VERSION }>;

    fn storage(&self) -> &Self::StorageProvider;
    fn crypto(&self) -> &Self::CryptoProvider;
    fn rand(&self) -> &Self::RandProvider;
}
```

Before implementation starts, the coordinator must verify these signatures against the exact pinned release. If a later stable OpenMLS release exists, update the version pins and this section first; do not silently code against `main`.

---

## 3. Critical scope boundary

Implementing `OpenMlsRand` means that randomness requested by OpenMLS through the `OpenMlsRand` trait comes from Entropy Core.

It does **not** prove that every random choice performed anywhere in the full cryptographic stack comes from Entropy Core.

For example, the current `openmls_rust_crypto::RustCrypto` implementation owns an internal RNG and uses it when its `signature_key_gen()` method generates signature keys. Other cryptographic dependencies may also have internal randomness paths.

Therefore the security claim of this library must be stated precisely:

> The library replaces the OpenMLS `OpenMlsRand` randomness source with QRNG Open API entropy.

It must **not** claim:

> All randomness used by OpenMLS, RustCrypto, HPKE, signatures, TLS, or the host application comes from the QRNG.

Auditing or replacing randomness internal to `OpenMlsCrypto` implementations is a separate project and is explicitly out of scope for version 1.

---

## 4. Design principles

The implementation shall follow these rules.

### 4.1 Fail closed

If entropy cannot be obtained, decoded, or validated, `random_array()` and `random_vec()` return an error.

There is no fallback to:

- `getrandom`;
- `/dev/urandom`;
- `rand::thread_rng()`;
- RustCrypto's own RNG;
- cached old QRNG bytes;
- deterministic substitute data.

A caller that selects this provider has explicitly selected QRNG-backed OpenMLS randomness.

### 4.2 Direct entropy retrieval in version 1

Every non-zero `OpenMlsRand` request shall ultimately be satisfied by a QRNG Open API `/v1/entropy` request.

There is no DRBG, local pool, prefetch queue, or mixing stage in version 1.

This is intentionally simple. It makes data provenance and failure behavior obvious. If later measurements show unacceptable latency, buffering or a QRNG-seeded DRBG can be designed as a separate version with its own security contract.

### 4.3 Synchronous I/O

`OpenMlsRand` is synchronous. The provider shall therefore use a synchronous HTTP client.

Use:

```toml
reqwest = {
    version = "0.12",
    default-features = false,
    features = ["blocking", "json", "rustls-tls"]
}
```

Do not introduce Tokio or an async runtime into the production crate.

### 4.4 No hidden retry policy

Entropy requests shall not be retried automatically.

Reasons:

- retries consume additional entropy;
- retries obscure availability failures;
- retries complicate timing and failure semantics;
- OpenMLS already receives a clean error and the application can decide whether to retry the higher-level operation.

Health polling naturally repeats at its configured interval, but each individual poll is a single request.

### 4.5 No TLS verification bypass

There shall be no `danger_accept_invalid_certs`, `--insecure`, or equivalent option.

Plain HTTP is supported explicitly for controlled testing or isolated trusted networks. HTTPS modes always verify the server certificate.

### 4.6 Generic QRNG Open API first

The core library shall use only standard QRNG Open API resources and fields.

Vendor-specific `extensions` shall be retained as JSON values and exposed to the caller, but the core library shall not interpret Quside-specific extensions in version 1.

---

## 5. QRNG Open API contract

The QRNG Open API defines three relevant operations.

### 5.1 Capabilities

```http
GET /v1/capabilities
```

The provider needs at least:

- `entropy.min_block_size` — optional; default to 1 byte;
- `entropy.max_block_size` — mandatory;
- `entropy.min_block_count` — optional; default to 1;
- `entropy.max_block_count` — mandatory;
- `entropy.entropy_types` — optional;
- health-test capability metadata — optional;
- `extensions` — optional.

The provider shall fetch capabilities once during connection/bootstrap and retain them.

A malformed capabilities response is a startup error.

### 5.2 Entropy

```http
POST /v1/entropy
Content-Type: application/json
```

Request:

```json
{
  "block_size": 32,
  "block_count": 1,
  "entropy_type": "optional-type"
}
```

`block_size` is mandatory. `block_count` is optional in the standard, but this provider shall always send `1` in version 1 for deterministic behavior and simple validation.

`entropy_type` shall only be sent when configured.

Response:

```json
{
  "entropy": [
    "<base64-encoded-random-bytes>"
  ],
  "extensions": []
}
```

The provider must:

1. require HTTP success;
2. require valid JSON;
3. require exactly one entropy element for `block_count = 1`;
4. Base64-decode it;
5. require the decoded block length to equal the requested `block_size`;
6. never return more or fewer bytes than the `OpenMlsRand` caller requested.

QRNG Open API status `422` is a protocol/request error. Status `503` is an entropy-source-unavailable error. Both must be distinguishable in `QrngError`.

### 5.3 Health test

```http
GET /v1/healthtest
```

The standard response contains a list of health-test results with fields such as:

```json
{
  "test_result": [
    {
      "test_type": "nist_90b",
      "test_result": 0.94,
      "time_stamp": "2026-09-14T10:00:00Z",
      "report_link": "https://..."
    }
  ],
  "extensions": []
}
```

The standard does not provide one universal semantic rule saying that every numeric result above or below a particular value means "healthy". The provider must therefore preserve the test type, value, timestamp, report link, and extensions without inventing a portable pass/fail threshold.

If an Entropy Core returns explicit vendor health state inside `extensions`, a later Entropy-Core-specific adapter may interpret it. That policy does not belong in the generic provider.

---

## 6. Transport and authentication modes

Use one explicit transport enum. Do not infer security mode solely from a URL.

```rust
pub enum TransportMode {
    PlainHttp,
    Tls {
        ca_cert_pem: Option<PathBuf>,
    },
    MutualTls {
        ca_cert_pem: PathBuf,
        client_cert_pem: PathBuf,
        client_key_pem: PathBuf,
    },
}
```

### 6.1 Plain HTTP

Configuration:

```text
scheme: http
transport: PlainHttp
```

Rules:

- URL must use `http://`;
- no TLS material is loaded;
- intended for local development, test environments, or explicitly controlled isolated networks;
- never silently downgrade an `https://` URL.

### 6.2 TLS

Configuration:

```text
scheme: https
transport: Tls
```

Rules:

- URL must use `https://`;
- server certificate validation is mandatory;
- if `ca_cert_pem` is absent, use the configured/system trust roots exposed by the HTTP/TLS stack;
- if `ca_cert_pem` is present, add that CA certificate to the client's trust store;
- do not load a client identity.

### 6.3 mTLS

Configuration:

```text
scheme: https
transport: MutualTls
```

Rules:

- URL must use `https://`;
- server certificate validation is mandatory;
- load the configured CA;
- load the client certificate and private key;
- present the client certificate during the TLS handshake;
- failure to load any certificate/key file is a configuration error;
- no password prompting or interactive credential loading.

### 6.4 Optional QRNG Open API HTTP authentication

Support only the two authentication mechanisms explicitly described by the QRNG Open API plus no HTTP authentication:

```rust
pub enum ApiAuth {
    None,
    Bearer(String),
    XApiKey(String),
}
```

Mapping:

```text
Bearer(token)  -> Authorization: Bearer <token>
XApiKey(value) -> X-API-KEY: <value>
None           -> no authentication header
```

Do not implement Basic Auth or proprietary headers in version 1.

`ApiAuth` must use a custom `Debug` implementation that never prints token values.

---

## 7. Public configuration

The public configuration surface shall be intentionally small:

```rust
pub struct QrngConfig {
    pub base_url: reqwest::Url,
    pub transport: TransportMode,
    pub auth: ApiAuth,
    pub entropy_type: Option<String>,
    pub request_timeout: Duration,
    pub health_poll_interval: Option<Duration>,
}
```

Defaults:

```text
request_timeout      = 5 seconds
health_poll_interval = Some(5 seconds)
entropy_type         = None
auth                 = None
```

Configuration validation must reject:

- `PlainHttp` with an `https://` URL;
- `Tls` with an `http://` URL;
- `MutualTls` with an `http://` URL;
- zero request timeout;
- zero health polling interval;
- unreadable TLS files;
- malformed PEM material;
- base URLs containing query strings or fragments.

The base URL may contain a path prefix, but endpoint construction must be deterministic.

Examples:

```text
http://127.0.0.1:8002
https://entropy.example.net
https://entropy.example.net/qrng
```

shall resolve respectively to:

```text
http://127.0.0.1:8002/v1/entropy
https://entropy.example.net/v1/entropy
https://entropy.example.net/qrng/v1/entropy
```

---

## 8. Crate architecture

Repository name:

```text
openmls-qrand
```

Crate name:

```text
openmls_qrand
```

Required tree:

```text
openmls-qrand/
├── Cargo.toml
├── README.md
├── LICENSE
├── src/
│   ├── lib.rs
│   ├── config.rs
│   ├── error.rs
│   ├── model.rs
│   ├── client.rs
│   ├── rand.rs
│   ├── health.rs
│   └── provider.rs
└── tests/
    ├── common/
    │   ├── mod.rs
    │   └── test_server.rs
    ├── config.rs
    ├── qrng_api.rs
    ├── transport.rs
    ├── rand_contract.rs
    ├── health_monitor.rs
    └── openmls_integration.rs
```

Each file has exactly one responsibility.

### `config.rs`

Owns:

- `QrngConfig`;
- `TransportMode`;
- `ApiAuth`;
- defaults;
- configuration validation;
- HTTP client construction inputs.

It performs no network I/O.

### `error.rs`

Owns the complete public error enum.

### `model.rs`

Owns serde types for:

- capabilities;
- entropy request;
- entropy response;
- health response;
- API extensions.

No behavior beyond small validation helpers.

### `client.rs`

Owns QRNG Open API I/O:

- connect/bootstrap;
- capability fetch;
- entropy fetch;
- health fetch;
- endpoint construction;
- response status handling;
- Base64 decoding and size validation;
- internal counters.

It knows nothing about OpenMLS.

### `rand.rs`

Owns `QrngRand` and the `OpenMlsRand` implementation.

It knows nothing about MLS groups, credentials, policies, or applications.

### `health.rs`

Owns:

- health snapshots;
- provider activity snapshots;
- background polling thread;
- clean shutdown.

It does not expose an HTTP server and does not depend on Prometheus.

### `provider.rs`

Owns a generic composition wrapper implementing `OpenMlsProvider` with:

- caller-provided crypto provider;
- caller-provided storage provider;
- `QrngRand` as the randomness provider.

It contains no cryptographic algorithms.

### `lib.rs`

Only re-exports the intended public API. It contains no substantial logic.

---

## 9. Data models

Use serde with conservative parsing.

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct Capabilities {
    pub entropy: EntropyCapabilities,

    // The QRNG Open API makes health capability metadata optional and
    // implementations may expose vendor-specific detail here. Presence
    // means the endpoint advertises health-test support; preserve the
    // capability object without inventing a vendor-independent schema.
    #[serde(default)]
    pub healthtest: Option<serde_json::Value>,

    #[serde(default)]
    pub source_count: Option<u32>,

    #[serde(default)]
    pub extensions: Vec<serde_json::Value>,
}
```

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct EntropyCapabilities {
    #[serde(default = "default_one")]
    pub min_block_size: usize,

    pub max_block_size: usize,

    #[serde(default = "default_one")]
    pub min_block_count: usize,

    pub max_block_count: usize,

    #[serde(default)]
    pub entropy_types: Vec<String>,

    #[serde(default)]
    pub extensions: Vec<serde_json::Value>,
}
```

Validate after deserialization:

```text
min_block_size >= 1
max_block_size >= min_block_size
min_block_count >= 1
max_block_count >= min_block_count
```

Entropy request:

```rust
#[derive(Debug, Serialize)]
struct EntropyRequest<'a> {
    block_size: usize,
    block_count: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    entropy_type: Option<&'a str>,
}
```

Entropy response:

```rust
#[derive(Debug, Deserialize)]
struct EntropyResponse {
    entropy: Vec<String>,

    #[serde(default)]
    extensions: Vec<serde_json::Value>,
}
```

Health test result:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct HealthTestResult {
    pub test_type: String,
    pub test_result: serde_json::Value,
    pub time_stamp: String,

    #[serde(default)]
    pub report_link: Option<String>,
}
```

Use `serde_json::Value` for `test_result` because the standard describes the field generically and deployed implementations may not all use the same primitive representation.

Health response:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct HealthReport {
    #[serde(default)]
    pub test_result: Vec<HealthTestResult>,

    #[serde(default)]
    pub extensions: Vec<serde_json::Value>,
}
```

Unknown JSON fields must be ignored for forward compatibility.

---

## 10. Error model

Use one public error type.

```rust
#[derive(Debug, thiserror::Error)]
pub enum QrngError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("unable to read TLS material: {0}")]
    TlsMaterial(String),

    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("QRNG API rejected the request: HTTP 422")]
    InvalidRequest,

    #[error("QRNG entropy source unavailable: HTTP 503")]
    EntropyUnavailable,

    #[error("QRNG health source unavailable: HTTP 503")]
    HealthUnavailable,

    #[error("unexpected QRNG API status: {0}")]
    HttpStatus(reqwest::StatusCode),

    #[error("invalid QRNG API response: {0}")]
    Protocol(String),

    #[error("invalid base64 entropy: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("configured entropy type is not advertised by the QRNG")]
    UnsupportedEntropyType,

    #[error("health monitoring is not supported by this QRNG endpoint")]
    HealthUnsupported,
}
```

Do not include:

- entropy bytes;
- bearer tokens;
- API keys;
- private-key contents;
- client certificate private material

in error strings or logs.

---

## 11. QRNG API client

Core type:

```rust
pub struct QrngClient {
    http: reqwest::blocking::Client,
    base_url: reqwest::Url,
    auth: ApiAuth,
    entropy_type: Option<String>,
    capabilities: Capabilities,
    metrics: Arc<ProviderMetrics>,
}
```

Construction:

```rust
impl QrngClient {
    pub fn connect(config: QrngConfig) -> Result<Self, QrngError>;
}
```

`connect()` performs, in order:

1. validate configuration;
2. construct the blocking HTTP client;
3. configure TLS or mTLS;
4. build `GET /v1/capabilities`;
5. apply optional QRNG API authentication;
6. send exactly one request;
7. require successful response;
8. parse and validate capabilities;
9. validate configured `entropy_type`, if the endpoint advertises a non-empty list;
10. return the initialized client.

Do not start the health thread inside `QrngClient::connect()`.

This keeps the API client deterministic and testable.

---

## 12. Entropy request algorithm

Public method:

```rust
pub fn fetch_entropy(&self, len: usize) -> Result<Vec<u8>, QrngError>;
```

### 12.1 Zero length

If `len == 0`, return:

```rust
Ok(Vec::new())
```

without network I/O.

### 12.2 General case

Version 1 always uses:

```text
block_count = 1
```

For each request:

```text
remaining = requested length - bytes already collected
block_size = min(remaining, max_block_size)
if block_size < min_block_size:
    block_size = min_block_size
```

Send:

```json
{
  "block_size": block_size,
  "block_count": 1
}
```

plus `entropy_type` when configured.

Validate the returned block exactly.

Append:

```text
min(remaining, decoded_block.len())
```

bytes to the result.

If the final call had to request `min_block_size` bytes to satisfy a smaller remainder, discard the unused tail. Never retain it for a future call in version 1.

Pseudocode:

```rust
fn fetch_entropy(&self, len: usize) -> Result<Vec<u8>, QrngError> {
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(len);

    while out.len() < len {
        let remaining = len - out.len();
        let requested_block = remaining
            .min(self.capabilities.entropy.max_block_size)
            .max(self.capabilities.entropy.min_block_size);

        let block = self.fetch_one_block(requested_block)?;

        let take = remaining.min(block.len());
        out.extend_from_slice(&block[..take]);
    }

    debug_assert_eq!(out.len(), len);
    Ok(out)
}
```

This algorithm is deliberately simpler than optimizing `block_count`.

### 12.3 Strict response validation

`fetch_one_block(n)` must reject:

- empty `entropy` array;
- more than one element;
- invalid Base64;
- decoded length not equal to `n`;
- HTTP 422;
- HTTP 503;
- any unexpected non-success status;
- malformed JSON.

Successful entropy bytes must never be logged.

---

## 13. OpenMLS randomness adapter

Type:

```rust
pub struct QrngRand {
    client: Arc<QrngClient>,
}
```

Constructor:

```rust
impl QrngRand {
    pub fn new(client: Arc<QrngClient>) -> Self;
}
```

Trait:

```rust
impl OpenMlsRand for QrngRand {
    type Error = QrngError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let bytes = self.client.fetch_entropy(N)?;
        bytes
            .try_into()
            .map_err(|_| QrngError::Protocol(
                "internal entropy length mismatch".into()
            ))
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.client.fetch_entropy(len)
    }
}
```

No additional logic belongs here.

The OpenMLS adapter should remain approximately this small.

---

## 14. Generic OpenMLS provider wrapper

The library shall offer a composition wrapper so callers do not need to implement `OpenMlsProvider` themselves.

```rust
pub struct QrngOpenMlsProvider<C, S> {
    crypto: C,
    storage: S,
    rand: QrngRand,
}
```

Constructor:

```rust
impl<C, S> QrngOpenMlsProvider<C, S> {
    pub fn new(crypto: C, storage: S, rand: QrngRand) -> Self {
        Self {
            crypto,
            storage,
            rand,
        }
    }
}
```

Trait implementation:

```rust
impl<C, S> OpenMlsProvider for QrngOpenMlsProvider<C, S>
where
    C: OpenMlsCrypto,
    S: StorageProvider<{ openmls_traits::storage::CURRENT_VERSION }>,
{
    type CryptoProvider = C;
    type RandProvider = QrngRand;
    type StorageProvider = S;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}
```

Do not put health monitoring into the `OpenMlsProvider` trait implementation. It is an orthogonal observability concern.

Example composition:

```rust
use openmls_rust_crypto::{MemoryStorage, RustCrypto};

let client = Arc::new(QrngClient::connect(config)?);
let rand = QrngRand::new(client.clone());

let provider = QrngOpenMlsProvider::new(
    RustCrypto::default(),
    MemoryStorage::default(),
    rand,
);
```

The production crate shall not require `openmls_rust_crypto`; it is only one possible consumer choice.

---

## 15. Health monitoring

Health monitoring uses the same `QrngClient`, transport mode, CA trust, mTLS identity, and QRNG API authentication as entropy retrieval.

### 15.1 Snapshot model

```rust
#[derive(Debug, Clone)]
pub struct HealthSnapshot {
    pub observed_at: SystemTime,
    pub report: Option<HealthReport>,
    pub consecutive_failures: u64,
    pub last_error: Option<String>,
}
```

Initial state before the first poll:

```text
report               = None
consecutive_failures = 0
last_error            = None
```

The snapshot represents **what the endpoint reported**, not a library-invented statistical verdict.

### 15.2 Provider activity metrics

Maintain simple atomics:

```rust
struct ProviderMetrics {
    entropy_requests_total: AtomicU64,
    entropy_bytes_total: AtomicU64,
    entropy_failures_total: AtomicU64,
    health_polls_total: AtomicU64,
    health_poll_failures_total: AtomicU64,
}
```

Expose a copyable public snapshot:

```rust
#[derive(Debug, Clone, Copy)]
pub struct ProviderMetricsSnapshot {
    pub entropy_requests_total: u64,
    pub entropy_bytes_total: u64,
    pub entropy_failures_total: u64,
    pub health_polls_total: u64,
    pub health_poll_failures_total: u64,
}
```

Do not depend on a metrics framework in version 1.

This allows agent-trust, a CLI, a daemon, Prometheus exporter, GUI, or other application to consume the same provider without coupling the crate to a monitoring stack.

### 15.3 Background monitor

Type:

```rust
pub struct HealthMonitor {
    state: Arc<RwLock<HealthSnapshot>>,
    stop_tx: Option<std::sync::mpsc::Sender<()>>,
    join: Option<std::thread::JoinHandle<()>>,
}
```

Creation:

```rust
pub fn start(
    client: Arc<QrngClient>,
    interval: Duration,
) -> Result<Self, QrngError>;
```

Behavior:

1. reject zero interval;
2. verify that health monitoring is available when required;
3. spawn one named background thread;
4. perform an immediate health poll;
5. update snapshot;
6. wait using `recv_timeout(interval)`;
7. poll again on timeout;
8. exit immediately when stop signal is received.

Do not implement shutdown by `sleep(interval)`, because dropping the monitor could otherwise block for the entire polling interval.

On successful poll:

```text
report               = Some(report)
consecutive_failures = 0
last_error            = None
```

On failed poll:

```text
retain previous successful report
consecutive_failures += 1
last_error = sanitized error string
```

`Drop` must:

1. signal stop;
2. join the thread;
3. never panic.

### 15.4 Public access

```rust
impl HealthMonitor {
    pub fn snapshot(&self) -> HealthSnapshot;
}
```

and:

```rust
impl QrngClient {
    pub fn metrics_snapshot(&self) -> ProviderMetricsSnapshot;
}
```

These two snapshots are the entire observability API in version 1.

### 15.5 Health does not silently gate entropy

The monitor does not refuse entropy based on an arbitrary health-test numeric value.

Entropy retrieval fails when:

- the entropy endpoint fails;
- the QRNG API explicitly returns source unavailable;
- the response is invalid.

If a future Entropy Core profile defines a portable explicit "usable / not usable" health semantic, gating can be added as a separately specified policy layer.

---

## 16. TLS implementation details

Build exactly one `reqwest::blocking::Client` per `QrngClient`.

Common settings:

```text
timeout = config.request_timeout
redirect policy = none
```

Redirects should be disabled. An entropy endpoint must not silently redirect authentication, mTLS credentials, or entropy requests to another host.

### Plain HTTP

Do not add certificates or identities.

### TLS

If a custom CA is provided:

1. read PEM bytes;
2. parse with `reqwest::Certificate::from_pem`;
3. call `add_root_certificate`.

Do not replace normal verification with an insecure verifier.

### mTLS

1. read CA PEM;
2. read client certificate PEM;
3. read client private-key PEM;
4. construct one client identity accepted by the rustls-backed reqwest client;
5. install the CA;
6. install the identity.

Certificate and key data shall only live long enough to construct the client. Do not retain raw PEM contents in public structs.

Paths may be retained in configuration for diagnostics, but private key contents must never be printable.

---

## 17. Logging rules

Use `tracing` only if the host project already standardizes on it. Otherwise use no logging dependency in version 1.

If logging is added, permitted fields are:

- endpoint host;
- operation (`capabilities`, `entropy`, `healthtest`);
- requested entropy length;
- HTTP status;
- latency;
- error category;
- health test type;
- health timestamp.

Never log:

- entropy bytes;
- Base64 entropy response strings;
- authentication tokens;
- API keys;
- private keys;
- full client identity material.

---

## 18. Deliberate non-features

Do not implement any of the following in the first version:

- local DRBG;
- entropy pool;
- entropy caching;
- entropy mixing with OS RNG;
- automatic retries;
- circuit breaker;
- load balancing across multiple Entropy Cores;
- QRNG source selection;
- custom statistics on entropy bytes;
- NIST SP 800-90B tests locally;
- Prometheus HTTP endpoint;
- OpenTelemetry exporter;
- agent identity;
- MLS membership policy;
- agent-trust authorization;
- credential generation;
- signature implementation;
- HPKE implementation;
- OpenMLS storage implementation;
- TLS for MLS transport;
- vendor-specific Entropy Core extension interpretation;
- dynamic configuration reload;
- "insecure TLS" mode.

Any of these requires a new specification or a clearly scoped version 2.

---

## 19. Cargo dependencies

Production dependencies should remain close to:

```toml
[dependencies]
openmls_traits = "0.6.0"
reqwest = { version = "0.12", default-features = false, features = ["blocking", "json", "rustls-tls"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
base64 = "0.22"
thiserror = "2"
```

Do not add dependencies without demonstrating that the standard library or an existing dependency cannot handle the requirement cleanly.

Development dependencies may include:

```toml
[dev-dependencies]
openmls = "0.9.0"
openmls_rust_crypto = "0.6.0"
openmls_basic_credential = "0.6.0"
rcgen = "0.14"
rustls = "0.23"
```

The exact test-server helper dependency set may be adjusted to the current compatible versions, but the production dependency surface must remain minimal.

---

## 20. Required tests

Tests are contract tests, not randomness-quality tests. Do not try to statistically prove that QRNG output is random in CI.

### 20.1 Configuration tests

Required cases:

```text
PlainHttp + http URL                 -> accepted
PlainHttp + https URL                -> rejected
Tls + https URL                      -> accepted
Tls + http URL                       -> rejected
MutualTls + https URL                -> accepted
MutualTls + http URL                 -> rejected
zero request timeout                 -> rejected
zero health interval                 -> rejected
URL with query                       -> rejected
URL with fragment                    -> rejected
```

### 20.2 Capabilities tests

Required cases:

- valid capabilities accepted;
- missing `min_block_size` defaults to 1;
- missing `min_block_count` defaults to 1;
- missing mandatory `max_block_size` rejected;
- impossible min/max relationship rejected;
- configured supported entropy type accepted;
- configured unsupported advertised type rejected;
- unknown JSON fields ignored.

### 20.3 Entropy API tests

Required cases:

- `fetch_entropy(0)` performs no request;
- exact single block returned;
- request larger than `max_block_size` causes multiple requests;
- remainder smaller than `min_block_size` fetches minimum block and discards the tail;
- HTTP 422 maps to `InvalidRequest`;
- HTTP 503 maps to `EntropyUnavailable`;
- other non-success status maps to `HttpStatus`;
- malformed JSON rejected;
- empty entropy array rejected;
- multiple entropy blocks rejected because v1 asks for one;
- invalid Base64 rejected;
- decoded block shorter than requested rejected;
- decoded block longer than requested rejected;
- entropy bytes never appear in error text.

### 20.4 Authentication tests

Required cases:

- `None` sends no auth header;
- `Bearer` sends the correct `Authorization` header;
- `XApiKey` sends the correct `X-API-KEY` header;
- `Debug` formatting never reveals the bearer token or API key.

### 20.5 Transport tests

A local test server must cover the actual handshake behavior, not merely configuration structure.

Required cases:

- plain HTTP succeeds;
- TLS with trusted test CA succeeds;
- TLS with untrusted CA fails;
- mTLS with trusted client certificate succeeds;
- mTLS without client identity fails;
- mTLS with client certificate from the wrong CA fails;
- HTTPS certificate hostname mismatch fails.

The test server must use generated ephemeral test certificates. Never commit private production keys.

### 20.6 `OpenMlsRand` contract tests

Required assertions:

- `random_array::<32>()` returns exactly 32 bytes supplied by the mock QRNG;
- `random_vec(64)` returns exactly 64 bytes;
- QRNG failure propagates as `QrngError`;
- no OS-RNG fallback is observed after QRNG failure;
- two concurrent callers do not corrupt response handling.

Do not assert that two random results are unequal. The test server should serve deterministic fixtures.

### 20.7 Health tests

Required cases:

- successful health response stored in snapshot;
- unknown extension preserved;
- `test_result` supports numeric and string JSON values;
- immediate first poll occurs;
- repeated poll happens after interval;
- failed poll increments failure counter;
- failed poll retains last successful report;
- later success resets consecutive failures;
- monitor drop shuts the thread down promptly;
- health 503 maps to `HealthUnavailable`;
- unsupported health capability maps to `HealthUnsupported` when monitoring is requested.

### 20.8 Provider metrics tests

Required cases:

- successful entropy call increments request counter;
- returned byte count increments byte counter;
- failed entropy call increments failure counter;
- health poll increments health counter;
- failed health poll increments health failure counter.

### 20.9 OpenMLS integration test

Use the real pinned OpenMLS release.

The test shall:

1. run a local deterministic QRNG Open API test server;
2. create `QrngClient`;
3. create `QrngRand`;
4. compose `QrngOpenMlsProvider<RustCrypto, MemoryStorage>`;
5. invoke at least one real OpenMLS operation that consumes `provider.rand()`;
6. verify from the server request log that `/v1/entropy` was called;
7. complete the OpenMLS operation successfully.

Prefer a small KeyPackage or group-creation path rather than a full messaging application.

The integration test proves compatibility with the current OpenMLS public contract. It does not claim that all internal RustCrypto randomness is QRNG-backed.

---

## 21. Test infrastructure

Do not mock `QrngClient` in contract tests.

Use a real loopback server.

The test helper in:

```text
tests/common/test_server.rs
```

must support:

- HTTP;
- TLS;
- mTLS;
- deterministic JSON responses;
- deterministic entropy bytes encoded as Base64;
- request inspection;
- configurable status responses;
- test certificate generation.

Keep all server complexity in test code. Production code must not contain test hooks.

Tests must bind to `127.0.0.1` on an OS-assigned port.

Do not require Internet connectivity.

---

## 22. Sub-agent-driven, test-first development workflow

Implementation starts from an empty repository and proceeds task by task.

The coordinator owns:

- the specification;
- worktree;
- dependency versions;
- task decomposition;
- integration;
- test execution;
- commits;
- final verification;
- packaging.

Workers must not spawn further workers.

Workers receive only:

- this specification;
- their task brief;
- files/interfaces relevant to that task;
- required command(s).

They do not inherit the full conversation or unrelated project context.

### 22.1 Hard TDD rule

No production behavior is written before a test demonstrating that behavior has been run and has failed for the expected reason.

For every behavior:

```text
RED
  test-author writes the smallest relevant test
  coordinator runs it
  failure is recorded and confirmed to be caused by missing behavior

GREEN
  a separate implementer writes the minimum production code
  coordinator runs the focused test
  coordinator runs the full suite

REFACTOR
  implementer or coordinator performs only behavior-preserving cleanup
  full suite remains green
```

Do not weaken a test to make an implementation pass.

If the test was wrong, the coordinator records why before changing it.

### 22.2 Separate test author and implementer

For each substantive task:

1. fresh **test-author agent** writes only the tests and test support required for that task;
2. coordinator executes them and records the expected RED failure;
3. fresh **implementer agent** writes production code only;
4. coordinator executes focused and full tests;
5. fresh **reviewer agent** checks:
   - specification compliance;
   - unnecessary functionality;
   - error handling;
   - security behavior;
   - test adequacy;
   - code simplicity.

The reviewer must not be the task implementer.

### 22.3 Task isolation

Use one isolated git worktree.

Do not implement directly on `main` or `master`.

Maintain:

```text
.superpowers/sdd/openmls-qrand/progress.md
```

or an equivalent git-ignored ledger.

For every task record:

```text
Task
Base commit
Test-author agent
RED command
RED exit code
Expected failure
Implementer agent
GREEN command
GREEN exit code
Full-suite command
Full-suite exit code
Review findings
Fix rounds
Final commit
```

This ledger is the recovery source if the session is interrupted.

### 22.4 No parallel edits to shared files

Parallelize only truly independent work.

In this project most implementation tasks are sequential because they share public interfaces. Do not run multiple agents concurrently against:

- `src/config.rs`;
- `src/client.rs`;
- `src/model.rs`;
- `src/error.rs`;
- `src/provider.rs`;
- `Cargo.toml`.

The coordinator integrates one reviewed task before the next task consumes its interfaces.

---

## 23. Implementation task sequence

### Task 1 — Repository bootstrap and configuration contract

**Goal:** establish the crate and configuration types.

Test author creates:

```text
tests/config.rs
```

covering the matrix in section 20.1.

Expected RED: crate/types do not exist.

Implementer creates:

```text
Cargo.toml
src/lib.rs
src/config.rs
src/error.rs
```

Production behavior is limited to configuration representation and validation.

Exit gate:

```bash
cargo fmt --check
cargo test --test config
cargo clippy --all-targets --all-features -- -D warnings
```

### Task 2 — QRNG Open API models and capabilities bootstrap

Test author creates capability contract tests in:

```text
tests/qrng_api.rs
tests/common/mod.rs
tests/common/test_server.rs
```

Implementer creates:

```text
src/model.rs
src/client.rs
```

Implement only:

```rust
QrngClient::connect(config)
QrngClient::capabilities()
```

No entropy retrieval yet.

Exit gate:

```bash
cargo test --test qrng_api capabilities
cargo test
```

### Task 3 — Authentication

Test author adds header-observation tests.

Implementer adds only:

```text
ApiAuth::None
ApiAuth::Bearer
ApiAuth::XApiKey
```

and a single internal request-authentication helper.

Do not duplicate auth logic across endpoints.

### Task 4 — Entropy retrieval

Test author adds all entropy cases from section 20.3.

Coordinator confirms RED.

Implementer adds:

```rust
QrngClient::fetch_entropy()
```

and private `fetch_one_block()`.

Do not implement `OpenMlsRand` in this task.

### Task 5 — OpenMLS randomness adapter

Test author creates:

```text
tests/rand_contract.rs
```

Implementer creates:

```text
src/rand.rs
```

with only `QrngRand` and `OpenMlsRand`.

Exit gate includes:

```bash
cargo test --test rand_contract
cargo test
```

### Task 6 — Health API and snapshots

Test author adds direct health-call parsing tests.

Implementer adds health data models and:

```rust
QrngClient::fetch_health()
```

No background thread yet.

### Task 7 — Background health monitor and metrics

Test author creates:

```text
tests/health_monitor.rs
```

covering polling, failure retention, counters, and prompt shutdown.

Implementer creates:

```text
src/health.rs
```

and minimal metrics bookkeeping in `client.rs`.

No exporter.

### Task 8 — Generic `OpenMlsProvider` composition

Test author adds compile/runtime composition tests.

Implementer creates:

```text
src/provider.rs
```

with `QrngOpenMlsProvider<C, S>`.

Keep the wrapper generic.

### Task 9 — Real TLS and mTLS transport verification

Test author extends the loopback test server with ephemeral CA/server/client certificates and adds all transport cases in:

```text
tests/transport.rs
```

The test author must not change production TLS code.

Coordinator confirms the TLS/mTLS tests fail before implementation.

Implementer updates only transport construction in `config.rs` / `client.rs`.

No insecure verification switches are permitted.

### Task 10 — Real OpenMLS integration

Test author creates:

```text
tests/openmls_integration.rs
```

using the pinned OpenMLS crates.

Coordinator confirms RED or compile failure caused by missing integration surface.

Implementer makes the minimum API adjustments required for the real OpenMLS operation.

Do not add application features.

### Task 11 — Documentation and final audit

A documentation agent updates:

```text
README.md
```

with:

- purpose;
- exact security claim;
- installation;
- plain HTTP example;
- TLS example;
- mTLS example;
- optional Bearer/X-API-KEY example;
- OpenMLS composition example;
- health monitoring example;
- known scope boundary around crypto-backend-internal randomness.

A fresh security/code reviewer audits the complete branch.

Required final commands:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo doc --no-deps
```

All must exit `0`.

---

## 24. Definition of done

The provider is complete only when all of the following are true:

- `OpenMlsRand` is implemented against `openmls_traits` 0.6.0 or the explicitly updated current stable contract;
- plain HTTP works;
- server-authenticated TLS works;
- mTLS works;
- invalid TLS trust fails;
- missing mTLS identity fails;
- QRNG Open API capabilities are discovered and validated;
- entropy is retrieved via `POST /v1/entropy`;
- entropy is Base64-decoded and length-checked;
- large requests are split according to `max_block_size`;
- no fallback RNG exists;
- health data is retrieved via `GET /v1/healthtest`;
- health polling runs independently of MLS calls;
- provider counters are observable;
- health extensions are retained;
- no vendor-specific health threshold is invented;
- the generic `OpenMlsProvider` wrapper composes with the real RustCrypto and storage traits;
- a real OpenMLS integration test invokes the QRNG endpoint;
- no secret or entropy bytes are logged;
- no TLS verification bypass exists;
- all production dependencies are justified;
- full test, clippy, format, and documentation checks pass;
- final reviewer reports no unresolved load-bearing issue.

---

## 25. Example final usage

Plain HTTP:

```rust
let config = QrngConfig {
    base_url: "http://127.0.0.1:8002".parse()?,
    transport: TransportMode::PlainHttp,
    auth: ApiAuth::None,
    entropy_type: None,
    request_timeout: Duration::from_secs(5),
    health_poll_interval: Some(Duration::from_secs(5)),
};
```

TLS:

```rust
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

mTLS:

```rust
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

Provider composition:

```rust
use std::sync::Arc;

use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_qrand::{
    HealthMonitor,
    QrngClient,
    QrngOpenMlsProvider,
    QrngRand,
};

let client = Arc::new(QrngClient::connect(config)?);

let health = HealthMonitor::start(
    client.clone(),
    Duration::from_secs(5),
)?;

let rand = QrngRand::new(client.clone());

let provider = QrngOpenMlsProvider::new(
    RustCrypto::default(),
    MemoryStorage::default(),
    rand,
);

// Pass `&provider` to OpenMLS APIs.
// Read `health.snapshot()` for QRNG health.
// Read `client.metrics_snapshot()` for provider activity.
```

This is the intended abstraction boundary:

```text
Application / agent-trust / messaging client
                    |
                    v
             OpenMLS 0.9.x
                    |
          OpenMlsProvider
          /       |       \
         /        |        \
 RustCrypto    QrngRand    Storage
                  |
                  v
              QrngClient
                  |
       QRNG Open API over HTTP
          /        |        \
     no TLS       TLS       mTLS
                  |
                  v
            Entropy Core
          /v1/capabilities
          /v1/entropy
          /v1/healthtest
```

---

## 26. Security claims and non-claims

### Claims supported by this design

When configured and functioning correctly:

- every byte returned through this instance's `OpenMlsRand` implementation is obtained from the configured QRNG Open API entropy endpoint;
- an unavailable or invalid QRNG does not silently fall back to another RNG;
- HTTPS validates the Entropy Core server;
- mTLS additionally authenticates the client at the TLS layer;
- QRNG health-test data is available to the host application with low polling latency;
- the provider is independent of agent-trust.

### Claims not supported by this design

This design alone does not establish that:

- all randomness inside the crypto provider comes from the QRNG;
- TLS itself uses QRNG entropy;
- the QRNG health score has a universal pass/fail interpretation;
- the network path is secure in plain HTTP mode;
- OpenMLS authorization or group membership is correct;
- agent-trust policies are enforced;
- the Entropy Core itself is uncompromised.

Those are separate system properties.

---

## 27. References verified for this specification

1. **OpenMLS 0.9.0 release**, 2026-08-25  
   https://blog.openmls.tech/posts/2026-08-25-0.9.0-release/

2. **OpenMLS 0.9.0 crate documentation**  
   https://docs.rs/crate/openmls/0.9.0

3. **OpenMLS public documentation**  
   https://latest.openmls.tech/doc/openmls/

4. **`openmls_rust_crypto` 0.6.0** — current RustCrypto backend and its dependency on `openmls_traits` 0.6.0  
   https://docs.rs/crate/openmls_rust_crypto/0.6.0

5. **OpenMLS RustCrypto source** — demonstrates that the crypto backend has internal RNG use in addition to the separate `OpenMlsRand` contract  
   https://docs.rs/openmls_rust_crypto/latest/src/openmls_rust_crypto/provider.rs.html

6. **QRNG Open API** — capabilities, entropy, health-test, TLS/mTLS and authentication conventions  
   https://github.com/PaloAltoNetworks/QRNG-OPENAPI

---
