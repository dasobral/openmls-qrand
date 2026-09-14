use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use reqwest::Url;

use crate::config::{ApiAuth, QrngConfig};
use crate::error::QrngError;
use crate::health::ProviderMetricsSnapshot;
use crate::model::{Capabilities, EntropyRequest, EntropyResponse, HealthReport};

struct ProviderMetrics {
    entropy_requests_total: AtomicU64,
    entropy_bytes_total: AtomicU64,
    entropy_failures_total: AtomicU64,
    health_polls_total: AtomicU64,
    health_poll_failures_total: AtomicU64,
}

impl ProviderMetrics {
    fn new() -> Self {
        Self {
            entropy_requests_total: AtomicU64::new(0),
            entropy_bytes_total: AtomicU64::new(0),
            entropy_failures_total: AtomicU64::new(0),
            health_polls_total: AtomicU64::new(0),
            health_poll_failures_total: AtomicU64::new(0),
        }
    }
}

pub struct QrngClient {
    http: reqwest::blocking::Client,
    base_url: Url,
    auth: ApiAuth,
    entropy_type: Option<String>,
    capabilities: Capabilities,
    metrics: Arc<ProviderMetrics>,
}

impl QrngClient {
    pub fn connect(config: QrngConfig) -> Result<Self, QrngError> {
        config.validate()?;

        // Task 2: one blocking client with timeout and no redirects.
        // Custom CA and mTLS identity are installed in Task 9.
        let http = reqwest::blocking::Client::builder()
            .timeout(config.request_timeout)
            .redirect(Policy::none())
            .build()?;

        let url = capabilities_url(&config.base_url);
        let response = apply_auth(http.get(url), &config.auth).send()?;
        let status = response.status();
        if !status.is_success() {
            return Err(QrngError::HttpStatus(status));
        }

        let body = response.bytes()?;
        let capabilities: Capabilities =
            serde_json::from_slice(&body).map_err(|err| QrngError::Protocol(err.to_string()))?;
        capabilities.validate()?;

        if let Some(ref configured) = config.entropy_type {
            let advertised = &capabilities.entropy.entropy_types;
            if !advertised.is_empty() && !advertised.iter().any(|t| t == configured) {
                return Err(QrngError::UnsupportedEntropyType);
            }
        }

        Ok(Self {
            http,
            base_url: config.base_url,
            auth: config.auth,
            entropy_type: config.entropy_type,
            capabilities,
            metrics: Arc::new(ProviderMetrics::new()),
        })
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub fn fetch_entropy(&self, len: usize) -> Result<Vec<u8>, QrngError> {
        if len == 0 {
            return Ok(Vec::new());
        }

        match self.fetch_entropy_inner(len) {
            Ok(out) => {
                self.metrics
                    .entropy_requests_total
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .entropy_bytes_total
                    .fetch_add(out.len() as u64, Ordering::Relaxed);
                Ok(out)
            }
            Err(err) => {
                self.metrics
                    .entropy_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    pub fn fetch_health(&self) -> Result<HealthReport, QrngError> {
        self.metrics
            .health_polls_total
            .fetch_add(1, Ordering::Relaxed);
        match self.fetch_health_inner() {
            Ok(report) => Ok(report),
            Err(err) => {
                self.metrics
                    .health_poll_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
        }
    }

    pub fn metrics_snapshot(&self) -> ProviderMetricsSnapshot {
        ProviderMetricsSnapshot {
            entropy_requests_total: self.metrics.entropy_requests_total.load(Ordering::Relaxed),
            entropy_bytes_total: self.metrics.entropy_bytes_total.load(Ordering::Relaxed),
            entropy_failures_total: self.metrics.entropy_failures_total.load(Ordering::Relaxed),
            health_polls_total: self.metrics.health_polls_total.load(Ordering::Relaxed),
            health_poll_failures_total: self
                .metrics
                .health_poll_failures_total
                .load(Ordering::Relaxed),
        }
    }

    fn fetch_entropy_inner(&self, len: usize) -> Result<Vec<u8>, QrngError> {
        let mut out = Vec::with_capacity(len);
        let min_block = self.capabilities.entropy.min_block_size;
        let max_block = self.capabilities.entropy.max_block_size;

        while out.len() < len {
            let remaining = len - out.len();
            let requested_block = remaining.min(max_block).max(min_block);
            let block = self.fetch_one_block(requested_block)?;
            let take = remaining.min(block.len());
            out.extend_from_slice(&block[..take]);
        }

        debug_assert_eq!(out.len(), len);
        Ok(out)
    }

    fn fetch_health_inner(&self) -> Result<HealthReport, QrngError> {
        let url = healthtest_url(&self.base_url);
        let response = apply_auth(self.http.get(url), &self.auth).send()?;
        let status = response.status();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            return Err(QrngError::HealthUnavailable);
        }
        if !status.is_success() {
            return Err(QrngError::HttpStatus(status));
        }

        let body = response.bytes()?;
        serde_json::from_slice(&body).map_err(|_| QrngError::Protocol("invalid JSON".to_owned()))
    }

    fn fetch_one_block(&self, n: usize) -> Result<Vec<u8>, QrngError> {
        let url = entropy_url(&self.base_url);
        let request = EntropyRequest {
            block_size: n,
            block_count: 1,
            entropy_type: self.entropy_type.as_deref(),
        };

        let response = apply_auth(self.http.post(url), &self.auth)
            .json(&request)
            .send()?;
        let status = response.status();
        if status == StatusCode::UNPROCESSABLE_ENTITY {
            return Err(QrngError::InvalidRequest);
        }
        if status == StatusCode::SERVICE_UNAVAILABLE {
            return Err(QrngError::EntropyUnavailable);
        }
        if !status.is_success() {
            return Err(QrngError::HttpStatus(status));
        }

        let body = response.bytes()?;
        let parsed: EntropyResponse = serde_json::from_slice(&body)
            .map_err(|_| QrngError::Protocol("invalid JSON".to_owned()))?;
        if parsed.entropy.len() != 1 {
            return Err(QrngError::Protocol(
                "expected exactly one entropy block".to_owned(),
            ));
        }

        let decoded = STANDARD.decode(parsed.entropy[0].as_bytes())?;
        if decoded.len() != n {
            return Err(QrngError::Protocol(
                "decoded entropy block length mismatch".to_owned(),
            ));
        }
        Ok(decoded)
    }
}

impl fmt::Debug for QrngClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QrngClient")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("entropy_type", &self.entropy_type)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

fn apply_auth(
    request: reqwest::blocking::RequestBuilder,
    auth: &ApiAuth,
) -> reqwest::blocking::RequestBuilder {
    match auth {
        ApiAuth::None => request,
        ApiAuth::Bearer(token) => {
            request.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        }
        ApiAuth::XApiKey(value) => request.header("X-API-KEY", value.as_str()),
    }
}

fn capabilities_url(base: &Url) -> Url {
    join_v1(base, "capabilities")
}

fn entropy_url(base: &Url) -> Url {
    join_v1(base, "entropy")
}

fn healthtest_url(base: &Url) -> Url {
    join_v1(base, "healthtest")
}

fn join_v1(base: &Url, resource: &str) -> Url {
    let mut url = base.clone();
    let path = url.path();
    let path = path.strip_suffix('/').unwrap_or(path);
    let joined = if path.is_empty() {
        format!("/v1/{resource}")
    } else {
        format!("{path}/v1/{resource}")
    };
    url.set_path(&joined);
    url
}
