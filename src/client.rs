use std::fmt;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use reqwest::redirect::Policy;
use reqwest::StatusCode;
use reqwest::Url;

use crate::config::{ApiAuth, QrngConfig};
use crate::error::QrngError;
use crate::model::{Capabilities, EntropyRequest, EntropyResponse};

pub struct QrngClient {
    http: reqwest::blocking::Client,
    base_url: Url,
    auth: ApiAuth,
    entropy_type: Option<String>,
    capabilities: Capabilities,
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
        })
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    pub fn fetch_entropy(&self, len: usize) -> Result<Vec<u8>, QrngError> {
        if len == 0 {
            return Ok(Vec::new());
        }

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
