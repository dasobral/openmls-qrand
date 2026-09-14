use std::fmt;

use reqwest::redirect::Policy;
use reqwest::Url;

use crate::config::{ApiAuth, QrngConfig};
use crate::error::QrngError;
use crate::model::Capabilities;

pub struct QrngClient {
    #[allow(dead_code)]
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
        let response = http.get(url).send()?;
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
}

impl fmt::Debug for QrngClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QrngClient")
            .field("base_url", &self.base_url)
            .field(
                "auth",
                &match self.auth {
                    ApiAuth::None => "None",
                    ApiAuth::Bearer(_) => "Bearer",
                    ApiAuth::XApiKey(_) => "XApiKey",
                },
            )
            .field("entropy_type", &self.entropy_type)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

fn capabilities_url(base: &Url) -> Url {
    let mut url = base.clone();
    let path = url.path();
    let path = path.strip_suffix('/').unwrap_or(path);
    let joined = if path.is_empty() {
        "/v1/capabilities".to_owned()
    } else {
        format!("{path}/v1/capabilities")
    };
    url.set_path(&joined);
    url
}
