use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::error::QrngError;

#[derive(Debug)]
pub enum TransportMode {
    PlainHttp,
    Tls {
        ca_cert_pem: Option<std::path::PathBuf>,
    },
    MutualTls {
        ca_cert_pem: std::path::PathBuf,
        client_cert_pem: std::path::PathBuf,
        client_key_pem: std::path::PathBuf,
    },
}

pub enum ApiAuth {
    None,
    Bearer(String),
    XApiKey(String),
}

impl fmt::Debug for ApiAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiAuth::None => f.write_str("None"),
            ApiAuth::Bearer(_) => f.write_str("Bearer"),
            ApiAuth::XApiKey(_) => f.write_str("XApiKey"),
        }
    }
}

#[derive(Debug)]
pub struct QrngConfig {
    pub base_url: reqwest::Url,
    pub transport: TransportMode,
    pub auth: ApiAuth,
    pub entropy_type: Option<String>,
    pub request_timeout: Duration,
    pub health_poll_interval: Option<Duration>,
}

impl QrngConfig {
    pub fn validate(&self) -> Result<(), QrngError> {
        if self.base_url.query().is_some() {
            return Err(QrngError::InvalidConfig(
                "base URL must not contain a query string".to_owned(),
            ));
        }
        if self.base_url.fragment().is_some() {
            return Err(QrngError::InvalidConfig(
                "base URL must not contain a fragment".to_owned(),
            ));
        }

        let scheme = self.base_url.scheme();
        match &self.transport {
            TransportMode::PlainHttp => {
                if scheme != "http" {
                    return Err(QrngError::InvalidConfig(
                        "PlainHttp requires an http:// base URL".to_owned(),
                    ));
                }
            }
            TransportMode::Tls { .. } => {
                if scheme != "https" {
                    return Err(QrngError::InvalidConfig(
                        "Tls requires an https:// base URL".to_owned(),
                    ));
                }
            }
            TransportMode::MutualTls { .. } => {
                if scheme != "https" {
                    return Err(QrngError::InvalidConfig(
                        "MutualTls requires an https:// base URL".to_owned(),
                    ));
                }
            }
        }

        if self.request_timeout.is_zero() {
            return Err(QrngError::InvalidConfig(
                "request_timeout must be greater than zero".to_owned(),
            ));
        }
        if let Some(interval) = self.health_poll_interval {
            if interval.is_zero() {
                return Err(QrngError::InvalidConfig(
                    "health_poll_interval must be greater than zero".to_owned(),
                ));
            }
        }

        match &self.transport {
            TransportMode::PlainHttp => {}
            TransportMode::Tls { ca_cert_pem } => {
                if let Some(path) = ca_cert_pem {
                    parse_ca_cert(path)?;
                }
            }
            TransportMode::MutualTls {
                ca_cert_pem,
                client_cert_pem,
                client_key_pem,
            } => {
                parse_ca_cert(ca_cert_pem)?;
                parse_client_identity(client_cert_pem, client_key_pem)?;
            }
        }

        Ok(())
    }
}

fn read_tls_file(path: &Path) -> Result<Vec<u8>, QrngError> {
    fs::read(path)
        .map_err(|err| QrngError::TlsMaterial(format!("unable to read {}: {err}", path.display())))
}

fn parse_ca_cert(path: &Path) -> Result<(), QrngError> {
    let pem = read_tls_file(path)?;
    // rustls-backed `Certificate::from_pem` stores bytes without parsing; the
    // bundle parser actually validates PEM and DER.
    let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|err| {
        QrngError::TlsMaterial(format!(
            "malformed CA certificate PEM at {}: {err}",
            path.display()
        ))
    })?;
    if certs.is_empty() {
        return Err(QrngError::TlsMaterial(format!(
            "no CA certificate found in PEM at {}",
            path.display()
        )));
    }
    Ok(())
}

fn parse_client_identity(cert_path: &Path, key_path: &Path) -> Result<(), QrngError> {
    let cert = read_tls_file(cert_path)?;
    let key = read_tls_file(key_path)?;
    let mut identity_pem = cert;
    identity_pem.extend_from_slice(&key);
    reqwest::Identity::from_pem(&identity_pem).map_err(|err| {
        QrngError::TlsMaterial(format!(
            "malformed client identity PEM from {} and {}: {err}",
            cert_path.display(),
            key_path.display()
        ))
    })?;
    Ok(())
}
