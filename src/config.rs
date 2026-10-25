use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use reqwest::redirect::Policy;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

use crate::error::QrngError;

/// The TLS key exchange of `Tls` and `MutualTls` connections.
///
/// The entropy fetched over these connections becomes key material. An attacker who
/// records a connection today and breaks its key exchange later learns that entropy, so
/// the client uses the hybrid group `X25519MLKEM768` (ML-KEM-768 with X25519, TLS 1.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyExchange {
    /// Offer only `X25519MLKEM768`, over TLS 1.3. A server without it is refused.
    #[default]
    PostQuantumOnly,
    /// Offer `X25519MLKEM768` first, then X25519, P-256 and P-384, so that a server
    /// without a post quantum group can still be reached. A downgrade is possible.
    PostQuantumPreferred,
}

impl KeyExchange {
    /// `pq-only` or `pq-preferred`.
    pub fn name(self) -> &'static str {
        match self {
            KeyExchange::PostQuantumOnly => "pq-only",
            KeyExchange::PostQuantumPreferred => "pq-preferred",
        }
    }

    /// Parses [`KeyExchange::name`].
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "pq-only" => Ok(KeyExchange::PostQuantumOnly),
            "pq-preferred" => Ok(KeyExchange::PostQuantumPreferred),
            _ => Err(format!(
                "unknown key exchange {name:?} (expected pq-only or pq-preferred)"
            )),
        }
    }
}

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
    /// The TLS key exchange; ignored for `PlainHttp`.
    pub key_exchange: KeyExchange,
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

    pub(crate) fn build_http_client(&self) -> Result<reqwest::blocking::Client, QrngError> {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(self.request_timeout)
            .redirect(Policy::none());

        // reqwest builds a TLS client even for plain HTTP. Give it this crate's
        // configuration in every mode, so it never needs a process default provider; a
        // `PlainHttp` client trusts no root, so it cannot reach an https:// URL at all.
        let tls = match &self.transport {
            TransportMode::PlainHttp => self.tls_config(RootCertStore::empty(), None)?,
            TransportMode::Tls { ca_cert_pem } => {
                let roots = match ca_cert_pem {
                    Some(path) => root_store(parse_ca_cert(path)?)?,
                    None => RootCertStore {
                        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                    },
                };
                self.tls_config(roots, None)?
            }
            TransportMode::MutualTls {
                ca_cert_pem,
                client_cert_pem,
                client_key_pem,
            } => {
                let roots = root_store(parse_ca_cert(ca_cert_pem)?)?;
                let identity = parse_client_identity(client_cert_pem, client_key_pem)?;
                self.tls_config(roots, Some(identity))?
            }
        };
        builder = builder.use_preconfigured_tls(tls);

        Ok(builder.build()?)
    }

    /// The rustls client of `Tls` and `MutualTls`: aws-lc-rs with the key exchange groups
    /// of [`KeyExchange`].
    fn tls_config(
        &self,
        roots: RootCertStore,
        identity: Option<ClientIdentity>,
    ) -> Result<ClientConfig, QrngError> {
        let mut provider = aws_lc_rs::default_provider();
        let versions: &[&rustls::SupportedProtocolVersion] = match self.key_exchange {
            KeyExchange::PostQuantumOnly => {
                provider.kx_groups = vec![kx_group::X25519MLKEM768];
                &[&rustls::version::TLS13]
            }
            KeyExchange::PostQuantumPreferred => {
                provider.kx_groups = vec![
                    kx_group::X25519MLKEM768,
                    kx_group::X25519,
                    kx_group::SECP256R1,
                    kx_group::SECP384R1,
                ];
                rustls::DEFAULT_VERSIONS
            }
        };
        let builder = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .map_err(|err| QrngError::TlsMaterial(format!("TLS configuration: {err}")))?
            .with_root_certificates(roots);
        let mut config = match identity {
            None => builder.with_no_client_auth(),
            Some(identity) => builder
                .with_client_auth_cert(identity.chain, identity.key)
                .map_err(|err| {
                    QrngError::TlsMaterial(format!("malformed client identity: {err}"))
                })?,
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// A client certificate chain and its private key.
struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn root_store(certs: Vec<CertificateDer<'static>>) -> Result<RootCertStore, QrngError> {
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|err| QrngError::TlsMaterial(format!("unusable CA certificate: {err}")))?;
    }
    Ok(roots)
}

fn read_tls_file(path: &Path) -> Result<Vec<u8>, QrngError> {
    fs::read(path)
        .map_err(|err| QrngError::TlsMaterial(format!("unable to read {}: {err}", path.display())))
}

fn parse_ca_cert(path: &Path) -> Result<Vec<CertificateDer<'static>>, QrngError> {
    let pem = read_tls_file(path)?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| {
            QrngError::TlsMaterial(format!(
                "malformed CA certificate PEM at {}: {err}",
                path.display()
            ))
        })?;
    // Each certificate must also parse as an X.509 trust anchor.
    for cert in &certs {
        RootCertStore::empty().add(cert.clone()).map_err(|err| {
            QrngError::TlsMaterial(format!(
                "malformed CA certificate at {}: {err}",
                path.display()
            ))
        })?;
    }
    if certs.is_empty() {
        return Err(QrngError::TlsMaterial(format!(
            "no CA certificate found in PEM at {}",
            path.display()
        )));
    }
    Ok(certs)
}

fn parse_client_identity(cert_path: &Path, key_path: &Path) -> Result<ClientIdentity, QrngError> {
    let cert = read_tls_file(cert_path)?;
    let key = read_tls_file(key_path)?;
    let malformed = |err: &dyn fmt::Display| {
        QrngError::TlsMaterial(format!(
            "malformed client identity PEM from {} and {}: {err}",
            cert_path.display(),
            key_path.display()
        ))
    };
    let chain = CertificateDer::pem_slice_iter(&cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| malformed(&err))?;
    if chain.is_empty() {
        return Err(malformed(&"no certificate"));
    }
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(|err| malformed(&err))?;
    // The key must be usable for signing, and must match the certificate.
    let signing = aws_lc_rs::sign::any_supported_type(&key).map_err(|err| malformed(&err))?;
    rustls::sign::CertifiedKey::new(chain.clone(), signing)
        .keys_match()
        .map_err(|err| malformed(&err))?;
    Ok(ClientIdentity { chain, key })
}
