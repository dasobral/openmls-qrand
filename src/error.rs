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
