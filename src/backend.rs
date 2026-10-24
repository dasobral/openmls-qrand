use crate::client::QrngClient;
use crate::error::QrngError;
use crate::health::ProviderMetricsSnapshot;

/// A source of entropy bytes for [`QrngRand`](crate::QrngRand).
///
/// [`QrngClient`] is the production backend: it fetches entropy from a QRNG Open API
/// endpoint. Implementations must fail closed: on any failure they return an error and
/// never substitute bytes from another source.
pub trait EntropyBackend: Send + Sync {
    /// Returns exactly `len` entropy bytes, or an error.
    fn fetch_entropy(&self, len: usize) -> Result<Vec<u8>, QrngError>;

    /// Entropy activity counters for this backend.
    fn metrics_snapshot(&self) -> ProviderMetricsSnapshot;
}

impl EntropyBackend for QrngClient {
    fn fetch_entropy(&self, len: usize) -> Result<Vec<u8>, QrngError> {
        QrngClient::fetch_entropy(self, len)
    }

    fn metrics_snapshot(&self) -> ProviderMetricsSnapshot {
        QrngClient::metrics_snapshot(self)
    }
}
