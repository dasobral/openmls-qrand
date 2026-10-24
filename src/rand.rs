use std::sync::Arc;

use openmls_traits::random::OpenMlsRand;

use crate::backend::EntropyBackend;
use crate::client::QrngClient;
use crate::error::QrngError;

/// `OpenMlsRand` over an [`EntropyBackend`], by default a [`QrngClient`].
///
/// `B` may be unsized, so `QrngRand<dyn EntropyBackend>` selects the backend at run time.
pub struct QrngRand<B: ?Sized + EntropyBackend = QrngClient> {
    client: Arc<B>,
}

impl<B: ?Sized + EntropyBackend> QrngRand<B> {
    pub fn new(client: Arc<B>) -> Self {
        Self { client }
    }
}

impl<B: ?Sized + EntropyBackend> OpenMlsRand for QrngRand<B> {
    type Error = QrngError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let bytes = self.client.fetch_entropy(N)?;
        bytes
            .try_into()
            .map_err(|_| QrngError::Protocol("internal entropy length mismatch".into()))
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.client.fetch_entropy(len)
    }
}
