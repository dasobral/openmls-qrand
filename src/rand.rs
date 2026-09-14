use std::sync::Arc;

use openmls_traits::random::OpenMlsRand;

use crate::client::QrngClient;
use crate::error::QrngError;

pub struct QrngRand {
    client: Arc<QrngClient>,
}

impl QrngRand {
    pub fn new(client: Arc<QrngClient>) -> Self {
        Self { client }
    }
}

impl OpenMlsRand for QrngRand {
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
