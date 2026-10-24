use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::storage::StorageProvider;
use openmls_traits::OpenMlsProvider;

use crate::backend::EntropyBackend;
use crate::client::QrngClient;
use crate::rand::QrngRand;

pub struct QrngOpenMlsProvider<C, S, B: ?Sized + EntropyBackend = QrngClient> {
    crypto: C,
    storage: S,
    rand: QrngRand<B>,
}

impl<C, S, B: ?Sized + EntropyBackend> QrngOpenMlsProvider<C, S, B> {
    pub fn new(crypto: C, storage: S, rand: QrngRand<B>) -> Self {
        Self {
            crypto,
            storage,
            rand,
        }
    }
}

impl<C, S, B> OpenMlsProvider for QrngOpenMlsProvider<C, S, B>
where
    C: OpenMlsCrypto,
    S: StorageProvider<{ openmls_traits::storage::CURRENT_VERSION }>,
    B: ?Sized + EntropyBackend,
{
    type CryptoProvider = C;
    type RandProvider = QrngRand<B>;
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
