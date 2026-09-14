use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::storage::StorageProvider;
use openmls_traits::OpenMlsProvider;

use crate::rand::QrngRand;

pub struct QrngOpenMlsProvider<C, S> {
    crypto: C,
    storage: S,
    rand: QrngRand,
}

impl<C, S> QrngOpenMlsProvider<C, S> {
    pub fn new(crypto: C, storage: S, rand: QrngRand) -> Self {
        Self {
            crypto,
            storage,
            rand,
        }
    }
}

impl<C, S> OpenMlsProvider for QrngOpenMlsProvider<C, S>
where
    C: OpenMlsCrypto,
    S: StorageProvider<{ openmls_traits::storage::CURRENT_VERSION }>,
{
    type CryptoProvider = C;
    type RandProvider = QrngRand;
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
