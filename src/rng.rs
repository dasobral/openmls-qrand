use std::sync::Arc;

use rand_core::{TryCryptoRng, TryRng};

use crate::backend::EntropyBackend;
use crate::client::QrngClient;
use crate::error::QrngError;

/// A `rand` 0.10 [`TryCryptoRng`] over an [`EntropyBackend`], by default a [`QrngClient`].
///
/// [`QrngRand`](crate::QrngRand) covers the randomness OpenMLS draws through
/// `OpenMlsRand`. Randomness drawn inside `OpenMlsCrypto` operations (HPKE encapsulation,
/// signature key generation) comes from the crypto backend instead. Pass an `EntropyRng`
/// to a crypto backend that takes an entropy source, such as
/// `openmls_libcrux_crypto::CryptoProvider::with_entropy_source`, to derive that
/// randomness from the same backend.
///
/// Like `QrngRand`, it fails closed: a backend failure is returned as an error and no
/// bytes from another source are substituted.
pub struct EntropyRng<B: ?Sized + EntropyBackend = QrngClient> {
    backend: Arc<B>,
}

impl<B: ?Sized + EntropyBackend> EntropyRng<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }
}

impl<B: ?Sized + EntropyBackend> TryRng for EntropyRng<B> {
    type Error = QrngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        if dst.is_empty() {
            return Ok(());
        }
        let bytes = self.backend.fetch_entropy(dst.len())?;
        if bytes.len() != dst.len() {
            return Err(QrngError::Protocol(
                "internal entropy length mismatch".into(),
            ));
        }
        dst.copy_from_slice(&bytes);
        Ok(())
    }
}

impl<B: ?Sized + EntropyBackend> TryCryptoRng for EntropyRng<B> {}
