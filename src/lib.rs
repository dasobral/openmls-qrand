//! `openmls-qrand`: a generic OpenMLS provider, independent of agent-trust, that fetches entropy from a QRNG Open API endpoint.
//!
//! The library replaces the OpenMLS `OpenMlsRand` randomness source with QRNG Open API entropy
//! ([`QrngRand`]). Randomness drawn inside `OpenMlsCrypto` operations comes from the crypto
//! backend. [`EntropyRng`] lets a crypto backend that takes an entropy source, such as the
//! OpenMLS libcrux provider's `CryptoProvider::with_entropy_source`, derive that randomness from
//! the same backend; backends that don't take one, such as RustCrypto, keep their own.

mod backend;
mod client;
mod config;
mod error;
mod health;
#[cfg(feature = "mock")]
mod mock;
mod model;
mod provider;
mod rand;
mod rng;

pub use backend::EntropyBackend;
pub use client::QrngClient;
pub use config::{ApiAuth, QrngConfig, TransportMode};
pub use error::QrngError;
pub use health::{HealthMonitor, HealthSnapshot, ProviderMetricsSnapshot};
#[cfg(feature = "mock")]
pub use mock::MockEntropy;
pub use model::{Capabilities, EntropyCapabilities, HealthReport, HealthTestResult};
pub use provider::QrngOpenMlsProvider;
pub use rand::QrngRand;
pub use rng::EntropyRng;
