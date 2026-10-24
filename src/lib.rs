//! `openmls-qrand`: a generic OpenMLS provider, independent of agent-trust, that fetches entropy from a QRNG Open API endpoint.
//!
//! The library replaces the OpenMLS `OpenMlsRand` randomness source with QRNG Open API entropy.
//! It does not replace randomness internal to every cryptographic backend, including randomness
//! that may be used internally by `OpenMlsCrypto` implementations such as RustCrypto
//! (`signature_key_gen`).

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
