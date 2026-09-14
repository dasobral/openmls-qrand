//! Generic OpenMLS provider, independent of agent-trust, that fetches entropy from a QRNG Open API endpoint.
//!
//! The library replaces the OpenMLS `OpenMlsRand` randomness source with QRNG Open API entropy.
//! It does not replace randomness internal to every cryptographic backend, including randomness
//! that may be used internally by `OpenMlsCrypto` implementations such as RustCrypto
//! (`signature_key_gen`).

mod client;
mod config;
mod error;
mod health;
mod model;
mod provider;
mod rand;

pub use client::QrngClient;
pub use config::{ApiAuth, QrngConfig, TransportMode};
pub use error::QrngError;
pub use health::{HealthMonitor, HealthSnapshot, ProviderMetricsSnapshot};
pub use model::{Capabilities, EntropyCapabilities, HealthReport, HealthTestResult};
pub use provider::QrngOpenMlsProvider;
pub use rand::QrngRand;
