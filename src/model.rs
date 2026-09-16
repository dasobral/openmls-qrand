use serde::{Deserialize, Serialize};

use crate::error::QrngError;

fn default_one() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize)]
pub struct Capabilities {
    pub entropy: EntropyCapabilities,
    #[serde(default)]
    pub healthtest: Option<serde_json::Value>,
    #[serde(default)]
    pub source_count: Option<u32>,
    #[serde(default)]
    pub extensions: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EntropyCapabilities {
    #[serde(default = "default_one")]
    pub min_block_size: usize,
    pub max_block_size: usize,
    #[serde(default = "default_one")]
    pub min_block_count: usize,
    pub max_block_count: usize,
    #[serde(default)]
    pub entropy_types: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<serde_json::Value>,
}

impl Capabilities {
    pub(crate) fn validate(&self) -> Result<(), QrngError> {
        let entropy = &self.entropy;
        if entropy.min_block_size < 1 {
            return Err(QrngError::Protocol(
                "min_block_size must be at least 1".to_owned(),
            ));
        }
        if entropy.max_block_size < entropy.min_block_size {
            return Err(QrngError::Protocol(
                "max_block_size must be greater than or equal to min_block_size".to_owned(),
            ));
        }
        if entropy.min_block_count < 1 {
            return Err(QrngError::Protocol(
                "min_block_count must be at least 1".to_owned(),
            ));
        }
        if entropy.max_block_count < entropy.min_block_count {
            return Err(QrngError::Protocol(
                "max_block_count must be greater than or equal to min_block_count".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct EntropyRequest<'a> {
    pub(crate) block_size: usize,
    pub(crate) block_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) entropy_type: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EntropyResponse {
    pub(crate) entropy: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub(crate) extensions: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthTestResult {
    pub test_type: String,
    pub test_result: serde_json::Value,
    /// QRNG Open API field. Entropy Core omits it on each result and puts
    /// RFC 3339 `timestamp` in `extensions` instead; also accepted as `timestamp`.
    #[serde(default, alias = "timestamp")]
    pub time_stamp: String,
    #[serde(default)]
    pub report_link: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthReport {
    #[serde(default)]
    pub test_result: Vec<HealthTestResult>,
    #[serde(default)]
    pub extensions: Vec<serde_json::Value>,
}
