use std::fmt;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use crate::client::QrngClient;
use crate::error::QrngError;
use crate::model::HealthReport;

#[derive(Debug, Clone)]
pub struct HealthSnapshot {
    pub observed_at: SystemTime,
    pub report: Option<HealthReport>,
    pub consecutive_failures: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderMetricsSnapshot {
    pub entropy_requests_total: u64,
    pub entropy_bytes_total: u64,
    pub entropy_failures_total: u64,
    pub health_polls_total: u64,
    pub health_poll_failures_total: u64,
}

pub struct HealthMonitor {
    state: Arc<RwLock<HealthSnapshot>>,
    stop_tx: Option<mpsc::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl fmt::Debug for HealthMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthMonitor")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl HealthMonitor {
    pub fn start(client: Arc<QrngClient>, interval: Duration) -> Result<Self, QrngError> {
        if interval.is_zero() {
            return Err(QrngError::InvalidConfig(
                "health poll interval must be greater than zero".to_owned(),
            ));
        }
        if client.capabilities().healthtest.is_none() {
            return Err(QrngError::HealthUnsupported);
        }

        let state = Arc::new(RwLock::new(HealthSnapshot {
            observed_at: SystemTime::now(),
            report: None,
            consecutive_failures: 0,
            last_error: None,
        }));
        let (stop_tx, stop_rx) = mpsc::channel();
        let thread_state = Arc::clone(&state);
        let thread_client = Arc::clone(&client);

        let join = thread::Builder::new()
            .name("qrng-health-monitor".to_owned())
            .spawn(move || {
                poll_once(&thread_client, &thread_state);
                loop {
                    match stop_rx.recv_timeout(interval) {
                        Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => poll_once(&thread_client, &thread_state),
                    }
                }
            })
            .map_err(|err| {
                QrngError::InvalidConfig(format!("failed to spawn health monitor thread: {err}"))
            })?;

        Ok(Self {
            state,
            stop_tx: Some(stop_tx),
            join: Some(join),
        })
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl Drop for HealthMonitor {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn poll_once(client: &QrngClient, state: &RwLock<HealthSnapshot>) {
    let result = client.fetch_health();
    let mut snapshot = state
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    snapshot.observed_at = SystemTime::now();
    match result {
        Ok(report) => {
            snapshot.report = Some(report);
            snapshot.consecutive_failures = 0;
            snapshot.last_error = None;
        }
        Err(err) => {
            snapshot.consecutive_failures = snapshot.consecutive_failures.saturating_add(1);
            snapshot.last_error = Some(err.to_string());
        }
    }
}
