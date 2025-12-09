use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

use crate::worker::Worker;

/// Periodically refreshes the threat MMDB from its configured source.
pub struct ThreatMmdbWorker {
    interval_secs: u64,
}

impl ThreatMmdbWorker {
    pub fn new(interval_secs: u64) -> Self {
        Self { interval_secs }
    }
}

impl Worker for ThreatMmdbWorker {
    fn name(&self) -> &str {
        "threat_mmdb"
    }

    fn run(&self, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        let interval_secs = self.interval_secs;
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(e) = crate::threat::refresh_threat_mmdb().await {
                            log::warn!("Threat MMDB refresh failed: {}", e);
                        } else {
                            log::info!("Threat MMDB refreshed");
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            log::info!("Threat MMDB worker received shutdown signal");
                            break;
                        }
                    }
                }
            }
        })
    }
}
