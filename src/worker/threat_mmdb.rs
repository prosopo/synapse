use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration, MissedTickBehavior};

use crate::http_client::get_global_reqwest_client;
use crate::worker::Worker;

/// Periodically checks versions.txt and downloads the latest Threat MMDB,
/// then asks the threat module to reload it from disk.
pub struct ThreatMmdbWorker {
    interval_secs: u64,
    mmdb_base_url: String,
    versions_url: String,
    mmdb_path: Option<PathBuf>,
}

impl ThreatMmdbWorker {
    pub fn new(
        interval_secs: u64,
        mmdb_base_url: String,
        versions_url: String,
        mmdb_path: Option<PathBuf>,
    ) -> Self {
        Self {
            interval_secs,
            mmdb_base_url,
            versions_url,
            mmdb_path,
        }
    }
}

impl Worker for ThreatMmdbWorker {
    fn name(&self) -> &str {
        "threat_mmdb"
    }

    fn run(&self, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        let interval_secs = self.interval_secs;
        let mmdb_base_url = self.mmdb_base_url.clone();
        let versions_url = self.versions_url.clone();
        let mmdb_path = self.mmdb_path.clone();

        tokio::spawn(async move {
            let worker_name = "threat_mmdb".to_string();
            let mut current_version: Option<String> = None;

            log::info!(
                "[{}] Starting Threat MMDB worker (interval: {}s)",
                worker_name,
                interval_secs
            );

            // Initial sync on startup
            match sync_mmdb(
                &mmdb_base_url,
                versions_url.clone(),
                mmdb_path.clone(),
                current_version.clone(),
            )
            .await
            {
                Ok(new_ver) => {
                    current_version = new_ver;
                }
                Err(e) => {
                    log::warn!(
                        "[{}] Initial Threat MMDB sync failed: {}",
                        worker_name,
                        e
                    );
                }
            }

            let mut ticker = interval(Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match sync_mmdb(
                            &mmdb_base_url,
                            versions_url.clone(),
                            mmdb_path.clone(),
                            current_version.clone(),
                        ).await {
                            Ok(new_ver) => {
                                if new_ver != current_version {
                                    current_version = new_ver;
                                    log::info!("[{}] Threat MMDB updated to latest version", worker_name);
                                } else {
                                    log::debug!("[{}] Threat MMDB already at latest version", worker_name);
                                }
                            }
                            Err(e) => {
                                log::warn!("[{}] Periodic Threat MMDB sync failed: {}", worker_name, e);
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            log::info!("[{}] Threat MMDB worker received shutdown signal", worker_name);
                            break;
                        }
                    }
                }
            }
        })
    }
}

/// One sync pass: check versions.txt, download a new MMDB if needed, write it
/// to disk, and ask the threat module to reload it.
async fn sync_mmdb(
    mmdb_base_url: &str,
    versions_url: &str,
    mmdb_path: Option<PathBuf>,
    current_version: Option<String>,
) -> Result<Option<String>> {
    let versions_text = if versions_url.starts_with("http://") || versions_url.starts_with("https://") {
        let client = get_global_reqwest_client()
            .context("Failed to get HTTP client for versions download")?;
        let resp = client
            .get(&versions_url)
            .send()
            .await
            .with_context(|| format!("Failed to download versions file from {}", versions_url))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!(
                "Versions download failed: status {} from {}",
                status,
                versions_url
            ));
        }
        resp.text().await.context("Failed to read versions body")?
    } else {
        tokio::fs::read_to_string(&versions_url)
            .await
            .with_context(|| format!("Failed to read versions file from {}", versions_url))?
    };

    let latest = parse_latest_version(&versions_text)
        .ok_or_else(|| anyhow!("Failed to parse latest version from versions file"))?;

    if let Some(ref curr) = current_version {
        if curr == &latest {
            // Already on latest, nothing to do.
            return Ok(current_version);
        }
    }

    let local_path = mmdb_path.ok_or_else(|| anyhow!("MMDB path not configured for Threat MMDB worker"))?;

    let base = mmdb_base_url.trim_end_matches('/');
    let bytes = if base.starts_with("http://") || base.starts_with("https://") {
        let url = format!("{}/{}", base, latest);
        download_mmdb(&url).await?
    } else {
        let src_path = PathBuf::from(base).join(&latest);
        tokio::fs::read(&src_path)
            .await
            .with_context(|| format!("Failed to read MMDB from {:?}", src_path))?
    };

    if let Some(parent) = local_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create MMDB directory {:?}", parent))?;
    }

    tokio::fs::write(&local_path, &bytes)
        .await
        .with_context(|| format!("Failed to write MMDB to {:?}", local_path))?;

    log::info!("Threat MMDB written to {:?}", local_path);

    // Ask the threat module to reload from the updated path.
    crate::threat::refresh_threat_mmdb().await?;

    Ok(Some(latest))
}

fn parse_latest_version(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("latest=") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

async fn download_mmdb(url: &str) -> Result<Vec<u8>> {
    let client = get_global_reqwest_client()
        .context("Failed to get HTTP client for MMDB download")?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to download MMDB from {}", url))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!(
            "MMDB download failed: status {} from {}",
            status,
            url
        ));
    }
    let bytes = resp.bytes().await.context("Failed to read MMDB body")?;
    Ok(bytes.to_vec())
}
