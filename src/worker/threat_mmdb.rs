use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration as TokioDuration, MissedTickBehavior};

use crate::http_client::get_global_reqwest_client;
use crate::threat;
use crate::worker::Worker;

#[derive(Debug, Deserialize)]
struct VersionResponse {
    success: bool,
    #[allow(dead_code)]
    timestamp: String,
    version: String,
    #[allow(dead_code)]
    hash: String,
}

/// Periodically checks version.txt and downloads the latest Threat MMDB,
/// then asks the threat module to reload it from disk.
pub struct ThreatMmdbWorker {
    interval_secs: u64,
    mmdb_base_url: String,
    mmdb_path: Option<PathBuf>,
    headers: Option<HashMap<String, String>>,
    api_key: String,
}

impl ThreatMmdbWorker {
    pub fn new(
        interval_secs: u64,
        mmdb_base_url: String,
        mmdb_path: Option<PathBuf>,
        headers: Option<HashMap<String, String>>,
        api_key: String,
    ) -> Self {
        Self {
            interval_secs,
            mmdb_base_url,
            mmdb_path,
            headers,
            api_key,
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
        let mmdb_path = self.mmdb_path.clone();
        let mut headers = self.headers.clone().unwrap_or_default();
        let api_key = self.api_key.clone();

        // Always add API key to headers if provided
        if !api_key.is_empty() {
            headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
        }

        let headers = if headers.is_empty() { None } else { Some(headers) };

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
                mmdb_path.clone(),
                current_version.clone(),
                headers.clone(),
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

            let mut ticker = interval(TokioDuration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match sync_mmdb(
                            &mmdb_base_url,
                            mmdb_path.clone(),
                            current_version.clone(),
                            headers.clone(),
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

/// One sync pass: check version API, download a new MMDB if needed, write it
/// to disk, and ask the threat module to reload it.
async fn sync_mmdb(
    mmdb_base_url: &str,
    mmdb_path: Option<PathBuf>,
    current_version: Option<String>,
    headers: Option<HashMap<String, String>>,
) -> Result<Option<String>> {
    // Construct version API URL from base URL
    let base = mmdb_base_url.trim_end_matches('/');
    let versions_url = format!("{}/v1/indicators/version", base);

    // Check L1 cache first using pingora-memory-cache
    let cache = threat::get_version_cache()
        .context("Failed to get version cache")?;
    let cache_key = format!("threat_mmdb_version:{}", base);

    // Try to get cached version
    let (cached_version, cache_status) = cache.get(&cache_key);

    // Download version from API endpoint
    let latest = if versions_url.starts_with("http://") || versions_url.starts_with("https://") {
        let client = get_global_reqwest_client()
            .context("Failed to get HTTP client for version download")?;
        let mut req = client.get(&versions_url).timeout(Duration::from_secs(120));
        if let Some(ref hdrs) = headers {
            for (key, value) in hdrs {
                req = req.header(key, value);
            }
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("Failed to download version from {} (timeout: 120s)", versions_url))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(anyhow!(
                "Version download failed: status {} from {}",
                status,
                versions_url
            ));
        }
        let version_resp: VersionResponse = resp
            .json()
            .await
            .with_context(|| format!("Failed to parse version JSON from {}", versions_url))?;

        if !version_resp.success {
            return Err(anyhow!("Version API returned success=false from {}", versions_url));
        }

        version_resp.version
    } else {
        // For file:// URLs, try to parse as JSON file
        let file_path = versions_url.strip_prefix("file://").unwrap_or(&versions_url);
        let content = tokio::fs::read_to_string(file_path)
            .await
            .with_context(|| format!("Failed to read version file from {}", file_path))?;
        let version_resp: VersionResponse = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse version JSON from {}", file_path))?;

        if !version_resp.success {
            return Err(anyhow!("Version file returned success=false from {}", file_path));
        }

        version_resp.version
    };

    // Check if cached version matches latest version
    if let Some(cached_ver) = cached_version {
        if cache_status.is_hit() && cached_ver == latest {
            // Version matches cache, skip download
            log::debug!("Threat MMDB version {} matches cache, skipping download", latest);
            return Ok(Some(latest));
        }
    }

    // If we have a current_version and it matches latest, also skip
    if let Some(ref curr) = current_version {
        if curr == &latest {
            // Already on latest, nothing to do.
            return Ok(current_version);
        }
    }

    let local_path = mmdb_path.ok_or_else(|| anyhow!("MMDB path not configured for Threat MMDB worker"))?;

    let base = mmdb_base_url.trim_end_matches('/');
    let bytes = if base.starts_with("http://") || base.starts_with("https://") {
        let url = format!("{}/v1/indicators/download?version={}", base, latest);
        download_mmdb(&url, headers.as_ref()).await?
    } else {
        // Strip file:// prefix if present
        let file_base = base.strip_prefix("file://").unwrap_or(base);
        let src_path = PathBuf::from(file_base).join(&latest);
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

    // Update L1 cache with new version (no TTL, cache indefinitely)
    cache.put(&cache_key, latest.clone(), None);
    log::debug!("Updated threat MMDB version cache: {}", latest);

    // Ask the threat module to reload from the updated path.
    crate::threat::refresh_threat_mmdb().await?;

    Ok(Some(latest))
}


async fn download_mmdb(url: &str, headers: Option<&HashMap<String, String>>) -> Result<Vec<u8>> {
    let client = get_global_reqwest_client()
        .context("Failed to get HTTP client for MMDB download")?;

    // Use a longer timeout for large files (120s base + 1s per MB)
    // For 172MB file, that would be ~292s, but we'll use a fixed 600s (10min) for very large files
    let timeout_secs = 600; // 10 minutes for large MMDB files
    let mut req = client.get(url).timeout(Duration::from_secs(timeout_secs));
    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            req = req.header(key, value);
        }
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("Failed to download MMDB from {} (timeout: 120s)", url))?;
    let status = resp.status();

    // Get content length for logging (before consuming response)
    let content_length = resp.content_length();

    if !status.is_success() {
        // Try to read error body, but don't fail if we can't
        let status_text = match resp.text().await {
            Ok(text) if !text.is_empty() => text,
            _ => format!("HTTP {}", status),
        };
        return Err(anyhow!(
            "MMDB download failed: status {} from {} - {}",
            status,
            url,
            status_text
        ));
    }

    let file_size_mb = content_length.map(|s| s as f64 / 1_048_576.0);
    log::info!(
        "Downloading MMDB from {} (content-length: {:?}, ~{:.2} MB, timeout: {}s)",
        url,
        content_length,
        file_size_mb.unwrap_or(0.0),
        timeout_secs
    );

    let bytes = resp
        .bytes()
        .await
        .with_context(|| {
            format!(
                "Failed to read MMDB body from {} (content-length: {:?}, ~{:.2} MB). This may indicate a network timeout or connection issue.",
                url,
                content_length,
                file_size_mb.unwrap_or(0.0)
            )
        })?;

    let data = bytes.to_vec();
    log::debug!(
        "Successfully downloaded MMDB from {} (size: {} bytes)",
        url,
        data.len()
    );

    Ok(data)
}
