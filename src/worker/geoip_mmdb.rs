use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration, MissedTickBehavior};

use crate::http_client::get_global_reqwest_client;
use crate::worker::Worker;

#[derive(Clone)]
pub enum GeoipDatabaseType {
    Country,
    Asn,
    City,
}

pub struct GeoipMmdbWorker {
    interval_secs: u64,
    mmdb_base_url: String,
    versions_url: String,
    mmdb_path: Option<PathBuf>,
    headers: Option<HashMap<String, String>>,
    db_type: GeoipDatabaseType,
}

impl GeoipMmdbWorker {
    pub fn new(
        interval_secs: u64,
        mmdb_base_url: String,
        versions_url: String,
        mmdb_path: Option<PathBuf>,
        headers: Option<HashMap<String, String>>,
        db_type: GeoipDatabaseType,
    ) -> Self {
        Self {
            interval_secs,
            mmdb_base_url,
            versions_url,
            mmdb_path,
            headers,
            db_type,
        }
    }
}

impl Worker for GeoipMmdbWorker {
    fn name(&self) -> &str {
        match self.db_type {
            GeoipDatabaseType::Country => "geoip_country_mmdb",
            GeoipDatabaseType::Asn => "geoip_asn_mmdb",
            GeoipDatabaseType::City => "geoip_city_mmdb",
        }
    }

    fn run(&self, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        let interval_secs = self.interval_secs;
        let mmdb_base_url = self.mmdb_base_url.clone();
        let versions_url = self.versions_url.clone();
        let mmdb_path = self.mmdb_path.clone();
        let headers = self.headers.clone();
        let db_type_enum = self.db_type.clone();
        let db_type = match self.db_type {
            GeoipDatabaseType::Country => "country",
            GeoipDatabaseType::Asn => "asn",
            GeoipDatabaseType::City => "city",
        };

        tokio::spawn(async move {
            let worker_name = format!("geoip_{}_mmdb", db_type);
            let mut current_version: Option<String> = None;

            log::info!(
                "[{}] Starting GeoIP MMDB worker (interval: {}s)",
                worker_name,
                interval_secs
            );

            match sync_mmdb(
                &mmdb_base_url,
                &versions_url,
                mmdb_path.clone(),
                current_version.clone(),
                headers.clone(),
                db_type_enum.clone(),
            )
            .await
            {
                Ok(new_ver) => {
                    // Only refresh if the file was actually updated (not "existing")
                    if new_ver.as_ref().map(|v| v != "existing").unwrap_or(true) {
                    current_version = new_ver;
                    }
                    // Always refresh the database reader to ensure it's loaded
                    match db_type {
                        "country" => {
                            if let Err(e) = crate::threat::refresh_geoip_country_mmdb().await {
                                log::warn!("[{}] Failed to refresh GeoIP Country MMDB: {}", worker_name, e);
                            }
                        }
                        "asn" => {
                            if let Err(e) = crate::threat::refresh_geoip_asn_mmdb().await {
                                log::warn!("[{}] Failed to refresh GeoIP ASN MMDB: {}", worker_name, e);
                            }
                        }
                        "city" => {
                            if let Err(e) = crate::threat::refresh_geoip_city_mmdb().await {
                                log::warn!("[{}] Failed to refresh GeoIP City MMDB: {}", worker_name, e);
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    log::warn!("[{}] Initial GeoIP {} MMDB sync failed: {}", worker_name, db_type, e);
                }
            }

            let mut ticker = interval(Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        match sync_mmdb(
                            &mmdb_base_url,
                            &versions_url,
                            mmdb_path.clone(),
                            current_version.clone(),
                            headers.clone(),
                            db_type_enum.clone(),
                        ).await {
                            Ok(new_ver) => {
                                if new_ver != current_version {
                                    current_version = new_ver;
                                    log::info!("[{}] GeoIP {} MMDB updated to latest version", worker_name, db_type);
                                    // Refresh only the specific database that was updated
                                    match db_type {
                                        "country" => {
                                            if let Err(e) = crate::threat::refresh_geoip_country_mmdb().await {
                                                log::warn!("[{}] Failed to refresh GeoIP Country MMDB: {}", worker_name, e);
                                            }
                                        }
                                        "asn" => {
                                            if let Err(e) = crate::threat::refresh_geoip_asn_mmdb().await {
                                                log::warn!("[{}] Failed to refresh GeoIP ASN MMDB: {}", worker_name, e);
                                            }
                                        }
                                        "city" => {
                                            if let Err(e) = crate::threat::refresh_geoip_city_mmdb().await {
                                                log::warn!("[{}] Failed to refresh GeoIP City MMDB: {}", worker_name, e);
                                            }
                                        }
                                        _ => {}
                                    }
                                } else {
                                    log::debug!("[{}] GeoIP {} MMDB already at latest version", worker_name, db_type);
                                }
                            }
                            Err(e) => {
                                log::warn!("[{}] Periodic GeoIP MMDB sync failed: {}", worker_name, e);
                            }
                        }
                    }
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            log::info!("[{}] GeoIP MMDB worker received shutdown signal", worker_name);
                            break;
                        }
                    }
                }
            }
        })
    }
}

async fn sync_mmdb(
    mmdb_base_url: &str,
    versions_url: &str,
    mmdb_path: Option<PathBuf>,
    current_version: Option<String>,
    headers: Option<HashMap<String, String>>,
    db_type: GeoipDatabaseType,
) -> Result<Option<String>> {
    let mut local_path = mmdb_path.ok_or_else(|| anyhow!("MMDB path not configured for GeoIP MMDB worker"))?;

    // If the path doesn't have a file extension, treat it as a directory and append the filename
    if local_path.extension().is_none() {
        let filename = match db_type {
            GeoipDatabaseType::Country => "GeoLite2-Country.mmdb",
            GeoipDatabaseType::Asn => "GeoLite2-ASN.mmdb",
            GeoipDatabaseType::City => "GeoLite2-City.mmdb",
        };
        local_path = local_path.join(filename);
    }

    if versions_url.is_empty() {
        // Check if file already exists - if it does, skip download to avoid redundant writes
        // This prevents multiple workers from downloading the same file simultaneously
        if local_path.exists() {
            log::debug!("GeoIP MMDB file already exists at {:?}, skipping download", local_path);
            return Ok(Some("existing".to_string()));
        }

        log::debug!("No versions URL provided, downloading directly from {}", mmdb_base_url);

        if mmdb_base_url.starts_with("http://") || mmdb_base_url.starts_with("https://") {
            // Stream directly to final location to avoid loading entire file into memory
            download_mmdb_to_file(mmdb_base_url, &local_path, headers.as_ref()).await?;
        } else {
            // For file:// URLs, copy from source to destination
            let src_path = PathBuf::from(mmdb_base_url);

            if let Some(parent) = local_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("Failed to create MMDB directory {:?}", parent))?;
            }

            tokio::fs::copy(&src_path, &local_path)
                .await
                .with_context(|| format!("Failed to copy MMDB from {:?} to {:?}", src_path, local_path))?;
        }

        log::info!("GeoIP MMDB written to {:?}", local_path);
        return Ok(Some("direct".to_string()));
    }

    let versions_text = if versions_url.starts_with("http://") || versions_url.starts_with("https://") {
        let client = get_global_reqwest_client()
            .context("Failed to get HTTP client for versions download")?;
        let mut req = client.get(versions_url);
        if let Some(ref hdrs) = headers {
            for (key, value) in hdrs {
                req = req.header(key, value);
            }
        }
        let resp = req
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
        tokio::fs::read_to_string(versions_url)
            .await
            .with_context(|| format!("Failed to read versions file from {}", versions_url))?
    };

    let latest = parse_latest_version(&versions_text)
        .ok_or_else(|| anyhow!("Failed to parse latest version from versions file"))?;

    if let Some(ref curr) = current_version {
        if curr == &latest {
            log::debug!("GeoIP MMDB already at latest version: {}", latest);
            return Ok(current_version);
        }
    }

    let base = mmdb_base_url.trim_end_matches('/');
    if base.starts_with("http://") || base.starts_with("https://") {
        // Stream directly to final location to avoid loading entire file into memory
        let url = format!("{}/{}", base, latest);
        download_mmdb_to_file(&url, &local_path, headers.as_ref()).await?;
    } else {
        // For file:// URLs, copy from source to destination
        let src_path = PathBuf::from(base).join(&latest);

        if let Some(parent) = local_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create MMDB directory {:?}", parent))?;
        }

        tokio::fs::copy(&src_path, &local_path)
            .await
            .with_context(|| format!("Failed to copy MMDB from {:?} to {:?}", src_path, local_path))?;
    }

    log::info!("GeoIP MMDB written to {:?}", local_path);
    crate::threat::refresh_geoip_mmdb().await?;
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

/// Download MMDB file by streaming directly to disk to avoid OOM on low-memory systems
async fn download_mmdb_to_file(url: &str, file_path: &PathBuf, headers: Option<&HashMap<String, String>>) -> Result<u64> {
    let client = get_global_reqwest_client()
        .context("Failed to get HTTP client for MMDB download")?;

    let timeout_secs = 600; // 10 minutes for large MMDB files
    let mut req = client.get(url).timeout(Duration::from_secs(timeout_secs));
    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            req = req.header(key, value);
        }
    }
    let mut resp = req
        .send()
        .await
        .with_context(|| format!("Failed to download MMDB from {} (timeout: {}s)", url, timeout_secs))?;
    let status = resp.status();

    let content_length = resp.content_length();

    if !status.is_success() {
        return Err(anyhow!(
            "MMDB download failed: status {} from {}",
            status,
            url
        ));
    }

    let file_size_mb = content_length.map(|s| s as f64 / 1_048_576.0);
    log::info!(
        "Downloading MMDB from {} (content-length: {:?}, ~{:.2} MB, timeout: {}s) - streaming to disk",
        url,
        content_length,
        file_size_mb.unwrap_or(0.0),
        timeout_secs
    );

    // Create parent directory if needed
    if let Some(parent) = file_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }

    // Stream the response directly to file to avoid loading entire file into memory
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::File::create(file_path)
        .await
        .with_context(|| format!("Failed to create file {:?} for streaming", file_path))?;

    let mut total_bytes = 0u64;

    // Read response in chunks to avoid loading entire file into memory
    // Use chunk() method which returns Option<Result<Bytes>>
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let len = chunk.len();
                file.write_all(&chunk)
                    .await
                    .with_context(|| format!("Failed to write chunk to file at {} bytes", total_bytes))?;
                total_bytes += len as u64;
            }
            Ok(None) => break, // EOF
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to read chunk from MMDB stream at {} bytes: {}", total_bytes, e));
            }
        }
    }

    file.sync_all()
        .await
        .with_context(|| format!("Failed to sync file {:?} to disk", file_path))?;

    log::info!(
        "Successfully downloaded MMDB from {} (size: {} bytes, ~{:.2} MB)",
        url,
        total_bytes,
        total_bytes as f64 / 1_048_576.0
    );

    Ok(total_bytes)
}

