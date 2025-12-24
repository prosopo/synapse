use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration, MissedTickBehavior};

use crate::http_client::get_global_reqwest_client;
use crate::worker::Worker;

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
) -> Result<Option<String>> {
    let local_path = mmdb_path.ok_or_else(|| anyhow!("MMDB path not configured for GeoIP MMDB worker"))?;

    if versions_url.is_empty() {
        // Check if file already exists - if it does, skip download to avoid redundant writes
        // This prevents multiple workers from downloading the same file simultaneously
        if local_path.exists() {
            log::debug!("GeoIP MMDB file already exists at {:?}, skipping download", local_path);
            return Ok(Some("existing".to_string()));
        }

        log::debug!("No versions URL provided, downloading directly from {}", mmdb_base_url);

        let bytes = if mmdb_base_url.starts_with("http://") || mmdb_base_url.starts_with("https://") {
            download_mmdb(mmdb_base_url, headers.as_ref()).await?
        } else {
            let src_path = PathBuf::from(mmdb_base_url);
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
    let bytes = if base.starts_with("http://") || base.starts_with("https://") {
        let url = format!("{}/{}", base, latest);
        download_mmdb(&url, headers.as_ref()).await?
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

async fn download_mmdb(url: &str, headers: Option<&HashMap<String, String>>) -> Result<Vec<u8>> {
    let client = get_global_reqwest_client()
        .context("Failed to get HTTP client for MMDB download")?;
    let mut req = client.get(url);
    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            req = req.header(key, value);
        }
    }
    let resp = req
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


