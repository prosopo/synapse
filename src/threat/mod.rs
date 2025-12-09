use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use maxminddb::{MaxMindDBError, Reader};
use pingora_memory_cache::MemoryCache;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::{OnceCell, RwLock};

use crate::http_client::get_global_reqwest_client;

/// Custom deserializer for optional datetime fields that can be empty strings or missing
fn deserialize_optional_datetime<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<String>::deserialize(deserializer)? {
        Some(s) => {
            if s.is_empty() {
                Ok(None)
            } else {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| Some(dt.with_timezone(&Utc)))
                    .map_err(serde::de::Error::custom)
            }
        }
        None => Ok(None),
    }
}

/// Threat intelligence response (compatible with previous REST shape)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResponse {
    pub schema_version: String,
    pub tenant_id: String,
    pub ip: String,
    pub intel: ThreatIntel,
    pub context: ThreatContext,
    pub advice: String,
    pub ttl_s: u64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntel {
    pub score: u32,
    pub confidence: f64,
    pub score_version: String,
    pub categories: Vec<String>,
    pub tags: Vec<String>,
    #[serde(deserialize_with = "deserialize_optional_datetime")]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(deserialize_with = "deserialize_optional_datetime")]
    pub last_seen: Option<DateTime<Utc>>,
    pub source_count: u32,
    pub reason_code: String,
    pub reason_summary: String,
    pub rule_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    pub asn: u32,
    pub org: String,
    pub ip_version: u8,
    pub geo: GeoInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: String,
    pub iso_code: String,
    #[serde(rename = "asniso_code")]
    pub asn_iso_code: String,
}

/// WAF fields extracted from threat data
#[derive(Debug, Clone)]
pub struct WafFields {
    pub ip_src_country: String,
    pub ip_src_asn: u32,
    pub ip_src_asn_org: String,
    pub ip_src_asn_country: String,
    pub threat_score: u32,
    pub threat_advice: String,
}

impl From<&ThreatResponse> for WafFields {
    fn from(threat: &ThreatResponse) -> Self {
        Self {
            ip_src_country: threat.context.geo.iso_code.clone(),
            ip_src_asn: threat.context.asn,
            ip_src_asn_org: threat.context.org.clone(),
            ip_src_asn_country: threat.context.geo.asn_iso_code.clone(),
            threat_score: threat.intel.score,
            threat_advice: threat.advice.clone(),
        }
    }
}

/// Raw record as written into the MMDB
#[derive(Debug, Deserialize)]
struct MmdbThreatRecord {
    action: Option<String>,
    score: Option<i32>,
    reason_code: Option<String>,
    description: Option<String>,
    rule_id: Option<String>,
    rule_name: Option<String>,
    source_tag_names: Option<Vec<String>>,
    country: Option<String>,
    iso_code: Option<String>,
    asn: Option<i32>,
    asniso_code: Option<String>,
    asn_org: Option<String>,
    num_sources: Option<i32>,
    expiration: Option<i32>,
    created_at: Option<String>,
    updated_at: Option<String>,
    scored_at: Option<String>,
}

/// Threat intelligence client backed by an MMDB file and in-memory cache
pub struct ThreatClient {
    mmdb_url: String,
    mmdb_path: Option<PathBuf>,
    reader: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
    pingora_cache: Arc<MemoryCache<String, ThreatResponse>>,
}

impl ThreatClient {
    pub fn new(mmdb_url: String, mmdb_path: Option<PathBuf>) -> Self {
        Self {
            mmdb_url,
            mmdb_path,
            reader: RwLock::new(None),
            pingora_cache: Arc::new(MemoryCache::new(10_000)),
        }
    }

    pub async fn refresh(&self) -> Result<()> {
        self.refresh_reader().await.map(|_| ())
    }

    /// Get threat intelligence for an IP address with in-memory caching
    pub async fn get_threat_intel(&self, ip: &str) -> Result<Option<ThreatResponse>> {
        // Check pingora-memory-cache
        let (cached_data, status) = self.pingora_cache.get(ip);
        if let Some(data) = cached_data {
            if status.is_hit() {
                log::debug!("Threat data for {} found in pingora-memory-cache", ip);
                return Ok(Some(data));
            }
        }

        // Ensure the MMDB is loaded
        let reader = match self.ensure_reader().await {
            Ok(r) => r,
            Err(e) => {
                log::error!("Failed to load threat MMDB: {}", e);
                return Ok(None);
            }
        };

        let ip_addr: IpAddr = match ip.parse() {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Invalid IP {}: {}", ip, e);
                return Ok(None);
            }
        };

        // Perform MMDB lookup off the async runtime
        let lookup_result = tokio::task::spawn_blocking(move || {
            reader
                .lookup::<MmdbThreatRecord>(ip_addr)
                .map(Some)
                .or_else(|e| match e {
                    MaxMindDBError::AddressNotFoundError(_) => Ok(None),
                    other => Err(other),
                })
        })
        .await
        .context("MMDB lookup task failed")?;

        let record = match lookup_result {
            Ok(rec) => rec,
            Err(e) => {
                log::error!("MMDB lookup error for {}: {}", ip, e);
                return Ok(None);
            }
        };

        let Some(record) = record else {
            return Ok(None);
        };

        log::debug!("Threat MMDB hit for {}", ip);

        let response = self.build_response(ip, ip_addr, record)?;

        // Store in pingora-memory-cache for faster access (L1 only)
        self.set_pingora_cache(ip, &response).await;

        Ok(Some(response))
    }

    /// Get WAF fields for an IP address
    pub async fn get_waf_fields(&self, ip: &str) -> Result<Option<WafFields>> {
        if let Some(threat_data) = self.get_threat_intel(ip).await? {
            Ok(Some(WafFields::from(&threat_data)))
        } else {
            Ok(None)
        }
    }

    /// Build a ThreatResponse from the MMDB record
    fn build_response(
        &self,
        ip: &str,
        ip_addr: IpAddr,
        record: MmdbThreatRecord,
    ) -> Result<ThreatResponse> {
        let ttl = record.expiration.unwrap_or(300).max(1) as u64;

        let score = record.score.unwrap_or(0).max(0) as u32;
        let confidence = (score as f64 / 100.0).clamp(0.0, 1.0);

        let (first_seen, last_seen) = (
            parse_optional_datetime(record.created_at.as_deref()),
            parse_optional_datetime(record.updated_at.as_deref()),
        );

        let advice = map_action_to_advice(record.action.as_deref());

        let geo = GeoInfo {
            country: record.country.unwrap_or_default(),
            iso_code: record.iso_code.unwrap_or_default(),
            asn_iso_code: record.asniso_code.unwrap_or_default(),
        };

        let response = ThreatResponse {
            schema_version: "1.0".to_string(),
            tenant_id: "mmdb".to_string(),
            ip: ip.to_string(),
            intel: ThreatIntel {
                score,
                confidence,
                score_version: "mmdb".to_string(),
                categories: record
                    .source_tag_names
                    .clone()
                    .unwrap_or_default(),
                tags: record.source_tag_names.unwrap_or_default(),
                first_seen,
                last_seen,
                source_count: record.num_sources.unwrap_or(0).max(0) as u32,
                reason_code: record
                    .reason_code
                    .unwrap_or_else(|| "NO_DATA".to_string()),
                reason_summary: record
                    .description
                    .unwrap_or_else(|| "No threat data available".to_string()),
                rule_id: record.rule_id.unwrap_or_else(|| "none".to_string()),
            },
            context: ThreatContext {
                asn: record.asn.unwrap_or(0).max(0) as u32,
                org: record.asn_org.unwrap_or_default(),
                ip_version: if ip_addr.is_ipv4() { 4 } else { 6 },
                geo,
            },
            advice,
            ttl_s: ttl,
            generated_at: Utc::now(),
        };

        Ok(response)
    }

    /// Download (or read) the MMDB and keep it in memory
    async fn refresh_reader(&self) -> Result<Arc<Reader<Vec<u8>>>> {
        let data = self.fetch_mmdb_bytes().await?;

        if let Some(path) = &self.mmdb_path {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("Failed to create MMDB directory {:?}", parent))?;
            }

            tokio::fs::write(path, &data)
                .await
                .with_context(|| format!("Failed to write MMDB to {:?}", path))?;
            log::info!("Threat MMDB written to {:?}", path);
        }

        let reader = Reader::from_source(data)
            .context("Failed to parse MMDB data")?;

        let arc = Arc::new(reader);

        let mut guard = self.reader.write().await;
        *guard = Some(arc.clone());

        Ok(arc)
    }

    async fn ensure_reader(&self) -> Result<Arc<Reader<Vec<u8>>>> {
        {
            let guard = self.reader.read().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
        }

        // No reader loaded yet – fetch it now
        self.refresh_reader().await
    }

    async fn fetch_mmdb_bytes(&self) -> Result<Vec<u8>> {
        // If the URL looks like HTTP(S), download it; otherwise treat as local path
        if self.mmdb_url.starts_with("http://") || self.mmdb_url.starts_with("https://") {
            let client = get_global_reqwest_client()
                .context("Failed to get HTTP client for MMDB download")?;

            let resp = client
                .get(&self.mmdb_url)
                .send()
                .await
                .with_context(|| format!("Failed to download MMDB from {}", self.mmdb_url))?;

            let status = resp.status();
            if !status.is_success() {
                return Err(anyhow::anyhow!(
                    "MMDB download failed: status {} from {}",
                    status,
                    self.mmdb_url
                ));
            }

            let bytes = resp
                .bytes()
                .await
                .context("Failed to read MMDB response body")?;

            Ok(bytes.to_vec())
        } else {
            tokio::fs::read(&self.mmdb_url)
                .await
                .with_context(|| format!("Failed to read MMDB from {}", self.mmdb_url))
        }
    }

    /// Set data in pingora-memory-cache with TTL from record
    async fn set_pingora_cache(&self, ip: &str, data: &ThreatResponse) {
        let ttl = Duration::from_secs(data.ttl_s);
        self.pingora_cache.put(ip, data.clone(), Some(ttl));
    }
}

/// Global threat client instance
static THREAT_CLIENT: OnceCell<Arc<ThreatClient>> = OnceCell::const_new();

/// Initialize the global threat client
pub async fn init_threat_client(
    mmdb_url: String,
    mmdb_path: Option<PathBuf>,
) -> Result<()> {
    let client = Arc::new(ThreatClient::new(mmdb_url, mmdb_path));

    // Load immediately so errors show up at startup
    client.refresh_reader().await?;

    THREAT_CLIENT
        .set(client)
        .map_err(|_| anyhow::anyhow!("Failed to initialize threat client"))?;

    Ok(())
}

/// Trigger an immediate MMDB refresh (used by worker)
pub async fn refresh_threat_mmdb() -> Result<()> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.refresh().await
}

/// Get threat intelligence for an IP address
pub async fn get_threat_intel(ip: &str) -> Result<Option<ThreatResponse>> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.get_threat_intel(ip).await
}

/// Get WAF fields for an IP address
pub async fn get_waf_fields(ip: &str) -> Result<Option<WafFields>> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.get_waf_fields(ip).await
}

fn parse_optional_datetime(raw: Option<&str>) -> Option<DateTime<Utc>> {
    raw.and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

fn map_action_to_advice(action: Option<&str>) -> String {
    match action.map(|a| a.to_lowercase()) {
        Some(a) if a == "block" => "block".to_string(),
        Some(a) if a == "captcha" || a == "challenge" => "challenge".to_string(),
        _ => "allow".to_string(),
    }
}
