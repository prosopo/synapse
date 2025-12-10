use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use maxminddb::{geoip2, MaxMindDBError, Reader};
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

/// Threat intelligence response (REST shape)
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

/// Threat intel client: REST API first, GeoIP MMDB fallback, in-memory cache only
pub struct ThreatClient {
    api_base_url: String,
    api_key: String,
    mmdb_base_url: String,
    versions_url: Option<String>,
    mmdb_path: Option<PathBuf>,
    reader: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
    current_version: RwLock<Option<String>>,
    current_path: RwLock<Option<PathBuf>>,
    pingora_cache: Arc<MemoryCache<String, ThreatResponse>>,
}

impl ThreatClient {
    pub fn new(
        api_base_url: String,
        api_key: String,
        mmdb_base_url: String,
        versions_url: Option<String>,
        mmdb_path: Option<PathBuf>,
    ) -> Self {
        Self {
            api_base_url,
            api_key,
            mmdb_base_url,
            versions_url,
            mmdb_path,
            reader: RwLock::new(None),
            current_version: RwLock::new(None),
            current_path: RwLock::new(None),
            pingora_cache: Arc::new(MemoryCache::new(10_000)),
        }
    }

    pub async fn refresh(&self) -> Result<()> {
        self.refresh_reader().await.map(|_| ())
    }

    /// Get threat intelligence for an IP address with caching and GeoIP fallback
    pub async fn get_threat_intel(&self, ip: &str) -> Result<Option<ThreatResponse>> {
        // L1 cache
        let (cached, status) = self.pingora_cache.get(ip);
        if let Some(data) = cached {
            if status.is_hit() {
                log::debug!("Threat data for {} found in pingora-memory-cache", ip);
                return Ok(Some(data));
            }
        }

        // REST API first
        if let Some(api_data) = self.fetch_from_api(ip).await? {
            self.set_pingora_cache(ip, &api_data).await;
            return Ok(Some(api_data));
        }

        // GeoIP fallback
        let ip_addr: IpAddr = match ip.parse() {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Invalid IP {}: {}", ip, e);
                return Ok(None);
            }
        };

        let (geo, asn, org) = self.lookup_geo(ip_addr).await?;
        let response = build_no_data_response(ip, ip_addr, geo, asn, org);
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

    async fn fetch_from_api(&self, ip: &str) -> Result<Option<ThreatResponse>> {
        if self.api_base_url.is_empty() || self.api_key.is_empty() {
            return Ok(None);
        }

        let url = format!("{}/threat?ip={}", self.api_base_url.trim_end_matches('/'), ip);
        let client = get_global_reqwest_client()
            .context("Failed to get global HTTP client")?;

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", &self.api_key))
            .send()
            .await
            .context("Failed to send HTTP request")?;

        if response.status() == 404 {
            return Ok(None);
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_else(|_| "Unable to read response body".to_string());
            log::error!("API request failed with status: {}, body: {}", status, body);
            return Ok(None);
        }

        let response_text = response.text().await
            .context("Failed to read response body")?;

        let threat_data: ThreatResponse = serde_json::from_str(&response_text)
            .context("Failed to parse JSON response")?;

        Ok(Some(threat_data))
    }

    /// Download (or read) the MMDB and keep it in memory
    async fn refresh_reader(&self) -> Result<Arc<Reader<Vec<u8>>>> {
        let (version_opt, data, target_path) = self.fetch_mmdb_bytes().await?;

        if let Some(path) = &target_path {
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

        if let Some(ver) = version_opt {
            let mut vguard = self.current_version.write().await;
            *vguard = Some(ver);
        }
        if let Some(path) = target_path {
            let mut pguard = self.current_path.write().await;
            let old = pguard.replace(path.clone());
            drop(pguard);
            if let Some(old_path) = old {
                if old_path != path {
                    let _ = tokio::fs::remove_file(old_path).await;
                }
            }
        }

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

    async fn lookup_geo(&self, ip: IpAddr) -> Result<(GeoInfo, u32, String)> {
        // ASN lookup (extract owned data inside blocking task)
        let reader = self.ensure_reader().await?;
        let (asn_num, asn_org) = tokio::task::spawn_blocking({
            let reader = reader.clone();
            move || -> Result<(u32, String), MaxMindDBError> {
                let res: geoip2::Asn = reader.lookup(ip)?;
                Ok((
                    res.autonomous_system_number.unwrap_or(0),
                    res.autonomous_system_organization.unwrap_or("").to_string(),
                ))
            }
        })
        .await??;

        // Country lookup (owned iso and name)
        let reader2 = self.ensure_reader().await?;
        let (iso, country_name) = tokio::task::spawn_blocking({
            let reader = reader2.clone();
            move || -> Result<(String, String), MaxMindDBError> {
                let country: geoip2::Country = reader.lookup(ip)?;
                let iso = country
                    .country
                    .as_ref()
                    .and_then(|c| c.iso_code)
                    .unwrap_or("")
                    .to_string();
                let country_name = country
                    .country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                Ok((iso, country_name))
            }
        })
        .await??;

        Ok((
            GeoInfo {
                country: country_name,
                iso_code: iso.clone(),
                asn_iso_code: iso,
            },
            asn_num,
            asn_org,
        ))
    }

    async fn fetch_mmdb_bytes(&self) -> Result<(Option<String>, Vec<u8>, Option<PathBuf>)> {
        // If versions URL is provided, resolve latest first
        if let Some(vurl) = &self.versions_url {
            let client = get_global_reqwest_client()
                .context("Failed to get HTTP client for versions download")?;
            let resp = client
                .get(vurl)
                .send()
                .await
                .with_context(|| format!("Failed to download versions file from {}", vurl))?;
            let status = resp.status();
            if !status.is_success() {
                return Err(anyhow::anyhow!(
                    "Versions download failed: status {} from {}",
                    status,
                    vurl
                ));
            }
            let text = resp.text().await.context("Failed to read versions body")?;
            let latest = parse_latest_version(&text)
                .ok_or_else(|| anyhow!("Failed to parse latest version from versions file"))?;
            let base = self.mmdb_base_url.trim_end_matches('/');

            if base.starts_with("http://") || base.starts_with("https://") {
                let url = format!("{}/{}", base, latest);
                let bytes = download_mmdb(&url).await?;
                let target_path = compute_target_path(self.mmdb_path.clone(), Some(&latest));
                return Ok((Some(latest), bytes, target_path));
            } else {
                let local_path = PathBuf::from(base).join(&latest);
                let bytes = tokio::fs::read(&local_path)
                    .await
                    .with_context(|| format!("Failed to read MMDB from {:?}", local_path))?;
                let target_path = compute_target_path(self.mmdb_path.clone(), Some(&latest));
                return Ok((Some(latest), bytes, target_path));
            }
        }

        // Fallback: single static URL/path
        if self.mmdb_base_url.starts_with("http://") || self.mmdb_base_url.starts_with("https://") {
            let bytes = download_mmdb(&self.mmdb_base_url).await?;
            let target_path = compute_target_path(self.mmdb_path.clone(), None);
            Ok((None, bytes, target_path))
        } else {
            let bytes = tokio::fs::read(&self.mmdb_base_url)
                .await
                .with_context(|| format!("Failed to read MMDB from {}", self.mmdb_base_url))?;
            let target_path = compute_target_path(self.mmdb_path.clone(), None);
            Ok((None, bytes, target_path))
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
    api_base_url: String,
    api_key: String,
    mmdb_base_url: String,
    versions_url: Option<String>,
    mmdb_path: Option<PathBuf>,
) -> Result<()> {
    let client = Arc::new(ThreatClient::new(api_base_url, api_key, mmdb_base_url, versions_url, mmdb_path));

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

fn build_no_data_response(ip: &str, ip_addr: IpAddr, geo: GeoInfo, asn: u32, org: String) -> ThreatResponse {
    ThreatResponse {
        schema_version: "1.0".to_string(),
        tenant_id: "geoip".to_string(),
        ip: ip.to_string(),
        intel: ThreatIntel {
            score: 0,
            confidence: 0.0,
            score_version: "geoip".to_string(),
            categories: vec![],
            tags: vec![],
            first_seen: None,
            last_seen: None,
            source_count: 0,
            reason_code: "NO_DATA".to_string(),
            reason_summary: "No threat data available".to_string(),
            rule_id: "none".to_string(),
        },
        context: ThreatContext {
            asn,
            org,
            ip_version: if ip_addr.is_ipv4() { 4 } else { 6 },
            geo,
        },
        advice: "allow".to_string(),
        ttl_s: 300,
        generated_at: Utc::now(),
    }
}

fn compute_target_path(base: Option<PathBuf>, latest: Option<&str>) -> Option<PathBuf> {
    match (base, latest) {
        (Some(p), Some(fname)) => {
            if p.extension().is_some() {
                Some(p)
            } else {
                Some(p.join(fname))
            }
        }
        (Some(p), None) => Some(p),
        (None, Some(fname)) => Some(PathBuf::from(fname)),
        (None, None) => None,
    }
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
        return Err(anyhow::anyhow!(
            "MMDB download failed: status {} from {}",
            status,
            url
        ));
    }
    let bytes = resp.bytes().await.context("Failed to read MMDB body")?;
    Ok(bytes.to_vec())
}
