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

/// Threat intel client: Threat MMDB first, then GeoIP MMDB fallback, with in-memory cache
pub struct ThreatClient {
    api_base_url: String,
    api_key: String,
    threat_mmdb_path: Option<PathBuf>,
    geoip_mmdb_path: Option<PathBuf>,
    threat_reader: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
    geoip_reader: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
    pingora_cache: Arc<MemoryCache<String, ThreatResponse>>,
}

impl ThreatClient {
    pub fn new(
        api_base_url: String,
        api_key: String,
        threat_mmdb_path: Option<PathBuf>,
        geoip_mmdb_path: Option<PathBuf>,
    ) -> Self {
        Self {
            api_base_url,
            api_key,
            threat_mmdb_path,
            geoip_mmdb_path,
            threat_reader: RwLock::new(None),
            geoip_reader: RwLock::new(None),
            pingora_cache: Arc::new(MemoryCache::new(10_000)),
        }
    }

    pub async fn refresh_threat(&self) -> Result<()> {
        self.refresh_threat_reader().await.map(|_| ())
    }

    pub async fn refresh_geoip(&self) -> Result<()> {
        self.refresh_geoip_reader().await.map(|_| ())
    }

    /// Get threat intelligence for an IP address with caching
    /// Priority: Cache → Threat MMDB → GeoIP MMDB (REST API disabled)
    pub async fn get_threat_intel(&self, ip: &str) -> Result<Option<ThreatResponse>> {
        // L1 cache
        let (cached, status) = self.pingora_cache.get(ip);
        if let Some(data) = cached {
            if status.is_hit() {
                log::debug!("Threat data for {} found in pingora-memory-cache", ip);
                return Ok(Some(data));
            }
        }

        let ip_addr: IpAddr = match ip.parse() {
            Ok(v) => v,
            Err(e) => {
                log::warn!("Invalid IP {}: {}", ip, e);
                return Ok(None);
            }
        };

        // Check Threat MMDB first (if configured)
        log::info!("🔍 [Threat] Checking Threat MMDB for {}", ip);
        if let Some(threat_data) = self.lookup_threat_mmdb(ip, ip_addr).await? {
            log::info!("🔍 [Threat] Found threat data in Threat MMDB for {}: score={}", ip, threat_data.intel.score);
            self.set_pingora_cache(ip, &threat_data).await;
            return Ok(Some(threat_data));
        }

        // REST API disabled - skip directly to GeoIP fallback
        log::info!("🔍 [Threat] No threat data found for {} in Threat MMDB, using GeoIP fallback", ip);

        // GeoIP fallback
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

    /// Read the MMDB from the configured local path and keep it in memory
    async fn refresh_threat_reader(&self) -> Result<Arc<Reader<Vec<u8>>>> {
        let path = self
            .threat_mmdb_path
            .clone()
            .ok_or_else(|| anyhow!("Threat MMDB path not configured"))?;

        let data = tokio::fs::read(&path)
            .await
            .with_context(|| format!("Failed to read Threat MMDB from {:?}", path))?;

        let reader = Reader::from_source(data)
            .context("Failed to parse Threat MMDB data")?;

        let arc = Arc::new(reader);

        let mut guard = self.threat_reader.write().await;
        *guard = Some(arc.clone());

        log::info!("Threat MMDB loaded from {:?}", path);

        Ok(arc)
    }

    async fn refresh_geoip_reader(&self) -> Result<Arc<Reader<Vec<u8>>>> {
        let path = self
            .geoip_mmdb_path
            .clone()
            .ok_or_else(|| anyhow!("GeoIP MMDB path not configured"))?;

        let data = tokio::fs::read(&path)
            .await
            .with_context(|| format!("Failed to read GeoIP MMDB from {:?}", path))?;

        let reader = Reader::from_source(data)
            .context("Failed to parse GeoIP MMDB data")?;

        let arc = Arc::new(reader);

        let mut guard = self.geoip_reader.write().await;
        *guard = Some(arc.clone());

        log::info!("GeoIP MMDB loaded from {:?}", path);

        Ok(arc)
    }

    async fn ensure_threat_reader(&self) -> Result<Arc<Reader<Vec<u8>>>> {
        {
            let guard = self.threat_reader.read().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
        }

        // No reader loaded yet – fetch it now
        self.refresh_threat_reader().await
    }

    async fn ensure_geoip_reader(&self) -> Result<Arc<Reader<Vec<u8>>>> {
        {
            let guard = self.geoip_reader.read().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
        }

        // No reader loaded yet – fetch it now
        self.refresh_geoip_reader().await
    }

    /// Look up threat intelligence from the Threat MMDB
    async fn lookup_threat_mmdb(&self, ip: &str, ip_addr: IpAddr) -> Result<Option<ThreatResponse>> {
        log::info!("🔍 [Threat MMDB] Starting lookup for {}", ip);
        
        // Check if threat reader is available
        let reader_opt = {
            let guard = self.threat_reader.read().await;
            guard.clone()
        };

        let reader = match reader_opt {
            Some(r) => {
                log::info!("🔍 [Threat MMDB] Reader available, performing lookup");
                r
            }
            None => {
                log::warn!("🔍 [Threat MMDB] Reader not loaded, skipping threat lookup for {}", ip);
                return Ok(None);
            }
        };

        // Perform blocking MMDB lookup in a separate thread
        let result = tokio::task::spawn_blocking({
            let reader = reader.clone();
            let ip_addr_clone = ip_addr;
            move || -> Result<ThreatResponse, maxminddb::MaxMindDBError> {
                reader.lookup(ip_addr_clone)
            }
        })
        .await;

        match result {
            Ok(Ok(threat_data)) => {
                log::info!("🔍 [Threat MMDB] Found data for {}: {:?}", ip, threat_data);
                Ok(Some(threat_data))
            }
            Ok(Err(maxminddb::MaxMindDBError::AddressNotFoundError(_))) => {
                log::debug!("🔍 [Threat MMDB] IP {} not found in database", ip);
                Ok(None)
            }
            Ok(Err(e)) => {
                log::warn!("🔍 [Threat MMDB] Lookup error for {}: {}", ip, e);
                Ok(None)
            }
            Err(e) => {
                log::warn!("🔍 [Threat MMDB] Task error for {}: {}", ip, e);
                Ok(None)
            }
        }
    }

    async fn lookup_geo(&self, ip: IpAddr) -> Result<(GeoInfo, u32, String)> {
        log::debug!("🔍 [GeoIP] Looking up IP: {}", ip);
        
        // ASN lookup (extract owned data inside blocking task)
        let reader = self.ensure_geoip_reader().await?;
        let (asn_num, asn_org) = tokio::task::spawn_blocking({
            let reader = reader.clone();
            let ip_clone = ip;
            move || -> Result<(u32, String), MaxMindDBError> {
                match reader.lookup::<geoip2::Asn>(ip_clone) {
                    Ok(res) => {
                        let asn = res.autonomous_system_number.unwrap_or(0);
                        let org = res.autonomous_system_organization.unwrap_or("").to_string();
                        log::info!("🔍 [GeoIP] ASN Lookup Success for {}: ASN={}, Org='{}'", ip_clone, asn, org);
                        Ok((asn, org))
                    }
                    Err(e) => {
                        log::warn!("🔍 [GeoIP] ASN Lookup FAILED for {}: {}", ip_clone, e);
                        Ok((0, String::new()))
                    }
                }
            }
        })
        .await??;

        // Country lookup (owned iso and name)
        let reader2 = self.ensure_geoip_reader().await?;
        let (iso, country_name) = tokio::task::spawn_blocking({
            let reader = reader2.clone();
            let ip_clone = ip;
            move || -> Result<(String, String), MaxMindDBError> {
                match reader.lookup::<geoip2::Country>(ip_clone) {
                    Ok(country) => {
                        // Debug: Log the raw country data structure
                        log::info!("🔍 [GeoIP] RAW Country Data for {}: {:?}", ip_clone, country);
                        
                        // Try multiple fields
                        let iso = country
                            .country
                            .as_ref()
                            .and_then(|c| c.iso_code)
                            .unwrap_or("")
                            .to_string();
                        
                        // Also try registered_country if country is empty
                        let iso = if iso.is_empty() {
                            country
                                .registered_country
                                .as_ref()
                                .and_then(|c| c.iso_code)
                                .unwrap_or("")
                                .to_string()
                        } else {
                            iso
                        };
                        
                        let country_name = country
                            .country
                            .as_ref()
                            .and_then(|c| c.names.as_ref())
                            .and_then(|n| n.get("en"))
                            .map(|s| s.to_string())
                            .unwrap_or_default();
                        
                        if iso.is_empty() {
                            log::warn!("🔍 [GeoIP] Country Lookup for {} returned EMPTY iso_code (IP found but no country data in ANY field)", ip_clone);
                        } else {
                            log::info!("🔍 [GeoIP] Country Lookup Success for {}: Country='{}' ({})", ip_clone, iso, country_name);
                        }
                        Ok((iso, country_name))
                    }
                    Err(e) => {
                        log::warn!("🔍 [GeoIP] Country Lookup FAILED for {}: IP NOT FOUND in database - {}", ip_clone, e);
                        Ok((String::new(), String::new()))
                    }
                }
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
    threat_mmdb_path: Option<PathBuf>,
    geoip_mmdb_path: Option<PathBuf>,
) -> Result<()> {
    let client = Arc::new(ThreatClient::new(
        api_base_url,
        api_key,
        threat_mmdb_path,
        geoip_mmdb_path,
    ));

    // Best-effort initial load from local MMDB paths.
    // If the files are not present yet, the workers can download them later.
    if let Err(e) = client.refresh_threat_reader().await {
        log::warn!("Initial Threat MMDB load failed: {}", e);
    }

    if let Err(e) = client.refresh_geoip_reader().await {
        log::warn!("Initial GeoIP MMDB load failed: {}", e);
    }

    THREAT_CLIENT
        .set(client)
        .map_err(|_| anyhow::anyhow!("Failed to initialize threat client"))?;

    Ok(())
}

/// Trigger an immediate Threat MMDB refresh (used by worker)
pub async fn refresh_threat_mmdb() -> Result<()> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.refresh_threat().await
}

/// Trigger an immediate GeoIP MMDB refresh (used by worker)
pub async fn refresh_geoip_mmdb() -> Result<()> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.refresh_geoip().await
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

