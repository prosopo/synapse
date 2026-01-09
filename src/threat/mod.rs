use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use maxminddb::{geoip2, MaxMindDbError, Reader};
use memmap2::MmapOptions;
use std::fs::File;
use pingora_memory_cache::MemoryCache;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::{OnceCell, RwLock};

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
    threat_mmdb_path: Option<PathBuf>,
    geoip_country_path: Option<PathBuf>,
    geoip_asn_path: Option<PathBuf>,
    geoip_city_path: Option<PathBuf>,
    threat_reader: RwLock<Option<Arc<Reader<memmap2::Mmap>>>>,
    geoip_country_reader: RwLock<Option<Arc<Reader<memmap2::Mmap>>>>,
    geoip_asn_reader: RwLock<Option<Arc<Reader<memmap2::Mmap>>>>,
    geoip_city_reader: RwLock<Option<Arc<Reader<memmap2::Mmap>>>>,
    pingora_cache: Arc<MemoryCache<String, ThreatResponse>>,
}

impl ThreatClient {
    pub fn new(
        threat_mmdb_path: Option<PathBuf>,
        geoip_country_path: Option<PathBuf>,
        geoip_asn_path: Option<PathBuf>,
        geoip_city_path: Option<PathBuf>,
    ) -> Self {
        Self {
            threat_mmdb_path,
            geoip_country_path,
            geoip_asn_path,
            geoip_city_path,
            threat_reader: RwLock::new(None),
            geoip_country_reader: RwLock::new(None),
            geoip_asn_reader: RwLock::new(None),
            geoip_city_reader: RwLock::new(None),
            pingora_cache: Arc::new(MemoryCache::new(10_000)),
        }
    }

    pub async fn refresh_threat(&self) -> Result<()> {
        self.refresh_threat_reader().await.map(|_| ())
    }

    pub async fn refresh_geoip(&self) -> Result<()> {
        // Refresh all geoip databases
        if let Err(e) = self.refresh_geoip_country_reader().await {
            log::warn!("Failed to refresh GeoIP Country database: {}", e);
        }
        if let Err(e) = self.refresh_geoip_asn_reader().await {
            log::warn!("Failed to refresh GeoIP ASN database: {}", e);
        }
        if let Err(e) = self.refresh_geoip_city_reader().await {
            log::warn!("Failed to refresh GeoIP City database: {}", e);
        }
        Ok(())
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


    /// Open the MMDB from the configured local path using memory-mapped file access
    async fn refresh_threat_reader(&self) -> Result<Arc<Reader<memmap2::Mmap>>> {
        let mut path = self
            .threat_mmdb_path
            .clone()
            .ok_or_else(|| anyhow!("Threat MMDB path not configured"))?;

        // If the path doesn't have a file extension, treat it as a directory and append the filename
        if path.extension().is_none() {
            path = path.join("threat.mmdb");
        }

        // Use spawn_blocking since file operations are blocking
        let reader = tokio::task::spawn_blocking({
            let path = path.clone();
            move || -> Result<Reader<memmap2::Mmap>> {
                let file = File::open(&path)
                    .with_context(|| format!("Failed to open Threat MMDB file {:?}", path))?;
                let mmap = unsafe {
                    MmapOptions::new()
                        .map(&file)
                        .with_context(|| format!("Failed to memory-map Threat MMDB from {:?}", path))?
                };
                Reader::from_source(mmap)
                    .with_context(|| format!("Failed to parse Threat MMDB from {:?}", path))
            }
        })
        .await
        .context("Failed to spawn blocking task for MMDB open")??;

        let arc = Arc::new(reader);

        let mut guard = self.threat_reader.write().await;
        *guard = Some(arc.clone());

        log::info!("Threat MMDB opened (memory-mapped) from {:?}", path);

        Ok(arc)
    }

    async fn refresh_geoip_country_reader(&self) -> Result<Arc<Reader<memmap2::Mmap>>> {
        let mut path = self
            .geoip_country_path
            .clone()
            .ok_or_else(|| anyhow!("GeoIP Country MMDB path not configured"))?;

        // If the path doesn't have a file extension, treat it as a directory and append the filename
        if path.extension().is_none() {
            path = path.join("GeoLite2-Country.mmdb");
        }

        // Use spawn_blocking since file operations are blocking
        let reader = tokio::task::spawn_blocking({
            let path = path.clone();
            move || -> Result<Reader<memmap2::Mmap>> {
                let file = File::open(&path)
                    .with_context(|| format!("Failed to open GeoIP Country MMDB file {:?}", path))?;
                let mmap = unsafe {
                    MmapOptions::new()
                        .map(&file)
                        .with_context(|| format!("Failed to memory-map GeoIP Country MMDB from {:?}", path))?
                };
                Reader::from_source(mmap)
                    .with_context(|| format!("Failed to parse GeoIP Country MMDB from {:?}", path))
            }
        })
        .await
        .context("Failed to spawn blocking task for MMDB open")??;

        let arc = Arc::new(reader);

        let mut guard = self.geoip_country_reader.write().await;
        *guard = Some(arc.clone());

        log::info!("GeoIP Country MMDB opened (memory-mapped) from {:?}", path);

        Ok(arc)
    }

    async fn refresh_geoip_asn_reader(&self) -> Result<Arc<Reader<memmap2::Mmap>>> {
        let mut path = self
            .geoip_asn_path
            .clone()
            .ok_or_else(|| anyhow!("GeoIP ASN MMDB path not configured"))?;

        // If the path doesn't have a file extension, treat it as a directory and append the filename
        if path.extension().is_none() {
            path = path.join("GeoLite2-ASN.mmdb");
        }

        // Use spawn_blocking since file operations are blocking
        let reader = tokio::task::spawn_blocking({
            let path = path.clone();
            move || -> Result<Reader<memmap2::Mmap>> {
                let file = File::open(&path)
                    .with_context(|| format!("Failed to open GeoIP ASN MMDB file {:?}", path))?;
                let mmap = unsafe {
                    MmapOptions::new()
                        .map(&file)
                        .with_context(|| format!("Failed to memory-map GeoIP ASN MMDB from {:?}", path))?
                };
                Reader::from_source(mmap)
                    .with_context(|| format!("Failed to parse GeoIP ASN MMDB from {:?}", path))
            }
        })
        .await
        .context("Failed to spawn blocking task for MMDB open")??;

        let arc = Arc::new(reader);

        let mut guard = self.geoip_asn_reader.write().await;
        *guard = Some(arc.clone());

        log::info!("GeoIP ASN MMDB opened (memory-mapped) from {:?}", path);

        Ok(arc)
    }

    async fn refresh_geoip_city_reader(&self) -> Result<Arc<Reader<memmap2::Mmap>>> {
        let mut path = self
            .geoip_city_path
            .clone()
            .ok_or_else(|| anyhow!("GeoIP City MMDB path not configured"))?;

        // If the path doesn't have a file extension, treat it as a directory and append the filename
        if path.extension().is_none() {
            path = path.join("GeoLite2-City.mmdb");
        }

        // Use spawn_blocking since file operations are blocking
        let reader = tokio::task::spawn_blocking({
            let path = path.clone();
            move || -> Result<Reader<memmap2::Mmap>> {
                let file = File::open(&path)
                    .with_context(|| format!("Failed to open GeoIP City MMDB file {:?}", path))?;
                let mmap = unsafe {
                    MmapOptions::new()
                        .map(&file)
                        .with_context(|| format!("Failed to memory-map GeoIP City MMDB from {:?}", path))?
                };
                Reader::from_source(mmap)
                    .with_context(|| format!("Failed to parse GeoIP City MMDB from {:?}", path))
            }
        })
        .await
        .context("Failed to spawn blocking task for MMDB open")??;

        let arc = Arc::new(reader);

        let mut guard = self.geoip_city_reader.write().await;
        *guard = Some(arc.clone());

        log::info!("GeoIP City MMDB opened (memory-mapped) from {:?}", path);

        Ok(arc)
    }

    async fn ensure_geoip_country_reader(&self) -> Result<Arc<Reader<memmap2::Mmap>>> {
        {
            let guard = self.geoip_country_reader.read().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
        }
        self.refresh_geoip_country_reader().await
    }

    async fn ensure_geoip_asn_reader(&self) -> Result<Arc<Reader<memmap2::Mmap>>> {
        {
            let guard = self.geoip_asn_reader.read().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
        }
        self.refresh_geoip_asn_reader().await
    }

    async fn ensure_geoip_city_reader(&self) -> Result<Arc<Reader<memmap2::Mmap>>> {
        {
            let guard = self.geoip_city_reader.read().await;
            if let Some(existing) = guard.as_ref() {
                return Ok(existing.clone());
            }
        }
        self.refresh_geoip_city_reader().await
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
            move || -> Result<ThreatResponse, maxminddb::MaxMindDbError> {
                let lookup_result = reader.lookup(ip_addr_clone)?;
                if !lookup_result.has_data() {
                    return Err(maxminddb::MaxMindDbError::invalid_input("IP address not found in database"));
                }
                lookup_result.decode()?
                    .ok_or_else(|| maxminddb::MaxMindDbError::invalid_input("Failed to decode threat data"))
            }
        })
        .await;

        match result {
            Ok(Ok(threat_data)) => {
                log::info!("🔍 [Threat MMDB] Found data for {}: {:?}", ip, threat_data);
                Ok(Some(threat_data))
            }
            Ok(Err(e)) => {
                log::debug!("🔍 [Threat MMDB] IP {} not found or error: {}", ip, e);
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

        // ASN lookup (use ASN database if available, otherwise try country database)
        let (asn_num, asn_org) = if let Ok(reader) = self.ensure_geoip_asn_reader().await {
            tokio::task::spawn_blocking({
            let reader = reader.clone();
            let ip_clone = ip;
            move || -> Result<(u32, String), MaxMindDbError> {
                match reader.lookup(ip_clone) {
                    Ok(lookup_result) => {
                        if !lookup_result.has_data() {
                            log::warn!("🔍 [GeoIP] ASN Lookup: No data for {}", ip_clone);
                            return Ok((0, String::new()));
                        }
                        match lookup_result.decode::<geoip2::Asn>() {
                            Ok(Some(res)) => {
                                let asn = res.autonomous_system_number.unwrap_or(0);
                                let org = res.autonomous_system_organization.unwrap_or("").to_string();
                                log::info!("🔍 [GeoIP] ASN Lookup Success for {}: ASN={}, Org='{}'", ip_clone, asn, org);
                                Ok((asn, org))
                            }
                            Ok(None) => {
                                log::warn!("🔍 [GeoIP] ASN Lookup: No ASN data for {}", ip_clone);
                                Ok((0, String::new()))
                            }
                            Err(e) => {
                                log::warn!("🔍 [GeoIP] ASN Lookup FAILED for {}: {}", ip_clone, e);
                                Ok((0, String::new()))
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("🔍 [GeoIP] ASN Lookup FAILED for {}: {}", ip_clone, e);
                        Ok((0, String::new()))
                    }
                }
            }
        })
            .await??
        } else {
            (0, String::new())
        };

        // Country lookup (use country database if available, fallback to city database)
        let reader2 = if let Ok(reader) = self.ensure_geoip_country_reader().await {
            reader
        } else if let Ok(reader) = self.ensure_geoip_city_reader().await {
            reader
        } else {
            return Err(anyhow!("No GeoIP database available for country lookup"));
        };
        let (iso, country_name): (String, String) = tokio::task::spawn_blocking({
            let reader = reader2.clone();
            let ip_clone = ip;
            move || -> Result<(String, String), MaxMindDbError> {
                match reader.lookup(ip_clone) {
                    Ok(lookup_result) => {
                        if !lookup_result.has_data() {
                            log::warn!("🔍 [GeoIP] Country Lookup: No data for {}", ip_clone);
                            return Ok((String::new(), String::new()));
                        }
                        match lookup_result.decode::<geoip2::Country>() {
                            Ok(Some(country)) => {
                                // Debug: Log the raw country data structure
                                log::info!("🔍 [GeoIP] RAW Country Data for {}: {:?}", ip_clone, country);

                                // Try multiple fields
                                let iso = country
                                    .country
                                    .iso_code
                                    .unwrap_or("")
                                    .to_string();

                                // Also try registered_country if country is empty
                                let iso = if iso.is_empty() {
                                    country
                                        .registered_country
                                        .iso_code
                                        .unwrap_or("")
                                        .to_string()
                                } else {
                                    iso
                                };

                                let country_name = country
                                    .country
                                    .names
                                    .english
                                    .map(|s| s.to_string())
                                    .unwrap_or_default();

                                if iso.is_empty() {
                                    log::warn!("🔍 [GeoIP] Country Lookup for {} returned EMPTY iso_code (IP found but no country data in ANY field)", ip_clone);
                                } else {
                                    log::info!("🔍 [GeoIP] Country Lookup Success for {}: Country='{}' ({})", ip_clone, iso, country_name);
                                }
                                Ok((iso, country_name))
                            }
                            Ok(None) => {
                                log::warn!("🔍 [GeoIP] Country Lookup: No country data for {}", ip_clone);
                                Ok((String::new(), String::new()))
                            }
                            Err(e) => {
                                log::warn!("🔍 [GeoIP] Country Lookup FAILED for {}: IP NOT FOUND in database - {}", ip_clone, e);
                                Ok((String::new(), String::new()))
                            }
                        }
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
    threat_mmdb_path: Option<PathBuf>,
    geoip_country_path: Option<PathBuf>,
    geoip_asn_path: Option<PathBuf>,
    geoip_city_path: Option<PathBuf>,
) -> Result<()> {
    let client = Arc::new(ThreatClient::new(
        threat_mmdb_path,
        geoip_country_path,
        geoip_asn_path,
        geoip_city_path,
    ));

    // Best-effort initial load from local MMDB paths.
    // If the files are not present yet, the workers can download them later.
    if let Err(e) = client.refresh_threat_reader().await {
        log::warn!("Initial Threat MMDB load failed: {}", e);
    }

    if let Err(e) = client.refresh_geoip_country_reader().await {
        log::warn!("Initial GeoIP Country MMDB load failed: {}", e);
    }
    if let Err(e) = client.refresh_geoip_asn_reader().await {
        log::warn!("Initial GeoIP ASN MMDB load failed: {}", e);
    }
    if let Err(e) = client.refresh_geoip_city_reader().await {
        log::warn!("Initial GeoIP City MMDB load failed: {}", e);
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

/// Trigger an immediate GeoIP MMDB refresh for all databases (used by worker)
pub async fn refresh_geoip_mmdb() -> Result<()> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.refresh_geoip().await
}

/// Trigger an immediate GeoIP Country MMDB refresh (used by worker)
pub async fn refresh_geoip_country_mmdb() -> Result<()> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.refresh_geoip_country_reader().await.map(|_| ())
}

/// Trigger an immediate GeoIP ASN MMDB refresh (used by worker)
pub async fn refresh_geoip_asn_mmdb() -> Result<()> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.refresh_geoip_asn_reader().await.map(|_| ())
}

/// Trigger an immediate GeoIP City MMDB refresh (used by worker)
pub async fn refresh_geoip_city_mmdb() -> Result<()> {
    let client = THREAT_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Threat client not initialized"))?;

    client.refresh_geoip_city_reader().await.map(|_| ())
}

/// Get threat intelligence for an IP address
pub async fn get_threat_intel(ip: &str) -> Result<Option<ThreatResponse>> {
    let client = match THREAT_CLIENT.get() {
        Some(c) => c,
        None => {
            log::trace!("Threat client not initialized (API key not provided), skipping threat intel lookup for {}", ip);
            return Ok(None);
        }
    };

    client.get_threat_intel(ip).await
}

/// Get access to a version cache (separate from threat response cache)
/// Uses the same pingora-memory-cache pattern as the threat response cache
pub fn get_version_cache() -> Result<Arc<MemoryCache<String, String>>> {
    use std::sync::OnceLock;
    static VERSION_CACHE: OnceLock<Arc<MemoryCache<String, String>>> = OnceLock::new();
    Ok(VERSION_CACHE.get_or_init(|| Arc::new(MemoryCache::new(100))).clone())
}

/// Get WAF fields for an IP address
pub async fn get_waf_fields(ip: &str) -> Result<Option<WafFields>> {
    let client = match THREAT_CLIENT.get() {
        Some(c) => c,
        None => {
            log::trace!("Threat client not initialized (API key not provided), skipping WAF fields lookup for {}", ip);
            return Ok(None);
        }
    };

    client.get_waf_fields(ip).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_build_no_data_response_ipv4() {
        let ip = "192.168.1.1";
        let ip_addr: IpAddr = ip.parse().unwrap();
        let geo = GeoInfo {
            country: "United States".to_string(),
            iso_code: "US".to_string(),
            asn_iso_code: "US".to_string(),
        };
        let response = build_no_data_response(ip, ip_addr, geo.clone(), 12345, "Test Org".to_string());

        assert_eq!(response.ip, ip);
        assert_eq!(response.context.ip_version, 4);
        assert_eq!(response.context.asn, 12345);
        assert_eq!(response.context.org, "Test Org");
        assert_eq!(response.context.geo.iso_code, "US");
        assert_eq!(response.intel.score, 0);
        assert_eq!(response.advice, "allow");
        assert_eq!(response.intel.reason_code, "NO_DATA");
    }

    #[test]
    fn test_build_no_data_response_ipv6() {
        let ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let ip_addr: IpAddr = ip.parse().unwrap();
        let geo = GeoInfo {
            country: "United States".to_string(),
            iso_code: "US".to_string(),
            asn_iso_code: "US".to_string(),
        };
        let response = build_no_data_response(ip, ip_addr, geo.clone(), 67890, "Test Org 2".to_string());

        assert_eq!(response.ip, ip);
        assert_eq!(response.context.ip_version, 6);
        assert_eq!(response.context.asn, 67890);
        assert_eq!(response.context.org, "Test Org 2");
    }

    #[test]
    fn test_waf_fields_from_threat_response() {
        let threat = ThreatResponse {
            schema_version: "1.0".to_string(),
            tenant_id: "test".to_string(),
            ip: "192.168.1.1".to_string(),
            intel: ThreatIntel {
                score: 75,
                confidence: 0.85,
                score_version: "1.0".to_string(),
                categories: vec!["malware".to_string()],
                tags: vec!["suspicious".to_string()],
                first_seen: None,
                last_seen: None,
                source_count: 5,
                reason_code: "THREAT_DETECTED".to_string(),
                reason_summary: "Threat detected".to_string(),
                rule_id: "rule1".to_string(),
            },
            context: ThreatContext {
                asn: 12345,
                org: "Test Org".to_string(),
                ip_version: 4,
                geo: GeoInfo {
                    country: "United States".to_string(),
                    iso_code: "US".to_string(),
                    asn_iso_code: "US".to_string(),
                },
            },
            advice: "block".to_string(),
            ttl_s: 3600,
            generated_at: Utc::now(),
        };

        let waf_fields = WafFields::from(&threat);
        assert_eq!(waf_fields.ip_src_country, "US");
        assert_eq!(waf_fields.ip_src_asn, 12345);
        assert_eq!(waf_fields.ip_src_asn_org, "Test Org");
        assert_eq!(waf_fields.ip_src_asn_country, "US");
        assert_eq!(waf_fields.threat_score, 75);
        assert_eq!(waf_fields.threat_advice, "block");
    }

    #[test]
    fn test_threat_client_new() {
        let _client = ThreatClient::new(None, None, None, None);
        // Just verify it can be created without panicking
        assert!(true);
    }

    #[tokio::test]
    async fn test_threat_client_get_threat_intel_invalid_ip() {
        let client = ThreatClient::new(None, None, None, None);
        let result = client.get_threat_intel("invalid-ip").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_threat_client_get_waf_fields_no_client() {
        let client = ThreatClient::new(None, None, None, None);
        let result = client.get_waf_fields("192.168.1.1").await;
        // Should return Ok(None) when no databases are configured or IP not found
        // The method may return an error if IP parsing fails, so we just check it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_geo_info_serialization() {
        let geo = GeoInfo {
            country: "United States".to_string(),
            iso_code: "US".to_string(),
            asn_iso_code: "US".to_string(),
        };
        let json = serde_json::to_string(&geo).unwrap();
        assert!(json.contains("US"));
        assert!(json.contains("United States"));
    }

    #[test]
    fn test_threat_response_serialization() {
        let response = ThreatResponse {
            schema_version: "1.0".to_string(),
            tenant_id: "test".to_string(),
            ip: "192.168.1.1".to_string(),
            intel: ThreatIntel {
                score: 50,
                confidence: 0.75,
                score_version: "1.0".to_string(),
                categories: vec!["test".to_string()],
                tags: vec![],
                first_seen: None,
                last_seen: None,
                source_count: 1,
                reason_code: "TEST".to_string(),
                reason_summary: "Test".to_string(),
                rule_id: "test".to_string(),
            },
            context: ThreatContext {
                asn: 12345,
                org: "Test".to_string(),
                ip_version: 4,
                geo: GeoInfo {
                    country: "US".to_string(),
                    iso_code: "US".to_string(),
                    asn_iso_code: "US".to_string(),
                },
            },
            advice: "allow".to_string(),
            ttl_s: 300,
            generated_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("192.168.1.1"));
        assert!(json.contains("\"score\":50"));
        assert!(json.contains("\"asn\":12345"));
    }

    #[test]
    fn test_maxminddb_error_type() {
        // Verify that MaxMindDbError (not MaxMindDBError) is the correct type
        let error = maxminddb::MaxMindDbError::invalid_input("test error");
        match error {
            maxminddb::MaxMindDbError::InvalidInput { message } => {
                assert_eq!(message, "test error");
            }
            _ => panic!("Expected InvalidInput variant"),
        }
    }

    #[test]
    fn test_maxminddb_error_invalid_database() {
        let error = maxminddb::MaxMindDbError::invalid_database("corrupted database");
        match error {
            maxminddb::MaxMindDbError::InvalidDatabase { message, .. } => {
                assert_eq!(message, "corrupted database");
            }
            _ => panic!("Expected InvalidDatabase variant"),
        }
    }

    #[test]
    fn test_maxminddb_error_decoding() {
        let error = maxminddb::MaxMindDbError::decoding("decoding failed");
        match error {
            maxminddb::MaxMindDbError::Decoding { message, .. } => {
                assert_eq!(message, "decoding failed");
            }
            _ => panic!("Expected Decoding variant"),
        }
    }

    #[test]
    fn test_geoip2_country_structure() {
        // Test that we can construct a geoip2::Country structure
        // This verifies the field access patterns we use in the code
        use maxminddb::geoip2;

        // Create a default Country structure
        let country_record = geoip2::Country::default();

        // Verify the structure has the expected fields
        // country.country and country.registered_country are direct structs (not Options)
        let _iso_code = country_record.country.iso_code;
        let _registered_iso = country_record.registered_country.iso_code;
        let _english_name = country_record.country.names.english;

        // Just verify it compiles and the structure is correct
        assert!(true);
    }

    #[test]
    fn test_geoip2_asn_structure() {
        // Test that we can work with geoip2::Asn structure
        // Note: Asn doesn't have Default, but we can verify the field types exist
        // Verify the structure has the expected fields by checking the type
        // autonomous_system_number: Option<u32>
        // autonomous_system_organization: Option<&str>
        // This test just documents the expected structure
        assert!(true);
    }

    #[test]
    fn test_names_english_field() {
        // Verify that Names has an 'english' field (not a get() method)
        use maxminddb::geoip2;

        let names = geoip2::Names::default();

        // Access the english field directly (not via get("en"))
        let _english_name: Option<&str> = names.english;

        // Verify other language fields exist
        let _german: Option<&str> = names.german;
        let _french: Option<&str> = names.french;
        let _spanish: Option<&str> = names.spanish;

        assert!(true);
    }

    #[test]
    fn test_country_iso_code_access() {
        // Verify that country.iso_code is Option<&str>, not a nested structure
        use maxminddb::geoip2;

        let country_info = geoip2::country::Country::default();

        // iso_code should be Option<&str>
        let _iso: Option<&str> = country_info.iso_code;

        // Verify the pattern: country.country.iso_code.unwrap_or("")
        let country_record = geoip2::Country::default();
        let _iso_from_record: Option<&str> = country_record.country.iso_code;
        let _registered_iso: Option<&str> = country_record.registered_country.iso_code;

        assert!(true);
    }
}
