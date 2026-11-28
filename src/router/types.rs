//! Data types of router audit and CVE results.
//!
//! They are always compiled. The adapters that fill them (`audit`, `cve`) are cargo features, but
//! the support report, the advisor and the web state read these types in every build.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct PortCheck {
    pub port: u16,
    pub service: String,
    pub open: bool,
    /// "high" | "warn" | "info" | "none"
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct AdapterExtra {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RouterAudit {
    pub probed_at: DateTime<Utc>,
    pub gateway_ip: Option<String>,
    pub gateway_mac: Option<String>,
    pub adapter_used: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub admin_url: Option<String>,
    pub uptime_s: Option<u64>,
    pub ports: Vec<PortCheck>,
    pub details: Vec<AdapterExtra>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct CveItem {
    pub id: String,
    pub severity: String,
    pub cvss: Option<f64>,
    pub kev: bool,
    pub summary: String,
    pub published: Option<String>,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct CveLookupResponse {
    pub queried_at: DateTime<Utc>,
    pub cached: bool,
    pub source: String,
    pub query: String,
    pub total: usize,
    pub kev_count: usize,
    pub items: Vec<CveItem>,
    pub note: Option<String>,
}
