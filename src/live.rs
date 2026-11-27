//! In-memory live state shared between the monitor (producer) and the web UI (reader).
//! The run loop owns updates; readers use `read()` to look at the parts they need without
//! copying the whole state (`snapshot()` clones everything, including 72 h of minute buckets).

use crate::model::*;
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

/// Per-minute aggregate of one interface (kept for the last `MINUTES_KEPT` minutes).
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct MinuteBucket {
    /// Minute start, UTC.
    pub t: chrono::DateTime<chrono::Utc>,
    pub ticks: u32,
    pub gw_fail: u32,
    pub isp_fail: u32,
    pub net_fail: u32,
    pub gw_rtt_avg: Option<f64>,
    pub gw_rtt_max: Option<f64>,
    pub net_rtt_avg: Option<f64>,
    pub net_rtt_max: Option<f64>,
    /// Worst state seen in this minute.
    pub worst: Option<PathState>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub signal_dbm: Option<i32>,
    pub busy_pct: Option<f64>,
}

/// One LAN device count point for the timeline (counts only).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct LanPoint {
    pub t: chrono::DateTime<chrono::Utc>,
    pub arp_alive: u32,
    pub ping_alive: u32,
    pub unique_seen: u32,
}

pub const MINUTES_KEPT: usize = 72 * 60;
pub const LAN_HISTORY_KEPT: usize = MINUTES_KEPT;
pub const EVENTS_KEPT: usize = 2000;

#[derive(Debug, Clone, Serialize, Default)]
pub struct IfaceLive {
    pub name: String,
    pub role: Option<IfaceRole>,
    pub state: Option<PathState>,
    pub state_since: Option<chrono::DateTime<chrono::Utc>>,
    pub last: Option<Sample>,
    pub wifi: Option<WifiStation>,
    pub channel_load: Option<ChannelLoad>,
    pub minutes: VecDeque<MinuteBucket>,
    /// Totals since start.
    pub ticks: u64,
    pub gw_fail: u64,
    pub net_fail: u64,
    pub down_s: f64,
}

/// Borrowed view of an interface without the minute history, for cheap status responses.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct IfaceStatus<'a> {
    pub name: &'a str,
    pub role: Option<IfaceRole>,
    pub state: Option<PathState>,
    pub state_since: Option<chrono::DateTime<chrono::Utc>>,
    pub last: Option<&'a Sample>,
    pub wifi: Option<&'a WifiStation>,
    pub channel_load: Option<&'a ChannelLoad>,
    pub minutes_count: usize,
    pub ticks: u64,
    pub gw_fail: u64,
    pub net_fail: u64,
    pub down_s: f64,
}

impl IfaceLive {
    pub fn status(&self) -> IfaceStatus<'_> {
        IfaceStatus {
            name: &self.name,
            role: self.role,
            state: self.state,
            state_since: self.state_since,
            last: self.last.as_ref(),
            wifi: self.wifi.as_ref(),
            channel_load: self.channel_load.as_ref(),
            minutes_count: self.minutes.len(),
            ticks: self.ticks,
            gw_fail: self.gw_fail,
            net_fail: self.net_fail,
            down_s: self.down_s,
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct LiveSnapshot {
    pub session: Option<SessionMeta>,
    pub started: Option<chrono::DateTime<chrono::Utc>>,
    pub verdict: Option<Verdict>,
    pub verdict_since: Option<chrono::DateTime<chrono::Utc>>,
    pub ifaces: BTreeMap<String, IfaceLive>,
    pub last_scan: BTreeMap<String, ScanReport>,
    pub speed: VecDeque<(chrono::DateTime<chrono::Utc>, SpeedResult)>,
    pub events: VecDeque<Envelope>,
    pub dropped_records: u64,
    pub isp_hop: Option<std::net::Ipv4Addr>,
    pub host: Option<HostSample>,
    pub router: Option<RouterSample>,
    pub lan: Option<LanSample>,
    pub lan_history: VecDeque<LanPoint>,
}

#[derive(Clone)]
pub struct Live {
    inner: Arc<RwLock<LiveSnapshot>>,
    /// Every envelope written (events, samples, wifi, speed) is broadcast here.
    pub feed: broadcast::Sender<Arc<Envelope>>,
}

impl Default for Live {
    fn default() -> Self {
        Self::new()
    }
}

impl Live {
    pub fn new() -> Self {
        let (feed, _) = broadcast::channel(1024);
        Self { inner: Arc::new(RwLock::new(LiveSnapshot::default())), feed }
    }

    /// Full deep copy. Expensive (all minute buckets and events); prefer `read`.
    pub fn snapshot(&self) -> LiveSnapshot {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Run `f` under the read lock. Keep `f` short and never await inside it.
    pub fn read<R>(&self, f: impl FnOnce(&LiveSnapshot) -> R) -> R {
        let g = self.inner.read().unwrap_or_else(|e| e.into_inner());
        f(&g)
    }

    pub fn update<R>(&self, f: impl FnOnce(&mut LiveSnapshot) -> R) -> R {
        let mut g = self.inner.write().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }
}
