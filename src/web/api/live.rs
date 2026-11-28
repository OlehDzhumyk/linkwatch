//! Live tab: status, minute buckets, events, speed, scans and the live SSE feed, plus the
//! minute history that is read from session files.

use super::{ApiError, ApiResult, LimitQuery, MAX_SCAN_LINES, blocking, json_body, session_dir};
use crate::agg::severity;
use crate::live::{EVENTS_KEPT, IfaceStatus, LAN_HISTORY_KEPT, LanPoint, MINUTES_KEPT, MinuteBucket};
use crate::model::{Envelope, HostSample, LanSample, NetworkFingerprint, Record, RouterSample, ScanReport, SpeedResult, Stream, Verdict};
use crate::store::read;
use crate::web::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use futures::{Stream as FStream, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;

const MAX_HOURS: u32 = (MINUTES_KEPT / 60) as u32;

/// `GET /api/status`: live state without the large arrays (minute buckets, events, speed, scans).
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct StatusResponse<'a> {
    pub now: DateTime<Utc>,
    pub session: Option<StatusSession<'a>>,
    pub started: Option<DateTime<Utc>>,
    pub verdict: Option<Verdict>,
    pub verdict_since: Option<DateTime<Utc>>,
    pub ifaces: BTreeMap<&'a str, IfaceStatus<'a>>,
    pub dropped_records: u64,
    pub isp_hop: Option<std::net::Ipv4Addr>,
    pub events_count: usize,
    pub speed_count: usize,
    /// A site file is configured (`/api/site` answers).
    pub site: bool,
    pub host: Option<&'a HostSample>,
    pub router: Option<&'a RouterSample>,
    pub lan: Option<&'a LanSample>,
}

/// Session metadata of the running session, without its config.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct StatusSession<'a> {
    pub v: u32,
    pub session: &'a str,
    pub started: DateTime<Utc>,
    pub host: &'a str,
    pub version: &'a str,
    pub point: Option<&'a str>,
    pub label: Option<&'a str>,
    pub note: Option<&'a str>,
    pub host_id: Option<&'a str>,
    pub tz_offset_s: Option<i32>,
    pub clock_synced: Option<bool>,
    pub network: Option<&'a NetworkFingerprint>,
}

/// `GET /api/minutes`: minute buckets per interface and LAN sweep points, oldest first.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct MinutesResponse<'a> {
    pub hours: u32,
    pub ifaces: &'a BTreeMap<String, Vec<MinuteBucket>>,
    pub lan: &'a [LanPoint],
}

/// `GET /api/events`: newest first.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct EventsResponse<'a> {
    pub events: Vec<&'a Envelope>,
}

/// `GET /api/speed`: newest first.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SpeedResponse<'a> {
    pub speed: Vec<SpeedRow<'a>>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SpeedRow<'a> {
    pub t: DateTime<Utc>,
    pub result: &'a SpeedResult,
}

/// `GET /api/scan`: last scan per interface.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ScanResponse<'a> {
    pub scan: BTreeMap<&'a str, ScanEntry<'a>>,
}

/// One interface's last scan with the channel and network the interface uses now.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ScanEntry<'a> {
    pub report: &'a ScanReport,
    pub our_channel: Option<u32>,
    pub our_freq_mhz: Option<u32>,
    pub our_bssid: Option<&'a str>,
    pub our_ssid: Option<&'a str>,
}

/// Live state without the large arrays (minute buckets, events, speed, scans).
/// Serialised under the read lock from borrowed views: nothing large is copied.
pub(super) async fn status(State(st): State<AppState>) -> Response {
    let has_site = st.site.is_some();
    st.live.read(|snap| {
        json_body(&StatusResponse {
            now: Utc::now(),
            session: snap.session.as_ref().map(|m| StatusSession {
                v: m.v,
                session: &m.session,
                started: m.started,
                host: &m.host,
                version: &m.version,
                point: m.point.as_deref(),
                label: m.label.as_deref(),
                note: m.note.as_deref(),
                host_id: m.host_id.as_deref(),
                tz_offset_s: m.tz_offset_s,
                clock_synced: m.clock_synced,
                network: m.network.as_ref(),
            }),
            started: snap.started,
            verdict: snap.verdict,
            verdict_since: snap.verdict_since,
            ifaces: snap.ifaces.iter().map(|(name, i)| (name.as_str(), i.status())).collect(),
            dropped_records: snap.dropped_records,
            isp_hop: snap.isp_hop,
            events_count: snap.events.len(),
            speed_count: snap.speed.len(),
            site: has_site,
            host: snap.host.as_ref(),
            router: snap.router.as_ref(),
            lan: snap.lan.as_ref(),
        })
    })
}

#[derive(Deserialize)]
pub(super) struct MinutesQuery {
    iface: Option<String>,
    hours: Option<u32>,
    minutes: Option<u32>,
    /// Read from this session's files instead of live memory.
    session: Option<String>,
}

/// Minute buckets per interface + LAN device counts: `{"hours": h, "ifaces": {...}, "lan": [...]}`.
pub(super) async fn minutes(State(st): State<AppState>, Query(q): Query<MinutesQuery>) -> ApiResult {
    let hours = q.hours.unwrap_or(24).clamp(1, MAX_HOURS);
    let keep = q
        .minutes
        .map(|m| m.clamp(5, MAX_HOURS * 60) as usize)
        .unwrap_or(hours as usize * 60);
    let resp_hours = q
        .hours
        .unwrap_or_else(|| (keep as u32).div_ceil(60).max(1))
        .clamp(1, MAX_HOURS);
    let hist: CachedMinutes = match q.session {
        Some(id) => {
            let dir = session_dir(&st, &id)?;
            let iface = q.iface.clone();
            let cache = st.history.clone();
            blocking(&st, move || {
                // Re-reading JSONL is the expensive part; reuse the result while the files are unchanged.
                let key = format!("{}|{:?}|{keep}|{}", dir.display(), iface, files_stamp(&dir));
                if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
                    return hit;
                }
                let v = Arc::new(minutes_from_disk(&dir, iface.as_deref(), keep));
                cache.lock().unwrap_or_else(|e| e.into_inner()).put(key, v.clone());
                v
            })
            .await?
        }
        None => {
            let cutoff = Utc::now() - TimeDelta::minutes(keep as i64);
            Arc::new(st.live.read(|snap| MinutesHistory {
                ifaces: snap
                    .ifaces
                    .iter()
                    .filter(|(name, _)| q.iface.as_ref().is_none_or(|i| i == *name))
                    .map(|(name, i)| {
                        let skip = i.minutes.len().saturating_sub(keep);
                        (name.clone(), i.minutes.iter().skip(skip).cloned().collect())
                    })
                    .collect(),
                lan: snap.lan_history.iter().filter(|p| p.t >= cutoff).cloned().collect(),
            }))
        }
    };
    Ok(json_body(&MinutesResponse { hours: resp_hours, ifaces: &hist.ifaces, lan: &hist.lan }))
}

/// Newest events first, from memory.
pub(super) async fn events(State(st): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let limit = q.limit.unwrap_or(200).clamp(1, EVENTS_KEPT);
    st.live.read(|snap| {
        json_body(&EventsResponse { events: snap.events.iter().rev().take(limit).collect() })
    })
}

/// Speed test results, newest first.
pub(super) async fn speed(State(st): State<AppState>) -> Response {
    st.live.read(|snap| {
        json_body(&SpeedResponse {
            speed: snap.speed.iter().rev().map(|(t, result)| SpeedRow { t: *t, result }).collect(),
        })
    })
}

/// Last scan per interface, with the channel the interface uses now.
pub(super) async fn scan(State(st): State<AppState>) -> Response {
    st.live.read(|snap| {
        let scan = snap
            .last_scan
            .iter()
            .map(|(iface, report)| {
                let wifi = snap.ifaces.get(iface).and_then(|i| i.wifi.as_ref());
                let entry = ScanEntry {
                    report,
                    our_channel: wifi.and_then(|w| w.channel),
                    our_freq_mhz: wifi.and_then(|w| w.freq_mhz),
                    our_bssid: wifi.and_then(|w| w.bssid.as_deref()),
                    our_ssid: wifi.and_then(|w| w.ssid.as_deref()),
                };
                (iface.as_str(), entry)
            })
            .collect();
        json_body(&ScanResponse { scan })
    })
}

/// Server-sent events: every envelope from the live feed as JSON `data`.
/// A client that falls behind gets an `event: lagged` and continues with newer records.
pub(super) async fn live_sse(
    State(st): State<AppState>,
) -> Result<Sse<impl FStream<Item = Result<Event, Infallible>>>, ApiError> {
    let permit = st
        .sse
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "too many live clients".into()))?;
    let rx = st.live.feed.subscribe();
    let mut stop = st.stop.clone();
    let stream = BroadcastStream::new(rx)
        .filter_map(|r| async move {
            match r {
                Ok(env) => Event::default().json_data(&*env).ok().map(Ok),
                Err(_) => Some(Ok(Event::default().event("lagged").data("{}"))),
            }
        })
        .take_until(async move {
            let _ = stop.wait_for(|v| *v).await;
        })
        // The permit lives as long as the stream.
        .map(move |e| {
            let _ = &permit;
            e
        });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[derive(Default)]
struct Acc {
    b: MinuteBucket,
    gw: (f64, u32),
    net: (f64, u32),
}

fn minute_of(ts: DateTime<Utc>) -> DateTime<Utc> {
    ts.duration_trunc(TimeDelta::minutes(1)).unwrap_or(ts)
}

/// Pushes into a per-iface minute map, keeping at most `keep` newest minutes.
fn bucket<'a>(
    map: &'a mut BTreeMap<String, BTreeMap<DateTime<Utc>, Acc>>,
    iface: &str,
    t: DateTime<Utc>,
    keep: usize,
) -> Option<&'a mut Acc> {
    let m = map.entry(iface.to_string()).or_default();
    if m.len() >= keep && !m.contains_key(&t) {
        let first = *m.keys().next()?;
        if t < first {
            return None;
        }
        m.pop_first();
    }
    let acc = m.entry(t).or_default();
    acc.b.t = t;
    Some(acc)
}

/// Downsamples a session's samples (and Wi-Fi / LAN records) into minute buckets + LAN points.
pub(super) fn minutes_from_disk(
    dir: &Path,
    iface: Option<&str>,
    keep: usize,
) -> MinutesHistory {
    let mut map: BTreeMap<String, BTreeMap<DateTime<Utc>, Acc>> = BTreeMap::new();
    // Anchor `since` to the session's newest day (not wall-clock now) so querying older
    // recorded sessions still returns their minute buckets.
    let newest_day = crate::store::list_stream_files(dir)
        .ok()
        .and_then(|files| files.into_iter().map(|f| f.day).max())
        .or_else(|| read::last_heartbeat(dir).map(|t| t.date_naive()))
        .unwrap_or_else(|| Utc::now().date_naive());
    let span_days = (keep as i64 / 1440) + 2;
    let since = newest_day - TimeDelta::days(span_days);
    for env in read::iter_since(dir, Stream::Samples, since).take(MAX_SCAN_LINES) {
        let Record::Sample(s) = env.rec else { continue };
        if iface.is_some_and(|i| i != s.iface) {
            continue;
        }
        let Some(a) = bucket(&mut map, &s.iface, minute_of(env.ts), keep) else {
            continue;
        };
        a.b.ticks += 1;
        if s.gw.as_ref().is_some_and(|g| !g.ok) {
            a.b.gw_fail += 1;
        }
        if s.isp.as_ref().is_some_and(|g| !g.ok) {
            a.b.isp_fail += 1;
        }
        if s.net.of > 0 && s.net.ok == 0 {
            a.b.net_fail += 1;
        }
        if let Some(r) = s.gw.as_ref().and_then(|g| g.rtt_ms) {
            a.gw.0 += r;
            a.gw.1 += 1;
            a.b.gw_rtt_max = Some(a.b.gw_rtt_max.map_or(r, |m| m.max(r)));
        }
        if let Some(r) = s.net.rtt_ms {
            a.net.0 += r;
            a.net.1 += 1;
            a.b.net_rtt_max = Some(a.b.net_rtt_max.map_or(r, |m| m.max(r)));
        }
        if a.b.worst.is_none_or(|w| severity(s.state) > severity(w)) {
            a.b.worst = Some(s.state);
        }
        a.b.rx_bytes += s.rx_delta;
        a.b.tx_bytes += s.tx_delta;
    }
    for env in read::iter_since(dir, Stream::Wifi, since).take(MAX_SCAN_LINES) {
        let t = minute_of(env.ts);
        match env.rec {
            Record::Wifi(w) if iface.is_none_or(|i| i == w.iface) => {
                if let Some(sig) = w.signal_avg_dbm.or(w.signal_dbm)
                    && let Some(a) = map.get_mut(&w.iface).and_then(|m| m.get_mut(&t))
                {
                    a.b.signal_dbm = Some(a.b.signal_dbm.map_or(sig, |s| s.min(sig)));
                }
            }
            Record::ChannelLoad(c) if iface.is_none_or(|i| i == c.iface) => {
                if let Some(a) = map.get_mut(&c.iface).and_then(|m| m.get_mut(&t)) {
                    a.b.busy_pct = Some(a.b.busy_pct.map_or(c.busy_pct, |b| b.max(c.busy_pct)));
                }
            }
            _ => {}
        }
    }
    let mut lan: Vec<LanPoint> = Vec::new();
    for env in read::iter_since(dir, Stream::Host, since).take(MAX_SCAN_LINES) {
        if let Record::Lan(l) = env.rec {
            lan.push(LanPoint {
                t: env.ts,
                arp_alive: l.arp_alive,
                ping_alive: l.ping_alive,
                unique_seen: l.unique_seen,
            });
        }
    }
    let ifaces: BTreeMap<String, Vec<MinuteBucket>> = map
        .into_iter()
        .map(|(name, m)| {
            let v = m
                .into_values()
                .map(|mut a| {
                    a.b.gw_rtt_avg = (a.gw.1 > 0).then(|| a.gw.0 / f64::from(a.gw.1));
                    a.b.net_rtt_avg = (a.net.1 > 0).then(|| a.net.0 / f64::from(a.net.1));
                    a.b
                })
                .collect();
            (name, v)
        })
        .collect();
    let newest_ts = ifaces
        .values()
        .filter_map(|v| v.last().map(|b| b.t))
        .chain(lan.iter().map(|p| p.t))
        .max();
    if let Some(end_ts) = newest_ts {
        let cutoff = end_ts - TimeDelta::minutes(keep as i64);
        lan.retain(|p| p.t >= cutoff);
    }
    lan.sort_by_key(|p| p.t);
    if lan.len() > LAN_HISTORY_KEPT {
        let drop_n = lan.len() - LAN_HISTORY_KEPT;
        lan.drain(..drop_n);
    }
    MinutesHistory { ifaces, lan }
}

/// Small LRU of history results. Keys include a stamp of the session files (name, size,
/// mtime), so a growing live session is re-read and a finished one is served from memory.
#[derive(Default)]
pub(super) struct MinutesHistory {
    pub ifaces: BTreeMap<String, Vec<MinuteBucket>>,
    pub lan: Vec<LanPoint>,
}

type CachedMinutes = Arc<MinutesHistory>;

#[derive(Default)]
pub(crate) struct HistoryCache {
    entries: std::collections::VecDeque<(String, CachedMinutes)>,
}

const HISTORY_CACHE_ENTRIES: usize = 16;

impl HistoryCache {
    fn get(&mut self, key: &str) -> Option<CachedMinutes> {
        let i = self.entries.iter().position(|(k, _)| k == key)?;
        let e = self.entries.remove(i)?;
        let v = e.1.clone();
        self.entries.push_back(e);
        Some(v)
    }

    fn put(&mut self, key: String, v: CachedMinutes) {
        self.entries.retain(|(k, _)| *k != key);
        self.entries.push_back((key, v));
        while self.entries.len() > HISTORY_CACHE_ENTRIES {
            self.entries.pop_front();
        }
    }
}

/// Cheap identity of a session's sample and host files: changes whenever one is appended, rotated or compressed.
fn files_stamp(dir: &Path) -> String {
    let mut parts: Vec<String> = crate::store::list_stream_files(dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|f| matches!(f.stream, Stream::Samples | Stream::Host))
        .filter_map(|f| {
            let m = std::fs::metadata(&f.path).ok()?;
            let mtime = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis();
            Some(format!("{}:{}:{}", f.path.file_name()?.to_string_lossy(), m.len(), mtime))
        })
        .collect();
    parts.sort();
    parts.join(",")
}
