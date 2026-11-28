//! JSON API handlers. Live endpoints read [`crate::live::Live`]; history endpoints read
//! session files on a blocking thread with hard limits on lines and results.

use super::{AppState, Authed};
use crate::analyze::{Analyzer, Msg, Opts, Report};
use crate::live::{EVENTS_KEPT, IfaceStatus, LAN_HISTORY_KEPT, LanPoint, MINUTES_KEPT, MinuteBucket};
use crate::model::{
    Envelope, HostSample, IfaceRole, IncidentOrigin, LanSample, NetworkFingerprint, PathState,
    Record, RouterSample, ScanReport, SpeedResult, Stream, Verdict,
};
use crate::control::{SendError, SessionRequest};
use crate::site::{BuildingView, Site};
use crate::store::read;
use std::sync::Arc;
use axum::extract::{Path as UrlPath, Query, State};
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use futures::{Stream as FStream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use tokio_stream::wrappers::BroadcastStream;

/// Most lines read from one session stream for one request.
const MAX_SCAN_LINES: usize = 3_000_000;
/// Most sessions listed.
const MAX_SESSIONS: usize = 500;
const MAX_HOURS: u32 = (MINUTES_KEPT / 60) as u32;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/minutes", get(minutes))
        .route("/api/events", get(events))
        .route("/api/speed", get(speed))
        .route("/api/scan", get(scan))
        .route("/api/site", get(site))
        .route("/api/sessions", get(sessions))
        .route("/api/report", get(report))
        .route("/api/report/export", get(report_export))
        .route("/api/compare", get(compare_sessions))
        .route("/api/support-report", get(support_report))
        .route("/api/sessions/:id/summary", get(session_summary))
        .route("/api/sessions/:id/events", get(session_events))
        .route("/api/live", get(live_sse))
        .route("/api/plan", get(plan))
        .route("/api/control", get(control_get))
        .route(
            "/api/control/session",
            post(control_session).layer(DefaultBodyLimit::max(CONTROL_BODY_LIMIT)),
        )
        .route("/api/router/audit", get(router_audit_get))
        .route(
            "/api/router/probe",
            post(router_probe_post).layer(DefaultBodyLimit::max(CONTROL_BODY_LIMIT)),
        )
        .route(
            "/api/router/cve",
            post(router_cve_post).layer(DefaultBodyLimit::max(CONTROL_BODY_LIMIT)),
        )
        .route("/api/advice", get(advice_get))
}

// ---------- response bodies ----------
//
// Every JSON body the UI reads is a named type here. `cargo test` writes their TypeScript
// declarations to src/web/ui/src/api/ (ts-rs); the UI imports them from there. Fields that
// are `Option` without `skip_serializing_if` are always present (`null` when unknown).

/// Body of every error response.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ErrorResponse {
    pub error: String,
}

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

/// `GET /api/sessions/:id/events`: newest first.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SessionEventsResponse {
    pub events: Vec<Envelope>,
    /// Lines that could not be parsed.
    pub skipped_lines: u64,
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

/// `GET /api/site`: resolved site geometry and the point of the running session.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SiteResponse<'a> {
    pub buildings: Vec<BuildingView<'a>>,
    pub current_point: Option<String>,
}

/// `GET /api/sessions`: newest first. Sessions shorter than a minute are left out
/// (except the running one).
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SessionsResponse {
    pub sessions: Vec<SessionEntry>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SessionEntry {
    /// Directory name of the session.
    pub id: String,
    /// This is the running session.
    pub current: bool,
    pub started: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub host: String,
    pub version: String,
    pub point: Option<String>,
    pub label: Option<String>,
    pub note: Option<String>,
    /// Last heartbeat minus start (up to now for the running session).
    pub duration_s: Option<f64>,
    /// From summary.json.
    pub availability_pct: Option<f64>,
    pub verdict: Option<String>,
    pub drops_per_h: Option<f64>,
    /// summary.json as written at the end of the session (free-form).
    pub summary: Option<Value>,
}

/// Error response with a JSON body `{"error": "..."}`.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorResponse { error: self.1 })).into_response()
    }
}

type ApiResult = Result<Response, ApiError>;

/// JSON response from a body that may borrow the live state: serialise while the borrow lasts.
fn json_body<T: Serialize>(v: &T) -> Response {
    match serde_json::to_vec(v) {
        Ok(body) => ([(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))], body).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Runs blocking file reads off the async threads, at most `MAX_DISK_READS` at a time.
async fn blocking<T: Send + 'static>(
    st: &AppState,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    let _permit = tokio::time::timeout(std::time::Duration::from_secs(10), st.disk.clone().acquire_owned())
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy: too many history requests".into()))?
        .map_err(internal)?;
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

/// Live state without the large arrays (minute buckets, events, speed, scans).
/// Serialised under the read lock from borrowed views: nothing large is copied.
async fn status(State(st): State<AppState>) -> Response {
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
struct MinutesQuery {
    iface: Option<String>,
    hours: Option<u32>,
    minutes: Option<u32>,
    /// Read from this session's files instead of live memory.
    session: Option<String>,
}

/// Minute buckets per interface + LAN device counts: `{"hours": h, "ifaces": {...}, "lan": [...]}`.
async fn minutes(State(st): State<AppState>, Query(q): Query<MinutesQuery>) -> ApiResult {
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

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

/// Newest events first, from memory.
async fn events(State(st): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let limit = q.limit.unwrap_or(200).clamp(1, EVENTS_KEPT);
    st.live.read(|snap| {
        json_body(&EventsResponse { events: snap.events.iter().rev().take(limit).collect() })
    })
}

/// Speed test results, newest first.
async fn speed(State(st): State<AppState>) -> Response {
    st.live.read(|snap| {
        json_body(&SpeedResponse {
            speed: snap.speed.iter().rev().map(|(t, result)| SpeedRow { t: *t, result }).collect(),
        })
    })
}

/// Last scan per interface, with the channel the interface uses now.
async fn scan(State(st): State<AppState>) -> Response {
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

async fn site(State(st): State<AppState>) -> ApiResult {
    let site = st
        .site
        .as_ref()
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no site file configured".into()))?;
    let current_point = st.live.read(|s| s.session.as_ref().and_then(|m| m.point.clone()));
    Ok(json_body(&SiteResponse { buildings: site.view(), current_point }))
}

/// Sessions (newest first) with meta, duration and summary; tiny ones left out.
async fn sessions(State(st): State<AppState>) -> ApiResult {
    let data_dir = st.data_dir.clone();
    let cache = st.index.clone();
    let current = st.live.read(|s| s.session.as_ref().map(|m| m.session.clone()));
    let list = blocking(&st, move || {
        let now = Utc::now();
        let cur = current.as_deref();
        index_sessions(&data_dir, &cache)
            .iter()
            .rev()
            .filter(|s| !s.tiny(cur, now))
            .take(MAX_SESSIONS)
            .map(|s| {
                let duration_s = s.duration_s(cur, now);
                SessionEntry {
                    id: s.id.clone(),
                    current: cur == Some(s.id.as_str()),
                    started: s.started,
                    last_seen: s.last_seen,
                    host: s.host.clone(),
                    version: s.version.clone(),
                    point: s.point.clone(),
                    label: s.label.clone(),
                    note: s.note.clone(),
                    duration_s,
                    availability_pct: s.availability_pct(),
                    verdict: s.verdict(),
                    drops_per_h: s
                        .drops()
                        .zip(s.recorded_s())
                        .filter(|(_, d)| *d > 0.0)
                        .map(|(n, d)| n as f64 / (d / 3600.0)),
                    summary: s.summary.clone(),
                }
            })
            .collect()
    })
    .await?;
    Ok(json_body(&SessionsResponse { sessions: list }))
}

/// Session directory for an id from the URL. Only plain names of existing sessions.
fn session_dir(st: &AppState, id: &str) -> Result<PathBuf, ApiError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid session id".into(),
        ));
    }
    let dir = st.data_dir.join(id);
    if !dir.join("meta.json").is_file() {
        return Err(ApiError(StatusCode::NOT_FOUND, format!("no session {id}")));
    }
    Ok(dir)
}

async fn session_summary(State(st): State<AppState>, UrlPath(id): UrlPath<String>) -> ApiResult {
    let dir = session_dir(&st, &id)?;
    let s = blocking(&st, move || read::summary(&dir)).await?;
    s.map(|v| Json(v).into_response()).ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            format!("session {id} has no summary yet"),
        )
    })
}

/// Last `limit` events of a session, newest first (heartbeats excluded).
async fn session_events(
    State(st): State<AppState>,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<LimitQuery>,
) -> ApiResult {
    let dir = session_dir(&st, &id)?;
    let limit = q.limit.unwrap_or(200).clamp(1, EVENTS_KEPT);
    let (events, skipped) = blocking(&st, move || {
        let mut ring: VecDeque<Envelope> = VecDeque::with_capacity(limit);
        let mut it = read::iter(&dir, Stream::Events);
        for env in it.by_ref().take(MAX_SCAN_LINES) {
            if matches!(env.rec, Record::Event(_)) {
                if ring.len() == limit {
                    ring.pop_front();
                }
                ring.push_back(env);
            }
        }
        (ring.into_iter().rev().collect::<Vec<_>>(), it.skipped())
    })
    .await?;
    Ok(json_body(&SessionEventsResponse { events, skipped_lines: skipped }))
}

/// Server-sent events: every envelope from the live feed as JSON `data`.
/// A client that falls behind gets an `event: lagged` and continues with newer records.
async fn live_sse(
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

use crate::agg::severity;

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

// ---------- session index (shared by /api/sessions, /api/plan, /api/control) ----------

/// Sessions shorter than this are hidden in lists and do not count in the plan
/// (a quick restart or a wrong choice that was corrected at once).
pub(crate) const MIN_SESSION_S: f64 = 60.0;
/// Most session directories scanned for one index.
const MAX_INDEX_DIRS: usize = 2000;

/// What the API needs of one session directory (meta without its config, heartbeat, summary).
#[derive(Debug, Clone)]
pub(crate) struct IndexedSession {
    pub id: String,
    pub started: DateTime<Utc>,
    pub host: String,
    pub version: String,
    pub point: Option<String>,
    pub label: Option<String>,
    pub note: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub summary: Option<Value>,
}

impl IndexedSession {
    /// Last heartbeat minus start; None without a heartbeat.
    pub fn recorded_s(&self) -> Option<f64> {
        self.last_seen.map(|t| ((t - self.started).num_milliseconds() as f64 / 1000.0).max(0.0))
    }

    /// Duration for lists and the plan: up to now for the running session.
    fn duration_s(&self, current: Option<&str>, now: DateTime<Utc>) -> Option<f64> {
        if current == Some(self.id.as_str()) {
            Some(((now - self.started).num_milliseconds() as f64 / 1000.0).max(0.0))
        } else {
            self.recorded_s()
        }
    }

    /// Too short to list or count (never true for the running session).
    fn tiny(&self, current: Option<&str>, now: DateTime<Utc>) -> bool {
        current != Some(self.id.as_str()) && self.duration_s(current, now).is_none_or(|d| d < MIN_SESSION_S)
    }

    fn availability_pct(&self) -> Option<f64> {
        self.summary.as_ref()?.get("availability_pct")?.as_f64().filter(|v| v.is_finite())
    }

    /// Drops in the summary: state changes of the worst interface, two per drop (down and up).
    fn drops(&self) -> Option<u64> {
        let t = self.summary.as_ref()?.get("transitions")?.as_object()?;
        let worst = t.values().filter_map(Value::as_u64).max().unwrap_or(0);
        Some(worst.div_ceil(2))
    }

    fn verdict(&self) -> Option<String> {
        self.summary.as_ref()?.get("verdict")?.as_str().map(str::to_string)
    }
}

/// Cached [`IndexedSession`]s by directory name with a stamp of their small files.
#[derive(Default)]
pub(crate) struct SessionIndex {
    entries: HashMap<String, (String, Arc<IndexedSession>)>,
}

fn file_stamp(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(m) => {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            format!("{}:{mtime}", m.len())
        }
        Err(_) => "-".into(),
    }
}

/// All sessions of `data_dir` (at most `MAX_INDEX_DIRS`, the newest by name), oldest first.
/// Only directories whose meta, heartbeat or summary changed are read again.
pub(crate) fn index_sessions(data_dir: &Path, cache: &std::sync::Mutex<SessionIndex>) -> Vec<Arc<IndexedSession>> {
    let Ok(rd) = std::fs::read_dir(data_dir) else { return Vec::new() };
    let mut names: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    names.sort_unstable_by(|a, b| b.cmp(a));
    names.truncate(MAX_INDEX_DIRS);
    let mut idx = cache.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = Vec::with_capacity(names.len());
    let mut seen = std::collections::HashSet::new();
    for name in names {
        let dir = data_dir.join(&name);
        let stamp = [crate::store::META_FILE, crate::store::HEARTBEAT_FILE, crate::store::SUMMARY_FILE]
            .iter()
            .map(|f| file_stamp(&dir.join(f)))
            .collect::<Vec<_>>()
            .join("|");
        seen.insert(name.clone());
        if let Some((s, e)) = idx.entries.get(&name)
            && *s == stamp
        {
            out.push(e.clone());
            continue;
        }
        let Some(meta) = read::read_json_file::<crate::model::SessionMeta>(&dir.join(crate::store::META_FILE)) else {
            idx.entries.remove(&name);
            continue;
        };
        let e = Arc::new(IndexedSession {
            id: name.clone(),
            started: meta.started,
            host: meta.host,
            version: meta.version,
            point: meta.point,
            label: meta.label,
            note: meta.note,
            last_seen: read::last_heartbeat(&dir),
            summary: read::summary(&dir),
        });
        idx.entries.insert(name, (stamp, e.clone()));
        out.push(e);
    }
    idx.entries.retain(|k, _| seen.contains(k));
    out.sort_by(|a, b| a.started.cmp(&b.started).then_with(|| a.id.cmp(&b.id)));
    out
}

// ---------- measurement plan ----------

/// Progress of one plan item.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub(crate) enum PlanStatus {
    /// Not measured yet.
    Todo,
    /// The running session is at this point.
    Active,
    /// Measured, but less than planned (or not planned at all).
    Partial,
    /// Measured at least as long as planned.
    Done,
}

/// One point of the plan, or a point that was measured without being planned.
#[derive(Serialize, Debug, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct PlanItem {
    pub point: String,
    /// In `[[plan]]` of the site file.
    pub planned: bool,
    /// Room or point name (the id when the site does not know the point).
    pub name: String,
    pub building: Option<String>,
    pub building_name: Option<String>,
    pub unit: Option<String>,
    pub unit_label: Option<String>,
    pub floor: Option<i32>,
    /// Note of the plan entry.
    pub note: Option<String>,
    /// Planned seconds (None when not planned).
    pub target_s: Option<f64>,
    /// Sum of the durations of the sessions at this point (sessions under a minute excluded).
    pub measured_s: f64,
    pub sessions: u32,
    pub status: PlanStatus,
    /// Duration-weighted availability from the session summaries.
    pub availability_pct: Option<f64>,
    /// Drops per hour from the session summaries.
    pub drops_per_h: Option<f64>,
    /// Newest session at this point.
    pub last_session: Option<String>,
}

/// `GET /api/plan`: plan items in file order, then measured points that are not planned.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct PlanResponse {
    /// A site file is configured.
    pub site: bool,
    pub current_point: Option<String>,
    pub min_session_s: f64,
    pub items: Vec<PlanItem>,
}

#[derive(Default)]
struct PointAcc {
    measured_s: f64,
    sessions: u32,
    avail: (f64, f64),
    drops: (u64, f64),
    last: Option<String>,
}

/// Plan progress from the session index. `current` is the running session (id, point).
pub(crate) fn build_plan(
    site: Option<&Site>,
    sessions: &[Arc<IndexedSession>],
    current: Option<(&str, Option<&str>)>,
    now: DateTime<Utc>,
) -> Vec<PlanItem> {
    let cur_id = current.map(|c| c.0);
    let cur_point = current.and_then(|c| c.1);
    let mut acc: BTreeMap<&str, PointAcc> = BTreeMap::new();
    for s in sessions {
        let Some(p) = s.point.as_deref() else { continue };
        if s.tiny(cur_id, now) {
            continue;
        }
        let d = s.duration_s(cur_id, now).unwrap_or(0.0);
        let a = acc.entry(p).or_default();
        a.measured_s += d;
        a.sessions += 1;
        if let Some(v) = s.availability_pct() {
            a.avail.0 += v * d;
            a.avail.1 += d;
        }
        if let Some(n) = s.drops() {
            a.drops.0 += n;
            a.drops.1 += d;
        }
        a.last = Some(s.id.clone());
    }
    let item = |point: &str, planned: Option<&crate::site::PlanEntry>| -> PlanItem {
        let a = acc.get(point);
        let rp = site.and_then(|s| s.point(point));
        let measured_s = a.map_or(0.0, |a| a.measured_s);
        let target_s = planned.map(|e| e.hours * 3600.0);
        let status = if cur_point == Some(point) {
            PlanStatus::Active
        } else if target_s.is_some_and(|t| measured_s >= t) {
            PlanStatus::Done
        } else if measured_s > 0.0 {
            PlanStatus::Partial
        } else {
            PlanStatus::Todo
        };
        PlanItem {
            point: point.to_string(),
            planned: planned.is_some(),
            name: rp.as_ref().map_or_else(|| point.to_string(), |p| p.name.clone()),
            building_name: rp.as_ref().and_then(|p| site?.building_name(&p.building)).map(str::to_string),
            unit_label: rp.as_ref().and_then(|p| site?.unit_label(&p.building, &p.unit)).map(str::to_string),
            building: rp.as_ref().map(|p| p.building.clone()),
            unit: rp.as_ref().map(|p| p.unit.clone()),
            floor: rp.as_ref().map(|p| p.floor),
            note: planned.and_then(|e| e.note.clone()),
            target_s,
            measured_s,
            sessions: a.map_or(0, |a| a.sessions),
            status,
            availability_pct: a.filter(|a| a.avail.1 > 0.0).map(|a| a.avail.0 / a.avail.1),
            drops_per_h: a.filter(|a| a.drops.1 > 0.0).map(|a| a.drops.0 as f64 / (a.drops.1 / 3600.0)),
            last_session: a.and_then(|a| a.last.clone()),
        }
    };
    let plan = site.map(Site::plan).unwrap_or_default();
    let mut items: Vec<PlanItem> = plan.iter().map(|e| item(&e.point, Some(e))).collect();
    let mut extra: Vec<&str> = acc.keys().copied().filter(|p| !plan.iter().any(|e| e.point == *p)).collect();
    if let Some(c) = cur_point
        && !acc.contains_key(c)
        && !plan.iter().any(|e| e.point == c)
    {
        extra.push(c);
    }
    extra.sort_unstable();
    items.extend(extra.into_iter().map(|p| item(p, None)));
    items
}

/// The running session: (id, point, started).
fn current_session(st: &AppState) -> Option<(String, Option<String>, DateTime<Utc>)> {
    st.live.read(|s| s.session.as_ref().map(|m| (m.session.clone(), m.point.clone(), m.started)))
}

async fn plan(State(st): State<AppState>) -> ApiResult {
    let data_dir = st.data_dir.clone();
    let cache = st.index.clone();
    let site = st.site.clone();
    let cur = current_session(&st);
    let current_point = cur.as_ref().and_then(|c| c.1.clone());
    let items = blocking(&st, move || {
        let all = index_sessions(&data_dir, &cache);
        build_plan(site.as_deref(), &all, cur.as_ref().map(|c| (c.0.as_str(), c.1.as_deref())), Utc::now())
    })
    .await?;
    Ok(json_body(&PlanResponse { site: st.site.is_some(), current_point, min_session_s: MIN_SESSION_S, items }))
}

// ---------- measurement control ----------

/// Shortest time between two accepted session switches.
pub(crate) const SWITCH_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// Largest accepted request body of `POST /api/control/session`.
pub(crate) const CONTROL_BODY_LIMIT: usize = 4096;
/// How long a switch may take (tasks stop, summary, new session opens).
const SWITCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const NO_TOKEN: &str = "set [web] token to enable control";
/// Most suggestions of earlier points.
const MAX_KNOWN_POINTS: usize = 50;

/// `GET /api/control`: whether this client may switch sessions, and the current choice.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ControlResponse {
    pub enabled: bool,
    /// Why control is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(test, ts(optional))]
    pub reason: Option<String>,
    pub point: Option<String>,
    pub label: Option<String>,
    pub note: Option<String>,
    pub session: Option<String>,
    pub started: Option<DateTime<Utc>>,
    /// A site file is configured: the point must be one of its points. Otherwise the point
    /// is free text (1..=64 of `[A-Za-z0-9 _./-]`).
    pub site: bool,
    /// Points of earlier sessions (and the running one), newest first, for suggestions.
    pub known_points: Vec<String>,
    pub min_interval_s: u32,
}

/// `POST /api/control/session` answer: id of the new session.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ControlSessionResponse {
    pub session: String,
}

/// Reason why control is off, or None when on. The token middleware has already
/// authenticated every request that reaches a handler when a token is configured.
fn control_off(st: &AppState, authed: bool) -> Option<&'static str> {
    if st.token.is_none() {
        Some(NO_TOKEN)
    } else if !authed {
        Some(READ_ONLY)
    } else if st.control.is_none() {
        Some("measurement control is not available in this process")
    } else {
        None
    }
}

/// Reason shown to viewers of an open (`view = "open"`) UI without the token.
const READ_ONLY: &str = "read-only view: open the UI once with ?token=<token> to control measurements";

async fn control_get(State(st): State<AppState>, Extension(Authed(authed)): Extension<Authed>) -> ApiResult {
    let data_dir = st.data_dir.clone();
    let cache = st.index.clone();
    let cur = st.live.read(|s| s.session.as_ref().map(|m| (m.session.clone(), m.point.clone(), m.label.clone(), m.note.clone(), m.started)));
    let cur_point = cur.as_ref().and_then(|c| c.1.clone());
    let known_points = blocking(&st, move || {
        let mut out: Vec<String> = Vec::new();
        if let Some(p) = cur_point {
            out.push(p);
        }
        for s in index_sessions(&data_dir, &cache).iter().rev() {
            if let Some(p) = &s.point
                && !out.contains(p)
            {
                out.push(p.clone());
                if out.len() >= MAX_KNOWN_POINTS {
                    break;
                }
            }
        }
        out
    })
    .await?;
    let off = control_off(&st, authed);
    let (session, point, label, note, started) = match cur {
        Some((id, p, l, n, t)) => (Some(id), p, l, n, Some(t)),
        None => (None, None, None, None, None),
    };
    Ok(json_body(&ControlResponse {
        enabled: off.is_none(),
        reason: off.map(str::to_string),
        point,
        label,
        note,
        session,
        started,
        site: st.site.is_some(),
        known_points,
        min_interval_s: SWITCH_MIN_INTERVAL.as_secs() as u32,
    }))
}

/// Host part of an `Origin` value (`scheme://host[:port]`), or None when it is not one.
fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://"))?;
    (!rest.is_empty() && !rest.contains('/')).then_some(rest)
}

/// CSRF defence: an `Origin` header, when present, must name this host; a browser that says
/// the request is cross-site is refused too.
fn same_origin(headers: &HeaderMap) -> bool {
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return false;
    }
    let Some(origin) = headers.get(header::ORIGIN) else { return true };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    match (origin.to_str().ok().and_then(origin_host), host) {
        (Some(o), Some(h)) => o.eq_ignore_ascii_case(h),
        _ => false,
    }
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}

/// Shortest time between two active router probes or CVE lookups.
const PROBE_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

fn rate_limited(
    slot: &std::sync::Mutex<Option<std::time::Instant>>,
    min_interval: std::time::Duration,
    action: &str,
) -> Option<Response> {
    let mut last = slot.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = *last {
        let since = t.elapsed();
        if since < min_interval {
            let wait = (min_interval - since).as_secs() + 1;
            let mut r = ApiError(StatusCode::TOO_MANY_REQUESTS, format!("wait {wait} s before the next {action}")).into_response();
            if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return Some(r);
        }
    }
    *last = Some(std::time::Instant::now());
    None
}

fn require_post_auth(st: &AppState, headers: &HeaderMap, no_token_msg: &str) -> Result<(), ApiError> {
    if st.token.is_none() {
        return Err(ApiError(StatusCode::FORBIDDEN, no_token_msg.into()));
    }
    if !same_origin(headers) {
        return Err(ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into()));
    }
    if !is_json(headers) {
        return Err(ApiError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json".into()));
    }
    Ok(())
}

/// Starts a new session with `{point?, label?, note?}`. Needs a configured token (and so an
/// authenticated request), JSON, the same origin, and at most one switch per 10 s.
async fn control_session(State(st): State<AppState>, headers: HeaderMap, body: axum::body::Bytes) -> ApiResult {
    if let Some(r) = control_off(&st, true) {
        return Err(ApiError(StatusCode::FORBIDDEN, r.into()));
    }
    let Some(ctl) = st.control.clone() else {
        return Err(ApiError(StatusCode::FORBIDDEN, NO_TOKEN.into()));
    };
    require_post_auth(&st, &headers, NO_TOKEN)?;
    let req: SessionRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    let req = req.validated(st.site.as_deref()).map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    if let Some(r) = rate_limited(&st.last_switch, SWITCH_MIN_INTERVAL, "switch") {
        return Ok(r);
    }
    match tokio::time::timeout(SWITCH_TIMEOUT, ctl.start_session(req)).await {
        Ok(Ok(session)) => Ok(json_body(&ControlSessionResponse { session })),
        Ok(Err(SendError::Busy)) => Err(ApiError(StatusCode::CONFLICT, "another switch is in progress".into())),
        Ok(Err(SendError::Closed)) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "the monitor is stopping".into())),
        Ok(Err(SendError::Failed(e))) => Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, e)),
        Err(_) => Err(ApiError(StatusCode::GATEWAY_TIMEOUT, "the switch takes too long; reload the page later".into())),
    }
}

// ---------- structured session report (/api/report) ----------

#[derive(Deserialize)]
struct ReportQuery {
    session: Option<String>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ReportHour {
    pub hour: u32,
    pub ticks: u64,
    pub loss_pct: f64,
    pub gw_rtt_med: Option<f64>,
    pub net_rtt_med: Option<f64>,
    pub net_rtt_p95: Option<f64>,
    pub episodes: u32,
    pub micro_drops: u32,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ReportIface {
    pub iface: String,
    pub role: Option<IfaceRole>,
    pub ticks: u64,
    pub availability_pct: f64,
    pub episodes: u32,
    pub micro_drops: u32,
    pub down_s: f64,
    pub longest_s: f64,
    pub gw_rtt_med: Option<f64>,
    pub net_rtt_med: Option<f64>,
    pub loaded_gw_rtt_med: Option<f64>,
    pub loaded_net_rtt_med: Option<f64>,
    pub peak_net_rtt_p95: Option<f64>,
    pub signal_med: Option<f64>,
    pub busy_med: Option<f64>,
    pub retry_rate_per_min: Option<f64>,
    pub stalls: u32,
    pub roams: u32,
    pub speed_med_mbps: Option<f64>,
    pub hours: Vec<ReportHour>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ReportEpisode {
    pub iface: String,
    pub role: IfaceRole,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_s: f64,
    pub state: PathState,
    pub cause: Option<Verdict>,
    pub origin: IncidentOrigin,
    pub band: Option<String>,
    pub speedtest_active: bool,
    /// Context lines (translatable; `text` is English).
    pub context: Vec<Msg>,
    /// The detective's graded attribution with its evidence.
    pub finding: crate::analyze::attribution::Finding,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ReportRouter {
    pub samples: u64,
    pub model: Option<String>,
    pub uptime_resets: u32,
    pub wan_down_samples: u64,
    pub wan_rx_mbps_med: Option<f64>,
    pub wan_rx_mbps_p95: Option<f64>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ReportLan {
    pub samples: u64,
    pub arp_alive_med: Option<f64>,
    pub arp_alive_max: Option<u32>,
    pub unique_seen_max: Option<u32>,
}

/// `GET /api/report`: structured analyzer summary + grouped incidents for the running or saved session.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ReportResponse {
    pub session: String,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub hours: f64,
    pub verdict: Option<Verdict>,
    /// English sentence; `verdict_code` + `verdict_args` let the UI translate it
    /// (`report.vc.<code>`).
    pub verdict_summary: String,
    pub verdict_code: String,
    pub verdict_args: BTreeMap<String, String>,
    pub network_incidents: u32,
    pub load_incidents: u32,
    pub observer_incidents: u32,
    pub ifaces: Vec<ReportIface>,
    pub episodes: Vec<ReportEpisode>,
    /// Analyzer findings, patterns and observer notes as translatable messages.
    pub findings: Vec<Msg>,
    pub patterns: Vec<Msg>,
    pub observer_findings: Vec<Msg>,
    /// Observer Trust Score of the session (`clean | caution | polluted` + reasons).
    pub observer_trust: crate::analyze::ObserverTrust,
    pub router: Option<ReportRouter>,
    pub lan: Option<ReportLan>,
}

const REPORT_CACHE_ENTRIES: usize = 8;
const MAX_REPORT_EPISODES: usize = 100;

#[derive(Default)]
pub(crate) struct ReportCache {
    entries: std::collections::VecDeque<(String, Arc<ReportResponse>)>,
    /// Newest report per `<dir>|<verdict>` with its build time. The running session's files
    /// change every few seconds, so their stamp never repeats; this entry lets every viewer
    /// reuse one analysis for [`REPORT_FRESH`] instead of re-reading the whole session.
    fresh: HashMap<String, (std::time::Instant, Arc<ReportResponse>)>,
}

/// How long a report of a growing session is reused (5 min).
///
/// Why: the analyzer re-reads the whole session and keeps all events in memory (see
/// docs/ROADMAP.md, "Live report cost"). On a Raspberry Pi with `MemoryMax=256M` and a
/// week-long session, a rebuild every 30 s while a tab is open risks OOM and late probe ticks.
/// The cached report is served unchanged until it is this old; `ReportResponse` has no age
/// field, so the UI sees an older (at most 5 min) report of a running session. Only one rebuild
/// runs at a time (`report_build` lock) and it runs in `spawn_blocking`.
pub(crate) const REPORT_FRESH: std::time::Duration = std::time::Duration::from_secs(300);

impl ReportCache {
    pub(crate) fn get_fresh(&self, key: &str) -> Option<Arc<ReportResponse>> {
        self.fresh.get(key).filter(|(t, _)| t.elapsed() < REPORT_FRESH).map(|(_, r)| r.clone())
    }

    pub(crate) fn put_fresh(&mut self, key: String, v: Arc<ReportResponse>) {
        self.fresh.retain(|_, (t, _)| t.elapsed() < REPORT_FRESH);
        self.fresh.insert(key, (std::time::Instant::now(), v));
    }

    /// Test helper: make a fresh entry look `age` old.
    #[cfg(test)]
    pub(crate) fn age_fresh(&mut self, key: &str, age: std::time::Duration) {
        if let Some((t, _)) = self.fresh.get_mut(key) {
            *t = std::time::Instant::now().checked_sub(age).unwrap_or(*t);
        }
    }

    fn get(&mut self, key: &str) -> Option<Arc<ReportResponse>> {
        let i = self.entries.iter().position(|(k, _)| k == key)?;
        let e = self.entries.remove(i)?;
        let v = e.1.clone();
        self.entries.push_back(e);
        Some(v)
    }

    fn put(&mut self, key: String, v: Arc<ReportResponse>) {
        self.entries.retain(|(k, _)| *k != key);
        self.entries.push_back((key, v));
        while self.entries.len() > REPORT_CACHE_ENTRIES {
            self.entries.pop_front();
        }
    }
}

fn all_stream_files_stamp(dir: &Path) -> String {
    let mut parts: Vec<String> = crate::store::list_stream_files(dir)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| {
            let m = std::fs::metadata(&f.path).ok()?;
            let mtime = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis();
            Some(format!("{}:{}:{}", f.path.file_name()?.to_string_lossy(), m.len(), mtime))
        })
        .collect();
    parts.sort();
    parts.join(",")
}

fn dominant_cause(rep: &Report) -> Option<Verdict> {
    let mut counts: BTreeMap<usize, (Verdict, u32, f64)> = BTreeMap::new();
    let key_of = |v: Verdict| match v {
        Verdict::AllOk => 0,
        Verdict::WifiProblem => 1,
        Verdict::WiredProblem => 2,
        Verdict::RouterProblem => 3,
        Verdict::LineProblem => 4,
        Verdict::InternetProblem => 5,
        Verdict::Dns => 6,
        Verdict::SinglePath => 7,
        Verdict::Unknown => 8,
    };
    for ep in &rep.episodes {
        if ep.origin == IncidentOrigin::Observer || crate::analyze::is_load_provoked(ep) {
            continue;
        }
        let Some(c) = ep.cause else { continue };
        if matches!(c, Verdict::AllOk | Verdict::Unknown) {
            continue;
        }
        let e = counts.entry(key_of(c)).or_insert((c, 0, 0.0));
        e.1 += 1;
        e.2 += ep.duration_s;
    }
    counts
        .into_values()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.total_cmp(&b.2)))
        .map(|(c, _, _)| c)
}

/// Verdict explanation: stable code + placeholder values for the UI, and the English text.
struct VerdictText {
    code: &'static str,
    args: BTreeMap<String, String>,
    text: String,
}

fn explain_verdict(verdict: Option<Verdict>, net_inc: u32, obs_inc: u32, ifaces: &[ReportIface]) -> VerdictText {
    let wifi_sig = ifaces
        .iter()
        .find(|i| i.role == Some(IfaceRole::Wifi))
        .and_then(|i| i.signal_med);
    let one = |code, text: &str| VerdictText { code, args: BTreeMap::new(), text: text.into() };
    let with = |code, k: &str, v: String, text: String| VerdictText { code, args: BTreeMap::from([(k.to_string(), v)]), text };
    match verdict {
        Some(Verdict::AllOk) => {
            if obs_inc > 0 && net_inc == 0 {
                with("all_ok_observer", "n", obs_inc.to_string(), format!("Network stayed healthy ({obs_inc} observer-host incident(s) excluded)."))
            } else if net_inc > 0 {
                with("all_ok_earlier", "n", net_inc.to_string(), format!("Paths are healthy right now; {net_inc} earlier incident(s) recorded in this session."))
            } else {
                one("all_ok_clean", "All monitored paths are healthy with no drops recorded.")
            }
        }
        Some(Verdict::WifiProblem) => match wifi_sig {
            Some(s) if s < -75.0 => with("wifi_weak", "dbm", format!("{s:.0}"), format!("Ethernet stayed stable while Wi-Fi failed — weak Wi-Fi signal (median {s:.0} dBm).")),
            _ => one("wifi", "Ethernet stayed stable while Wi-Fi failed — issue is on the wireless hop."),
        },
        Some(Verdict::WiredProblem) => one("wired", "Wi-Fi stayed up while the wired path failed — check Ethernet cable or port."),
        Some(Verdict::RouterProblem) => one("router", "All monitored paths failed at the router — router rebooted, stalled, or LAN stopped responding."),
        Some(Verdict::LineProblem) => one("line", "All paths reached the router but failed at the ISP hop — issue is on the access line."),
        Some(Verdict::InternetProblem) => one("internet", "Local network and ISP hop answered, but external internet targets timed out."),
        Some(Verdict::Dns) => one("dns", "IP probes succeeded, but DNS name resolution failed."),
        Some(Verdict::SinglePath) => {
            if net_inc == 0 {
                one("single_clean", "Monitoring a single path cleanly (connect Ethernet alongside Wi-Fi to isolate Wi-Fi vs ISP faults).")
            } else {
                with("single_incidents", "n", net_inc.to_string(), format!("Single monitored path had {net_inc} incident(s); add a second path to separate Wi-Fi from the line."))
            }
        }
        Some(Verdict::Unknown) | None => one("waiting", "Waiting for enough samples to classify path health."),
    }
}

fn analyze_session_raw(dir: &Path) -> Report {
    let meta: Option<crate::model::SessionMeta> = read::read_json_file(&dir.join(crate::store::META_FILE));
    let mut analyzer = Analyzer::new(Opts::for_session(meta.as_ref()));
    for st in Stream::ALL {
        for env in read::iter(dir, st).take(MAX_SCAN_LINES) {
            analyzer.push(&env);
        }
    }
    analyzer.finish(&[])
}

fn analyze_session_dir(dir: &Path, id: String, live_verdict: Option<Verdict>) -> ReportResponse {
    let rep = analyze_session_raw(dir);
    let ifaces: Vec<ReportIface> = rep
        .ifaces
        .iter()
        .map(|i| ReportIface {
            iface: i.iface.clone(),
            role: i.role,
            ticks: i.ticks,
            availability_pct: i.availability_pct,
            episodes: i.episodes,
            micro_drops: i.micro_drops,
            down_s: i.down_s,
            longest_s: i.longest_s,
            gw_rtt_med: i.gw_rtt_med,
            net_rtt_med: i.net_rtt_med,
            loaded_gw_rtt_med: i.loaded_gw_rtt_med,
            loaded_net_rtt_med: i.loaded_net_rtt_med,
            peak_net_rtt_p95: i.peak_net_rtt_p95,
            signal_med: i.signal_med,
            busy_med: i.busy_med,
            retry_rate_per_min: i.retry_rate_per_min,
            stalls: i.stalls,
            roams: i.roams,
            speed_med_mbps: i.speed_med_mbps,
            hours: i
                .hours
                .iter()
                .map(|h| ReportHour {
                    hour: h.hour,
                    ticks: h.ticks,
                    loss_pct: h.loss_pct,
                    gw_rtt_med: h.gw_rtt_med,
                    net_rtt_med: h.net_rtt_med,
                    net_rtt_p95: h.net_rtt_p95,
                    episodes: h.episodes,
                    micro_drops: h.micro_drops,
                })
                .collect(),
        })
        .collect();
    let verdict = live_verdict
        .or_else(|| dominant_cause(&rep))
        .or(match rep.ifaces.len() {
            0 => None,
            1 => Some(Verdict::SinglePath),
            _ => Some(Verdict::AllOk),
        });
    let mut episodes: Vec<ReportEpisode> = rep
        .episodes
        .iter()
        .rev()
        .take(MAX_REPORT_EPISODES)
        .map(|ep| ReportEpisode {
            iface: ep.iface.clone(),
            role: ep.role,
            start: ep.start,
            end: ep.end,
            duration_s: ep.duration_s,
            state: ep.state,
            cause: ep.cause,
            origin: ep.origin,
            band: ep.band.clone(),
            speedtest_active: ep.speedtest_active,
            context: ep.context_msg.clone(),
            finding: ep.finding.clone(),
        })
        .collect();
    // Ensure strict newest-first order when multiple interfaces had interleaved episodes.
    episodes.sort_by_key(|a| std::cmp::Reverse(a.start));
    let vt = explain_verdict(verdict, rep.network_incidents, rep.observer_incidents, &ifaces);
    ReportResponse {
        session: id,
        from: rep.from,
        to: rep.to,
        hours: rep.hours,
        verdict,
        verdict_summary: vt.text,
        verdict_code: vt.code.into(),
        verdict_args: vt.args,
        network_incidents: rep.network_incidents,
        load_incidents: rep.load_incidents,
        observer_incidents: rep.observer_incidents,
        ifaces,
        episodes,
        findings: rep.findings_msg,
        patterns: rep.patterns_msg,
        observer_findings: rep.observer_findings_msg,
        observer_trust: rep.observer_trust,
        router: rep.router.map(|r| ReportRouter {
            samples: r.samples,
            model: r.model,
            uptime_resets: r.uptime_resets,
            wan_down_samples: r.wan_down_samples,
            wan_rx_mbps_med: r.wan_rx_mbps_med,
            wan_rx_mbps_p95: r.wan_rx_mbps_p95,
        }),
        lan: rep.lan.map(|l| ReportLan {
            samples: l.samples,
            arp_alive_med: l.arp_alive_med,
            arp_alive_max: l.arp_alive_max,
            unique_seen_max: l.unique_seen_max,
        }),
    }
}

fn resolve_report_target(st: &AppState, session: Option<String>) -> Result<(String, Option<PathBuf>), ApiError> {
    match session {
        Some(id) => Ok((id.clone(), Some(session_dir(st, &id)?))),
        None => {
            let cur_id = st.live.read(|s| s.session.as_ref().map(|m| m.session.clone()));
            Ok(match cur_id {
                Some(id) if st.data_dir.join(&id).join(crate::store::META_FILE).is_file() => {
                    (id.clone(), Some(st.data_dir.join(id)))
                }
                Some(id) => (id, None),
                None => (String::new(), None),
            })
        }
    }
}

async fn report(State(st): State<AppState>, Query(q): Query<ReportQuery>) -> ApiResult {
    let live_verdict = st.live.read(|s| s.verdict);
    let (id, dir) = resolve_report_target(&st, q.session)?;
    let Some(dir) = dir else {
        let vt = explain_verdict(live_verdict, 0, 0, &[]);
        return Ok(json_body(&ReportResponse {
            session: id,
            from: None,
            to: None,
            hours: 0.0,
            verdict: live_verdict,
            verdict_summary: vt.text,
            verdict_code: vt.code.into(),
            verdict_args: vt.args,
            network_incidents: 0,
            load_incidents: 0,
            observer_incidents: 0,
            ifaces: Vec::new(),
            episodes: Vec::new(),
            findings: Vec::new(),
            patterns: Vec::new(),
            observer_findings: Vec::new(),
            observer_trust: Default::default(),
            router: None,
            lan: None,
        }));
    };
    // No verdict in this key: a flapping live verdict must not defeat the rate limit.
    let fresh_key = dir.display().to_string();
    if let Some(hit) = st.reports.lock().unwrap_or_else(|e| e.into_inner()).get_fresh(&fresh_key) {
        return Ok(json_body(&*hit));
    }
    // One analysis at a time: viewers that arrive while it runs wait and then hit the cache.
    let _build = st.report_build.lock().await;
    if let Some(hit) = st.reports.lock().unwrap_or_else(|e| e.into_inner()).get_fresh(&fresh_key) {
        return Ok(json_body(&*hit));
    }
    let cache = st.reports.clone();
    let rep = blocking(&st, move || {
        let key = format!("{}|{}|{live_verdict:?}", dir.display(), all_stream_files_stamp(&dir));
        let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
        let built = match c.get(&key) {
            Some(hit) => hit,
            None => {
                drop(c);
                let built = Arc::new(analyze_session_dir(&dir, id, live_verdict));
                c = cache.lock().unwrap_or_else(|e| e.into_inner());
                c.put(key, built.clone());
                built
            }
        };
        c.put_fresh(fresh_key, built.clone());
        built
    })
    .await?;
    Ok(json_body(&*rep))
}

#[derive(Deserialize)]
struct ExportQuery {
    session: Option<String>,
    format: Option<String>,
}

fn attachment_response(content_type: &'static str, filename: &str, body: Vec<u8>) -> Response {
    let mut r = ([(header::CONTENT_TYPE, HeaderValue::from_static(content_type))], body).into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    r
}

fn safe_slug(raw: &str, fallback: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    let trimmed = s.trim_matches('_');
    if trimmed.is_empty() { fallback.into() } else { trimmed.into() }
}

async fn report_export(State(st): State<AppState>, Query(q): Query<ExportQuery>) -> ApiResult {
    let fmt = q.format.as_deref().unwrap_or("md");
    if !matches!(fmt, "md" | "json") {
        return Err(ApiError(StatusCode::BAD_REQUEST, "format must be md or json".into()));
    }
    let (id, dir) = resolve_report_target(&st, q.session)?;
    let Some(dir) = dir else {
        return Err(ApiError(StatusCode::NOT_FOUND, "session has no recorded data yet".into()));
    };
    let rep = blocking(&st, move || analyze_session_raw(&dir)).await?;
    let slug = safe_slug(&id, "session");
    if fmt == "json" {
        let bytes = serde_json::to_vec_pretty(&rep).map_err(internal)?;
        Ok(attachment_response("application/json", &format!("linkwatch-{slug}.json"), bytes))
    } else {
        let md = crate::analyze::to_markdown(&rep);
        Ok(attachment_response("text/markdown; charset=utf-8", &format!("linkwatch-{slug}.md"), md.into_bytes()))
    }
}

#[derive(Deserialize)]
struct CompareQuery {
    sessions: String,
    tolerance_s: Option<f64>,
    format: Option<String>,
}

async fn compare_sessions(State(st): State<AppState>, Query(q): Query<CompareQuery>) -> ApiResult {
    let fmt = q.format.as_deref().unwrap_or("json");
    if !matches!(fmt, "json" | "md") {
        return Err(ApiError(StatusCode::BAD_REQUEST, "format must be json or md".into()));
    }
    let tol = q.tolerance_s.unwrap_or(2.0);
    if !tol.is_finite() || !(0.0..=60.0).contains(&tol) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "tolerance_s must be 0..=60".into()));
    }
    let mut dirs = Vec::new();
    let mut seen = Vec::new();
    for part in q.sessions.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if seen.iter().any(|s| s == part) {
            return Err(ApiError(StatusCode::BAD_REQUEST, format!("duplicate session id {part}")));
        }
        dirs.push(session_dir(&st, part)?);
        seen.push(part.to_string());
    }
    if !(2..=8).contains(&dirs.len()) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "sessions must list 2..=8 session ids".into()));
    }
    let site = st.site.clone();
    let rep = blocking(&st, move || {
        let mut views = Vec::with_capacity(dirs.len());
        for d in dirs {
            views.push(crate::compare::SessionView::load(&d)?);
        }
        let mut rep = crate::compare::compare(views, &crate::compare::CompareOpts { tolerance_s: tol });
        if let Some(site) = site.as_deref() {
            crate::compare::attach_site_rf(&mut rep, site);
        }
        Ok::<_, anyhow::Error>(rep)
    })
    .await?
    .map_err(internal)?;

    if fmt == "md" {
        let md = crate::compare::to_markdown(&rep);
        Ok(attachment_response("text/markdown; charset=utf-8", "linkwatch-compare.md", md.into_bytes()))
    } else {
        Ok(json_body(&rep))
    }
}

// ---------- router audit, CVE lookup & advisor ----------

fn live_gateway(live: &crate::live::Live) -> (Option<std::net::Ipv4Addr>, Option<String>) {
    live.read(|s| {
        let gw = s
            .ifaces
            .values()
            .find_map(|i| i.last.as_ref().and_then(|l| l.link.gateway));
        let mac = s
            .session
            .as_ref()
            .and_then(|m| m.network.as_ref())
            .and_then(|n| n.gateway_mac.clone());
        (gw, mac)
    })
}

/// Last audit result only. A GET never sends anything to the network: viewers (possibly without
/// a token) must not be able to trigger port checks or adapter logins. Probes run only through
/// `POST /api/router/probe`, which needs the token.
async fn router_audit_get(State(st): State<AppState>) -> ApiResult {
    if let Some(cached) = st.router_audit.lock().await.clone() {
        return Ok(json_body(&cached));
    }
    let (gw, gw_mac) = live_gateway(&st.live);
    Ok(json_body(&crate::router_audit::RouterAudit {
        probed_at: Utc::now(),
        gateway_ip: gw.map(|g| g.to_string()),
        gateway_mac: gw_mac,
        adapter_used: "none".into(),
        warnings: vec![if gw.is_some() {
            "Not probed yet: run a probe (needs the web token).".into()
        } else {
            "Default gateway IP not detected yet.".into()
        }],
        ..Default::default()
    }))
}

async fn router_probe_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult {
    require_post_auth(&st, &headers, "set [web] token to probe router with credentials")?;
    let req: crate::router_audit::RouterProbeRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    let (live_gw, gw_mac) = live_gateway(&st.live);
    let target = match req.host.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => crate::router_audit::validate_local_host(raw)
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("{e:#}")))?,
        None => live_gw.ok_or_else(|| {
            ApiError(StatusCode::BAD_REQUEST, "gateway IP not known; specify a local host".into())
        })?,
    };
    if let Some(r) = rate_limited(&st.last_probe, PROBE_MIN_INTERVAL, "router probe") {
        return Ok(r);
    }
    let audit = crate::router_audit::run_probe(target, gw_mac, &req, st.router_upnp_url.as_deref()).await;
    *st.router_audit.lock().await = Some(audit.clone());
    Ok(json_body(&audit))
}

fn validate_cve_field(name: &str, raw: &str, required: bool) -> Result<(), ApiError> {
    let t = raw.trim();
    if required && t.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("{name} must not be empty")));
    }
    if t.chars().count() > 128 {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("{name} is too long (max 128 chars)")));
    }
    if t.chars().any(char::is_control) {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("{name} contains control characters")));
    }
    Ok(())
}

async fn router_cve_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult {
    require_post_auth(&st, &headers, "set [web] token to query external CVE databases")?;
    let req: crate::cve::CveLookupRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    validate_cve_field("model", &req.model, true)?;
    if let Some(v) = &req.vendor {
        validate_cve_field("vendor", v, false)?;
    }
    if let Some(fw) = &req.firmware {
        validate_cve_field("firmware", fw, false)?;
    }
    if let Some(r) = rate_limited(&st.last_cve, PROBE_MIN_INTERVAL, "CVE lookup") {
        return Ok(r);
    }
    let res = crate::cve::lookup_cves(&st.data_dir, &req, st.nvd_api_key.as_deref())
        .await
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("CVE lookup failed: {e:#}")))?;
    Ok(json_body(&res))
}

async fn advice_get(State(st): State<AppState>) -> ApiResult {
    let audit = st.router_audit.lock().await.clone();
    let resp = st.live.read(|snap| crate::advice::evaluate(snap, audit.as_ref()));
    Ok(json_body(&resp))
}

#[derive(Deserialize)]
struct SupportReportQuery {
    sessions: Option<String>,
    audience: Option<String>,
    lang: Option<String>,
    redact: Option<String>,
    format: Option<String>,
    tolerance_s: Option<f64>,
}

async fn support_report(
    State(st): State<AppState>,
    Extension(Authed(authed)): Extension<Authed>,
    Query(q): Query<SupportReportQuery>,
) -> ApiResult {
    use crate::support_report::{
        RedactionLevel, SupportAudience, SupportFormat, SupportInput, SupportLang, SupportOpts, build_pack, render_html,
        render_markdown,
    };

    let audience = match q.audience.as_deref().unwrap_or("isp") {
        "isp" => SupportAudience::Isp,
        "landlord" => SupportAudience::Landlord,
        "admin" => SupportAudience::Admin,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "audience must be isp, landlord, or admin".into())),
    };
    let lang = match q.lang.as_deref().unwrap_or("en") {
        "en" => SupportLang::En,
        "uk" => SupportLang::Uk,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "lang must be en or uk".into())),
    };
    let mut redaction = match q.redact.as_deref().unwrap_or("standard") {
        "standard" => RedactionLevel::Standard,
        "strict" => RedactionLevel::Strict,
        "none" => RedactionLevel::None,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "redact must be standard, strict, or none".into())),
    };
    if !authed && redaction == RedactionLevel::None {
        redaction = RedactionLevel::Standard;
    }
    let format = match q.format.as_deref().unwrap_or("json") {
        "json" => SupportFormat::Json,
        "text" => SupportFormat::Text,
        "md" => SupportFormat::Md,
        "html" => SupportFormat::Html,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "format must be json, text, md, or html".into())),
    };
    let tolerance_s = q.tolerance_s.unwrap_or(2.0);
    if !tolerance_s.is_finite() || !(0.0..=60.0).contains(&tolerance_s) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "tolerance_s must be 0..=60".into()));
    }

    let mut dirs = Vec::new();
    let mut seen = Vec::new();
    if let Some(raw) = q.sessions.as_deref() {
        for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if seen.iter().any(|s| s == part) {
                return Err(ApiError(StatusCode::BAD_REQUEST, format!("duplicate session id {part}")));
            }
            dirs.push(session_dir(&st, part)?);
            seen.push(part.to_string());
        }
        if dirs.len() > 8 {
            return Err(ApiError(StatusCode::BAD_REQUEST, "sessions must list at most 8 session ids".into()));
        }
    }
    let slug_src = if dirs.is_empty() {
        let (id, opt_dir) = resolve_report_target(&st, None)?;
        let Some(dir) = opt_dir else {
            return Err(ApiError(StatusCode::NOT_FOUND, "session has no recorded data yet".into()));
        };
        dirs.push(dir);
        id
    } else if seen.len() == 1 {
        seen[0].clone()
    } else {
        "multi".to_string()
    };

    let audit = st.router_audit.lock().await.clone();
    let site = st.site.clone();
    let pack = blocking(&st, move || {
        let mut views = Vec::with_capacity(dirs.len());
        for d in dirs {
            views.push(crate::compare::SessionView::load(&d)?);
        }
        Ok::<_, anyhow::Error>(build_pack(
            &SupportInput {
                sessions: &views,
                site: site.as_deref(),
                router_audit: audit.as_ref(),
                cve: None,
                router_log: &[],
            },
            &SupportOpts { audience, lang, redaction, tolerance_s },
        ))
    })
    .await?
    .map_err(internal)?;

    let slug = safe_slug(&slug_src, "session");
    match format {
        SupportFormat::Json => Ok(json_body(&pack)),
        SupportFormat::Text => Ok(([(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"))], pack.short_text).into_response()),
        SupportFormat::Md => Ok(attachment_response("text/markdown; charset=utf-8", &format!("support-report-{slug}.md"), render_markdown(&pack).into_bytes())),
        SupportFormat::Html => Ok(attachment_response("text/html; charset=utf-8", &format!("support-report-{slug}.html"), render_html(&pack).into_bytes())),
    }
}
