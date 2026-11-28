//! Report tab: the structured session report, its cache and the report export.

use super::{ApiError, ApiResult, attachment_response, blocking, internal, json_body, safe_slug, session_dir, web_load_opts};
use crate::analyze::{Msg, Report};
use crate::model::{IfaceRole, IncidentOrigin, PathState, Verdict};
use crate::session;
use crate::verdict;
use crate::web::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Deserialize)]
pub(super) struct ReportQuery {
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
    /// Conditions that blind one element for the whole session (reported once).
    pub session_blinds: Vec<crate::analyze::SessionBlind>,
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

/// A cached report with the verdict sentence of the current live verdict: the report may be up
/// to [`REPORT_FRESH`] old, but its headline must never contradict the live status.
fn with_live_verdict(rep: &ReportResponse, live: Option<Verdict>) -> Response {
    if rep.verdict == live {
        return json_body(rep);
    }
    let wifi_signal = rep.ifaces.iter().find(|i| i.role == Some(IfaceRole::Wifi)).and_then(|i| i.signal_med);
    let h = verdict::explain(live, rep.network_incidents, rep.observer_incidents, wifi_signal);
    let Ok(mut v) = serde_json::to_value(rep) else { return json_body(rep) };
    if let Some(o) = v.as_object_mut() {
        o.insert("verdict".into(), serde_json::to_value(live).unwrap_or_default());
        o.insert("verdict_summary".into(), h.text.into());
        o.insert("verdict_code".into(), h.code.into());
        o.insert("verdict_args".into(), serde_json::to_value(h.args).unwrap_or_default());
    }
    json_body(&v)
}

fn analyze_session_raw(dir: &Path) -> anyhow::Result<Report> {
    Ok(session::load(dir, &web_load_opts())?.report)
}

fn analyze_session_dir(dir: &Path, id: String, live_verdict: Option<Verdict>) -> anyhow::Result<ReportResponse> {
    let rep = analyze_session_raw(dir)?;
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
    let headline = verdict::headline(&rep, live_verdict);
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
    Ok(ReportResponse {
        session: id,
        from: rep.from,
        to: rep.to,
        hours: rep.hours,
        verdict: headline.verdict,
        verdict_summary: headline.text,
        verdict_code: headline.code.into(),
        verdict_args: headline.args,
        network_incidents: rep.network_incidents,
        load_incidents: rep.load_incidents,
        observer_incidents: rep.observer_incidents,
        ifaces,
        episodes,
        findings: rep.findings_msg,
        patterns: rep.patterns_msg,
        observer_findings: rep.observer_findings_msg,
        observer_trust: rep.observer_trust,
        session_blinds: rep.session_blinds,
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
    })
}

pub(super) fn resolve_report_target(st: &AppState, session: Option<String>) -> Result<(String, Option<PathBuf>), ApiError> {
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

pub(super) async fn report(State(st): State<AppState>, Query(q): Query<ReportQuery>) -> ApiResult {
    let live_verdict = st.live.read(|s| s.verdict);
    let (id, dir) = resolve_report_target(&st, q.session)?;
    let Some(dir) = dir else {
        let headline = verdict::headline(&Report::default(), live_verdict);
        return Ok(json_body(&ReportResponse {
            session: id,
            from: None,
            to: None,
            hours: 0.0,
            verdict: headline.verdict,
            verdict_summary: headline.text,
            verdict_code: headline.code.into(),
            verdict_args: headline.args,
            network_incidents: 0,
            load_incidents: 0,
            observer_incidents: 0,
            ifaces: Vec::new(),
            episodes: Vec::new(),
            findings: Vec::new(),
            patterns: Vec::new(),
            observer_findings: Vec::new(),
            observer_trust: Default::default(),
            session_blinds: Vec::new(),
            router: None,
            lan: None,
        }));
    };
    // No verdict in this key: a flapping live verdict must not defeat the rate limit.
    let fresh_key = dir.display().to_string();
    let hit = st.reports.lock().unwrap_or_else(|e| e.into_inner()).get_fresh(&fresh_key);
    if let Some(hit) = hit {
        return Ok(with_live_verdict(&hit, live_verdict));
    }
    // One analysis at a time: viewers that arrive while it runs wait and then hit the cache.
    let _build = st.report_build.lock().await;
    let hit = st.reports.lock().unwrap_or_else(|e| e.into_inner()).get_fresh(&fresh_key);
    if let Some(hit) = hit {
        return Ok(with_live_verdict(&hit, live_verdict));
    }
    let cache = st.reports.clone();
    let rep = blocking(&st, move || {
        let key = format!("{}|{}|{live_verdict:?}", dir.display(), all_stream_files_stamp(&dir));
        let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
        let built = match c.get(&key) {
            Some(hit) => hit,
            None => {
                drop(c);
                let built = Arc::new(analyze_session_dir(&dir, id, live_verdict)?);
                c = cache.lock().unwrap_or_else(|e| e.into_inner());
                c.put(key, built.clone());
                built
            }
        };
        c.put_fresh(fresh_key, built.clone());
        Ok::<_, anyhow::Error>(built)
    })
    .await?
    .map_err(internal)?;
    Ok(json_body(&*rep))
}

#[derive(Deserialize)]
pub(super) struct ExportQuery {
    session: Option<String>,
    format: Option<String>,
}

pub(super) async fn report_export(State(st): State<AppState>, Query(q): Query<ExportQuery>) -> ApiResult {
    let fmt = q.format.as_deref().unwrap_or("md");
    if !matches!(fmt, "md" | "json") {
        return Err(ApiError(StatusCode::BAD_REQUEST, "format must be md or json".into()));
    }
    let (id, dir) = resolve_report_target(&st, q.session)?;
    let Some(dir) = dir else {
        return Err(ApiError(StatusCode::NOT_FOUND, "session has no recorded data yet".into()));
    };
    let rep = blocking(&st, move || analyze_session_raw(&dir)).await?.map_err(internal)?;
    let slug = safe_slug(&id, "session");
    if fmt == "json" {
        let bytes = serde_json::to_vec_pretty(&rep).map_err(internal)?;
        Ok(attachment_response("application/json", &format!("linkwatch-{slug}.json"), bytes))
    } else {
        let md = crate::analyze::to_markdown(&rep);
        Ok(attachment_response("text/markdown; charset=utf-8", &format!("linkwatch-{slug}.md"), md.into_bytes()))
    }
}
