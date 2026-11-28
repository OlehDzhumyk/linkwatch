//! The one loader that turns a session folder into results (docs/ARCHITECTURE.md §3.2, P1).
//!
//! `linkwatch analyze`, `compare`, `support-report`, the web report, the web compare and the web
//! support pack all call [`load`]. The same session gives the same [`Report`] on every surface.
//! Surfaces keep their own formatting; they hold no loading code.

use crate::analyze::{self, Analyzer, Report, RouterLine};
use crate::link;
use crate::model::{EventKind, IfaceRole, NetworkFingerprint, PathState, Record, SessionMeta, Stream};
use crate::store;
use chrono::{DateTime, Duration, Utc};
use std::path::Path;

#[cfg(test)]
mod tests;

/// Options for [`load`].
#[derive(Debug, Clone, Default)]
pub struct LoadOpts {
    /// Recompute the path state of every sample with the current classifier, instead of using the
    /// state recorded at the time (`linkwatch analyze --reclassify`, see `analyze::reclassify`).
    pub reclassify: bool,
    /// Cable-modem event log lines to match with outages (see `analyze::parse_router_log`).
    pub router_log: Vec<RouterLine>,
    /// Most lines read from each stream. `None` reads everything (the CLI).
    ///
    /// The web sets this limit to keep one request inside the memory and time budget of a small
    /// device. A stream that is longer than the limit is cut at the limit: the oldest lines are
    /// analysed and the rest is ignored. The cut is logged, not shown in the report.
    pub max_lines: Option<usize>,
}

/// What one session folder gives: its identity, the network fingerprint, the clock facts, the
/// time ranges with no data, and the analyzer [`Report`].
#[derive(Debug, Clone)]
pub struct SessionResult {
    pub id: String,
    pub label: String,
    pub meta: Option<SessionMeta>,
    pub network: NetworkFingerprint,
    pub clock_synced: Option<bool>,
    pub clock_jumps: usize,
    pub gaps: Vec<(DateTime<Utc>, DateTime<Utc>)>,
    pub report: Report,
}

/// Reads the session in `dir` and analyses it.
///
/// Malformed lines are skipped and counted in `report.monitor_gaps`. Fails only when `dir` is
/// not a directory.
pub fn load(dir: &Path, opts: &LoadOpts) -> anyhow::Result<SessionResult> {
    anyhow::ensure!(dir.is_dir(), "session directory not found: {}", dir.display());
    let meta: Option<SessionMeta> = store::read::read_json_file(&dir.join(store::META_FILE));
    let id = meta
        .as_ref()
        .map(|m| m.session.clone())
        .or_else(|| dir.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "session".into());
    let label = format_session_label(&id, meta.as_ref());

    let mut network = meta.as_ref().and_then(|m| m.network.clone()).unwrap_or_default();
    let mut clock_synced = meta.as_ref().and_then(|m| m.clock_synced);
    let mut clock_jumps = 0usize;
    let analyzer_opts = analyze::Opts::for_session(meta.as_ref());
    let gap_thresh_s = (analyzer_opts.tick_s * 5.0).max(15.0);
    let tick = Duration::milliseconds((analyzer_opts.tick_s * 1000.0) as i64);
    let mut a = Analyzer::new(analyzer_opts);
    let mut gaps: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    let mut from_ts: Option<DateTime<Utc>> = None;
    let mut to_ts: Option<DateTime<Utc>> = None;
    let mut first_active_ts: Option<DateTime<Utc>> = None;
    let mut last_active_ts: Option<DateTime<Utc>> = None;
    let mut skipped = 0u64;

    let mut rc = opts.reclassify.then(|| analyze::reclassify::Reclassifier::for_session(meta.as_ref()));
    // Samples must be in order per interface; the other streams are used as sets.
    for st in Stream::ALL {
        let mut it = store::read::iter(dir, st);
        for (taken, mut env) in it.by_ref().enumerate() {
            if opts.max_lines.is_some_and(|max| taken >= max) {
                tracing::warn!("session {id}: stream {st:?} is longer than {taken} lines; the rest is ignored");
                break;
            }
            if let Some(rc) = rc.as_mut() {
                rc.apply(&mut env);
            }
            from_ts = Some(from_ts.map_or(env.ts, |f| f.min(env.ts)));
            to_ts = Some(to_ts.map_or(env.ts, |t| t.max(env.ts)));
            match &env.rec {
                Record::Event(EventKind::NetworkInfo { fingerprint }) => merge_fingerprint(&mut network, fingerprint),
                Record::Event(EventKind::ClockJump { .. }) => clock_jumps += 1,
                Record::Event(EventKind::Start { gap_s: Some(g), .. }) if *g > 5.0 => {
                    let start = env.ts - Duration::milliseconds((*g * 1000.0).round() as i64);
                    gaps.push((start, env.ts));
                }
                Record::Event(EventKind::SuspendGap { secs }) if *secs > 0.0 => {
                    let start = env.ts - Duration::milliseconds((*secs * 1000.0).round() as i64);
                    gaps.push((start, env.ts));
                }
                Record::Sample(s) => {
                    if network.gateway_ip.is_none() {
                        network.gateway_ip = s.link.gateway;
                    }
                    if network.subnet.is_none() {
                        network.subnet = s.link.ipv4.zip(s.link.prefix_len).map(|(ip, p)| link::subnet_cidr(ip, p));
                    }
                    if s.role == IfaceRole::Wifi || !matches!(s.state, PathState::LinkDown | PathState::NoIp) {
                        let ts = s.t.unwrap_or(env.ts);
                        first_active_ts = Some(first_active_ts.map_or(ts, |p| p.min(ts)));
                        if let Some(prev) = last_active_ts {
                            if ts > prev && (ts - prev).num_milliseconds() as f64 / 1000.0 > gap_thresh_s {
                                gaps.push((prev + tick, ts));
                            }
                            last_active_ts = Some(prev.max(ts));
                        } else {
                            last_active_ts = Some(ts);
                        }
                    }
                }
                Record::Wifi(w) => {
                    if w.connected
                        && let Some(ref b) = w.bssid
                    {
                        let b_lc = b.to_ascii_lowercase();
                        if !network.bssids.iter().any(|x| x.eq_ignore_ascii_case(&b_lc)) {
                            network.bssids.push(b_lc);
                        }
                    }
                }
                Record::Host(h) => {
                    if h.clock_synced == Some(false) {
                        clock_synced = Some(false);
                    } else if h.clock_synced == Some(true) && clock_synced.is_none() {
                        clock_synced = Some(true);
                    }
                }
                _ => {}
            }
            a.push(&env);
        }
        skipped += it.skipped();
    }
    if let (Some(f), Some(t), Some(fa), Some(la)) = (from_ts, to_ts, first_active_ts, last_active_ts) {
        if (fa - f).num_milliseconds() as f64 / 1000.0 > gap_thresh_s {
            gaps.push((f, fa));
        }
        let la_end = la + tick;
        if (t - la_end).num_milliseconds() as f64 / 1000.0 > gap_thresh_s {
            gaps.push((la_end, t));
        }
    }
    let mut report = a.finish(&opts.router_log);
    if skipped > 0 {
        report.monitor_gaps.push(format!("{skipped} malformed lines skipped while reading"));
    }
    Ok(SessionResult { id, label, meta, network, clock_synced, clock_jumps, gaps, report })
}

fn format_session_label(id: &str, meta: Option<&SessionMeta>) -> String {
    let Some(m) = meta else {
        return id.to_string();
    };
    match (&m.point, &m.label) {
        (Some(p), Some(l)) => format!("{p} ({l})"),
        (Some(p), None) => p.clone(),
        (None, Some(l)) => format!("{l} ({})", m.host),
        (None, None) => format!("{} ({id})", m.host),
    }
}

fn merge_fingerprint(dst: &mut NetworkFingerprint, src: &NetworkFingerprint) {
    if dst.gateway_ip.is_none() {
        dst.gateway_ip = src.gateway_ip;
    }
    if dst.gateway_mac.is_none() {
        dst.gateway_mac = src.gateway_mac.clone();
    }
    if dst.subnet.is_none() {
        dst.subnet = src.subnet.clone();
    }
    if dst.isp_hop.is_none() {
        dst.isp_hop = src.isp_hop;
    }
    for b in &src.bssids {
        if !dst.bssids.iter().any(|x| x.eq_ignore_ascii_case(b)) {
            dst.bssids.push(b.to_ascii_lowercase());
        }
    }
}
