//! Multi-observer and multi-session comparison (`linkwatch compare`).
//!
//! Recognises whether sessions were recorded on the same network via their
//! [`NetworkFingerprint`], aligns overlapping sessions in UTC within a configurable
//! clock tolerance, excludes observer-origin faults, and separates shared outages
//! (router/line/ISP) from local Wi-Fi or band-specific problems. Also provides
//! side-by-side comparison for sequential runs (e.g. bedroom 1 vs bedroom 2, or 2.4 vs 5 GHz).

use crate::analyze::{self, Analyzer, Episode, Msg, Report};
use crate::link;
use crate::model::{EventKind, IncidentOrigin, IfaceRole, NetworkFingerprint, PathState, Record, SessionMeta, Stream, Verdict};
use crate::store;
use chrono::{DateTime, Duration, Local, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct CompareOpts {
    pub tolerance_s: f64,
}

impl Default for CompareOpts {
    fn default() -> Self {
        Self { tolerance_s: 2.0 }
    }
}

#[derive(Debug, Clone)]
pub struct SessionView {
    pub id: String,
    pub label: String,
    pub meta: Option<SessionMeta>,
    pub network: NetworkFingerprint,
    pub clock_synced: Option<bool>,
    pub clock_jumps: usize,
    pub gaps: Vec<(DateTime<Utc>, DateTime<Utc>)>,
    pub report: Report,
}

impl SessionView {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(dir.is_dir(), "session directory not found: {}", dir.display());
        let meta: Option<SessionMeta> =
            std::fs::read(dir.join("meta.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
        let id = meta
            .as_ref()
            .map(|m| m.session.clone())
            .or_else(|| dir.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "session".into());
        let label = format_session_label(&id, meta.as_ref());

        let mut network = meta.as_ref().and_then(|m| m.network.clone()).unwrap_or_default();
        let mut clock_synced = meta.as_ref().and_then(|m| m.clock_synced);
        let mut clock_jumps = 0usize;
        let opts = analyze::Opts::for_session(meta.as_ref());
        let gap_thresh_s = (opts.tick_s * 5.0).max(15.0);
        let tick = Duration::milliseconds((opts.tick_s * 1000.0) as i64);
        let mut a = Analyzer::new(opts);
        let mut gaps: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
        let mut from_ts: Option<DateTime<Utc>> = None;
        let mut to_ts: Option<DateTime<Utc>> = None;
        let mut first_active_ts: Option<DateTime<Utc>> = None;
        let mut last_active_ts: Option<DateTime<Utc>> = None;

        for st in Stream::ALL {
            for env in store::read::iter(dir, st) {
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
        let report = a.finish(&[]);
        Ok(Self {
            id,
            label,
            meta,
            network,
            clock_synced,
            clock_jumps,
            gaps,
            report,
        })
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum NetworkMatch {
    Same,
    Likely,
    Different,
    Unknown,
}

/// Compares two sessions' network fingerprints to tell whether they tested the same network.
pub fn match_networks(a: &NetworkFingerprint, b: &NetworkFingerprint) -> (NetworkMatch, Msg) {
    use crate::msg;
    let a_mac = a.gateway_mac.as_deref().map(str::to_ascii_lowercase);
    let b_mac = b.gateway_mac.as_deref().map(str::to_ascii_lowercase);
    if let (Some(ma), Some(mb)) = (&a_mac, &b_mac)
        && ma == mb
    {
        return (NetworkMatch::Same, msg!("n_same_mac", "same gateway MAC ({mac})", mac = ma));
    }
    let a_bss: BTreeSet<String> = a.bssids.iter().map(|s| s.to_ascii_lowercase()).collect();
    let b_bss: BTreeSet<String> = b.bssids.iter().map(|s| s.to_ascii_lowercase()).collect();
    if let Some(shared) = a_bss.intersection(&b_bss).next() {
        return (NetworkMatch::Same, msg!("n_same_bssid", "shared router BSSID ({bssid})", bssid = shared));
    }
    if let (Some(ma), Some(mb)) = (&a_mac, &b_mac) {
        return (NetworkMatch::Different, msg!("n_diff_mac", "different gateway MACs ({a} vs {b})", a = ma, b = mb));
    }
    if let (Some(sa), Some(sb)) = (&a.subnet, &b.subnet)
        && sa != sb
    {
        return (NetworkMatch::Different, msg!("n_diff_subnet", "different subnets ({a} vs {b})", a = sa, b = sb));
    }
    if let (Some(ia), Some(ib)) = (a.isp_hop, b.isp_hop)
        && ia != ib
    {
        return (NetworkMatch::Different, msg!("n_diff_isp", "different ISP first hops ({a} vs {b})", a = ia, b = ib));
    }
    if let (Some(ga), Some(gb)) = (a.gateway_ip, b.gateway_ip)
        && ga != gb
    {
        return (NetworkMatch::Different, msg!("n_diff_gw", "different gateway IPs ({a} vs {b})", a = ga, b = gb));
    }
    if a.gateway_ip.is_some() && a.gateway_ip == b.gateway_ip && a.subnet.is_some() && a.subnet == b.subnet {
        if a.isp_hop.is_some() && a.isp_hop == b.isp_hop {
            return (NetworkMatch::Likely, msg!("n_likely_isp", "same gateway IP, subnet and ISP hop (gateway MAC unknown)"));
        }
        return (NetworkMatch::Likely, msg!("n_likely", "same gateway IP, subnet (gateway MAC unknown)"));
    }
    (NetworkMatch::Unknown, msg!("n_unknown", "insufficient network fingerprint data"))
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct PairMatch {
    pub a: String,
    pub b: String,
    pub match_kind: NetworkMatch,
    pub reason: String,
    pub reason_msg: Msg,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct SessionRow {
    pub id: String,
    pub label: String,
    pub host: String,
    pub point: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub hours: f64,
    pub iface: String,
    pub bands: Vec<String>,
    pub availability_pct: f64,
    pub outages: u32,
    pub micro_drops: u32,
    pub stalls: u32,
    pub outages_per_h: f64,
    pub micro_per_h: f64,
    pub gw_rtt_med: Option<f64>,
    pub net_rtt_med: Option<f64>,
    pub loaded_net_rtt_med: Option<f64>,
    pub signal_med: Option<f64>,
    pub speed_med_mbps: Option<f64>,
    pub retry_rate_per_min: Option<f64>,
    pub observer_incidents: u32,
    pub rf: Option<crate::site::RfPathEstimate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum CorrelatedKind {
    SharedOutage,
    WifiOnlyOutage,
    LocalOnly,
    BandSpecific,
    PartialOverlap,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct CorrelatedIncident {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub kind: CorrelatedKind,
    pub detail: String,
    pub affected: Vec<String>,
    pub unaffected: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct CompareReport {
    pub tolerance_s: f64,
    pub network_matches: Vec<PairMatch>,
    pub clock_warnings: Vec<String>,
    pub clock_warnings_msg: Vec<Msg>,
    pub sessions: Vec<SessionRow>,
    pub overlap_hours: f64,
    pub correlated: Vec<CorrelatedIncident>,
    pub findings: Vec<String>,
    pub findings_msg: Vec<Msg>,
}

impl CompareReport {
    fn say(&mut self, m: Msg) {
        self.findings.push(m.text.clone());
        self.findings_msg.push(m);
    }
    fn warn_clock(&mut self, m: Msg) {
        self.clock_warnings.push(m.text.clone());
        self.clock_warnings_msg.push(m);
    }
}

/// Attaches 5 GHz RF path attenuation estimates from `site` to every [`SessionRow`] whose
/// `point` matches a site point with a reachable router/AP in the same building.
pub fn attach_site_rf(rep: &mut CompareReport, site: &crate::site::Site) {
    for row in &mut rep.sessions {
        if let Some(pid) = row.point.as_deref() {
            row.rf = site.estimate_rf(pid);
        }
    }
}

pub fn compare(sessions: Vec<SessionView>, opts: &CompareOpts) -> CompareReport {
    let mut rep = CompareReport {
        tolerance_s: opts.tolerance_s,
        ..Default::default()
    };
    if sessions.is_empty() {
        return rep;
    }

    // 1. Pairwise network fingerprint matches.
    for i in 0..sessions.len() {
        for j in (i + 1)..sessions.len() {
            let (mk, reason) = match_networks(&sessions[i].network, &sessions[j].network);
            rep.network_matches.push(PairMatch {
                a: sessions[i].label.clone(),
                b: sessions[j].label.clone(),
                match_kind: mk,
                reason: reason.text.clone(),
                reason_msg: reason,
            });
        }
    }

    // 2. Clock warnings.
    for s in &sessions {
        if s.clock_synced == Some(false) {
            rep.warn_clock(crate::msg!("cw_ntp", "{label}: clock was NOT NTP-synchronized; concurrent overlap alignment may drift beyond ±{tol}s",
                label = s.label, tol = format!("{:.0}", opts.tolerance_s)));
        }
        if s.clock_jumps > 0 {
            rep.warn_clock(crate::msg!("cw_jumps", "{label}: recorded {n} clock jump(s) during the session", label = s.label, n = s.clock_jumps));
        }
    }

    // 3. Per-session rows & band metadata.
    let mut session_bands: Vec<BTreeSet<String>> = Vec::with_capacity(sessions.len());
    for s in &sessions {
        let primary = s
            .report
            .ifaces
            .iter()
            .filter(|i| i.ticks > 0)
            .max_by_key(|i| (i.role == Some(IfaceRole::Wifi), i.ticks))
            .or_else(|| s.report.ifaces.first());
        let mut bands = BTreeSet::new();
        for i in &s.report.ifaces {
            for b in &i.bands {
                bands.insert(b.band.clone());
            }
        }
        session_bands.push(bands.clone());

        let hours = s.report.hours;
        let div_h = if hours > 1e-4 { hours } else { 1.0 };
        let (iface, avail, outs, micros, stalls, gw, net, loaded_net, sig, spd, retry) = match primary {
            Some(p) => (
                p.iface.clone(),
                p.availability_pct,
                p.episodes,
                p.micro_drops,
                p.stalls,
                p.gw_rtt_med,
                p.net_rtt_med,
                p.loaded_net_rtt_med,
                p.signal_med,
                p.speed_med_mbps,
                p.retry_rate_per_min,
            ),
            None => ("-".into(), 0.0, 0, 0, 0, None, None, None, None, None, None),
        };
        rep.sessions.push(SessionRow {
            id: s.id.clone(),
            label: s.label.clone(),
            host: s.meta.as_ref().map_or_else(|| "-".into(), |m| m.host.clone()),
            point: s.meta.as_ref().and_then(|m| m.point.clone()),
            from: s.report.from,
            to: s.report.to,
            hours,
            iface,
            bands: bands.into_iter().collect(),
            availability_pct: avail,
            outages: outs,
            micro_drops: micros,
            stalls,
            outages_per_h: if hours > 1e-4 { f64::from(outs) / div_h } else { 0.0 },
            micro_per_h: if hours > 1e-4 { f64::from(micros) / div_h } else { 0.0 },
            gw_rtt_med: gw,
            net_rtt_med: net,
            loaded_net_rtt_med: loaded_net,
            signal_med: sig,
            speed_med_mbps: spd,
            retry_rate_per_min: retry,
            observer_incidents: s.report.observer_incidents,
            rf: None,
        });
    }

    // 4. Overlap duration where >= 2 sessions were active simultaneously.
    rep.overlap_hours = total_multi_observer_hours(&sessions);

    // 5. Cluster non-observer, non-load-provoked episodes across sessions within ±tolerance_s.
    let tol = Duration::milliseconds((opts.tolerance_s * 1000.0).round() as i64);
    let mut all_eps: Vec<(usize, &Episode)> = Vec::new();
    for (idx, s) in sessions.iter().enumerate() {
        for ep in &s.report.episodes {
            if ep.origin != IncidentOrigin::Observer && !analyze::is_load_provoked(ep) {
                all_eps.push((idx, ep));
            }
        }
    }
    all_eps.sort_by_key(|(_, ep)| ep.start);

    struct Cluster<'a> {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        items: Vec<(usize, &'a Episode)>,
    }
    let mut clusters: Vec<Cluster<'_>> = Vec::new();
    for (idx, ep) in all_eps {
        match clusters.last_mut() {
            Some(c) if ep.start <= c.end + tol => {
                c.end = c.end.max(ep.end);
                c.items.push((idx, ep));
            }
            _ => clusters.push(Cluster {
                start: ep.start,
                end: ep.end,
                items: vec![(idx, ep)],
            }),
        }
    }

    let mut local_counts: BTreeMap<usize, u32> = BTreeMap::new();
    let mut shared_count = 0u32;
    let mut wifi_only_count = 0u32;
    let mut band_counts: BTreeMap<String, u32> = BTreeMap::new();
    for c in clusters {
        let aff_idx: BTreeSet<usize> = c.items.iter().map(|(i, _)| *i).collect();
        let active: Vec<usize> = sessions
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                if aff_idx.contains(&i) {
                    return Some(i);
                }
                let (Some(f), Some(t)) = (s.report.from, s.report.to) else { return None };
                let has_active_iface = s.report.ifaces.iter().any(|inf| inf.ticks > 0);
                let covered = f <= c.end + tol && t >= c.start - tol;
                let gapped = s.gaps.iter().any(|(gs, ge)| *gs < c.end + tol && *ge > c.start - tol);
                (has_active_iface && covered && !gapped).then_some(i)
            })
            .collect();
        if active.len() < 2 {
            continue;
        }
        let unaff_idx: Vec<usize> = active.iter().copied().filter(|i| !aff_idx.contains(i)).collect();
        let affected: Vec<String> = aff_idx.iter().map(|&i| sessions[i].label.clone()).collect();
        let unaffected: Vec<String> = unaff_idx.iter().map(|&i| sessions[i].label.clone()).collect();

        let aff_bands: BTreeSet<String> = c
            .items
            .iter()
            .filter_map(|(_, ep)| ep.band.clone())
            .collect();
        let unaff_other_band = !aff_bands.is_empty()
            && unaff_idx
                .iter()
                .any(|&i| session_bands[i].iter().any(|b| !aff_bands.contains(b)));

        let all_wifi = !c.items.is_empty() && c.items.iter().all(|(_, ep)| ep.role == IfaceRole::Wifi);
        let wired_stayed_up = c.items.iter().any(|(_, ep)| ep.cause == Some(Verdict::WifiProblem));

        let (kind, detail) = if unaff_idx.is_empty() && all_wifi && wired_stayed_up {
            wifi_only_count += 1;
            if aff_bands.len() == 1
                && let Some(b) = aff_bands.iter().next()
            {
                (
                    CorrelatedKind::WifiOnlyOutage,
                    format!("all {} active Wi-Fi observers failed on {b} while a co-located wired path stayed online (AP / Wi-Fi radio issue)", active.len()),
                )
            } else {
                (
                    CorrelatedKind::WifiOnlyOutage,
                    format!("all {} active Wi-Fi observers failed while a co-located wired path stayed online (AP / Wi-Fi radio issue)", active.len()),
                )
            }
        } else if unaff_idx.is_empty() {
            shared_count += 1;
            (
                CorrelatedKind::SharedOutage,
                format!("all {} active observers failed simultaneously (router / line / ISP)", active.len()),
            )
        } else if aff_idx.len() == 1
            && let Some(&only) = aff_idx.iter().next()
        {
            *local_counts.entry(only).or_default() += 1;
            (
                CorrelatedKind::LocalOnly,
                format!("only {} failed while {} other observer(s) stayed online (local Wi-Fi)", sessions[only].label, unaff_idx.len()),
            )
        } else if aff_bands.len() == 1
            && unaff_other_band
            && let Some(b) = aff_bands.into_iter().next()
        {
            *band_counts.entry(b.clone()).or_default() += 1;
            (
                CorrelatedKind::BandSpecific,
                format!("only {b} observers failed while other band(s) stayed online"),
            )
        } else {
            (
                CorrelatedKind::PartialOverlap,
                format!("{} of {} active observers failed", aff_idx.len(), active.len()),
            )
        };
        rep.correlated.push(CorrelatedIncident {
            start: c.start,
            end: c.end,
            kind,
            detail,
            affected,
            unaffected,
        });
    }

    // 6. Plain-language findings.
    if !rep.network_matches.is_empty() {
        let all_same = rep
            .network_matches
            .iter()
            .all(|m| matches!(m.match_kind, NetworkMatch::Same | NetworkMatch::Likely));
        let any_diff = rep
            .network_matches
            .iter()
            .any(|m| m.match_kind == NetworkMatch::Different);
        if any_diff {
            let diffs: Vec<String> = rep
                .network_matches
                .iter()
                .filter(|m| m.match_kind == NetworkMatch::Different)
                .map(|m| format!("{} vs {}: {}", m.a, m.b, m.reason))
                .collect();
            rep.say(crate::msg!("cf_diff_net", "Warning: sessions may be from DIFFERENT networks ({list}).", list = diffs.join("; ")));
        } else if all_same {
            let reason = rep.network_matches[0].reason.clone();
            rep.say(crate::msg!("cf_same_net", "Network match confirmed across all {n} sessions ({reason}).", n = sessions.len(), reason = reason));
        }
    }

    if rep.overlap_hours > 0.0 {
        let (h, tol) = (format!("{:.2}", rep.overlap_hours), format!("{:.1}", opts.tolerance_s));
        rep.say(crate::msg!("cf_window", "Concurrent observation window (2+ points active at once): {h} h (clock tolerance ±{tol} s).", h = h, tol = tol));
        if shared_count > 0 {
            rep.say(crate::msg!("cf_shared", "{n} shared outage(s) hit every active observer at the same time — router, cable line, or ISP problem.", n = shared_count));
        }
        if wifi_only_count > 0 {
            rep.say(crate::msg!("cf_wifi_only", "{n} Wi-Fi-only outage(s) hit every Wi-Fi observer while a co-located wired connection stayed online — router Wi-Fi / AP problem, not the upstream line.", n = wifi_only_count));
        }
        for (idx, count) in local_counts {
            rep.say(crate::msg!("cf_local", "{label}: {n} local outage(s) happened while other active observer(s) stayed online — Wi-Fi issue at this point.", label = sessions[idx].label, n = count));
        }
        for (band, count) in band_counts {
            rep.say(crate::msg!("cf_band", "{band}: {n} band-specific outage(s) occurred while other frequency band(s) stayed online.", band = band, n = count));
        }
    } else if sessions.len() >= 2 {
        rep.say(crate::msg!("cf_no_overlap", "Sessions do not overlap in time — showing side-by-side comparison of rates and signal/speed."));
    }

    if rep.sessions.len() >= 2 {
        let best = rep
            .sessions
            .iter()
            .max_by(|a, b| a.availability_pct.total_cmp(&b.availability_pct));
        let worst = rep
            .sessions
            .iter()
            .min_by(|a, b| a.availability_pct.total_cmp(&b.availability_pct));
        if let (Some(b), Some(w)) = (best, worst)
            && b.id != w.id
            && (b.availability_pct - w.availability_pct > 0.05 || w.outages_per_h > b.outages_per_h + 0.1)
        {
            let m = crate::msg!("cf_best_worst", "Best vs worst point: {best} ({ba}% avail, {bo} outages/h) vs {worst} ({wa}% avail, {wo} outages/h).",
                best = b.label, ba = format!("{:.2}", b.availability_pct), bo = format!("{:.2}", b.outages_per_h),
                worst = w.label, wa = format!("{:.2}", w.availability_pct), wo = format!("{:.2}", w.outages_per_h));
            rep.say(m);
        }
    }

    rep
}

fn total_multi_observer_hours(sessions: &[SessionView]) -> f64 {
    let mut pts: Vec<(DateTime<Utc>, i32)> = Vec::new();
    for s in sessions {
        if let (Some(f), Some(t)) = (s.report.from, s.report.to)
            && t > f
        {
            pts.push((f, 1));
            pts.push((t, -1));
        }
    }
    pts.sort_by_key(|(t, d)| (*t, *d));
    let mut active = 0i32;
    let mut prev: Option<DateTime<Utc>> = None;
    let mut total_ms = 0i64;
    for (t, d) in pts {
        if active >= 2
            && let Some(p) = prev
            && t > p
        {
            total_ms += (t - p).num_milliseconds();
        }
        active += d;
        prev = Some(t);
    }
    total_ms as f64 / 3_600_000.0
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

pub fn to_markdown(r: &CompareReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let lt = |t: DateTime<Utc>| t.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string();
    let _ = writeln!(s, "# linkwatch comparison report\n");
    if !r.clock_warnings.is_empty() {
        let _ = writeln!(s, "## Clock warnings\n");
        for w in &r.clock_warnings {
            let _ = writeln!(s, "- {w}");
        }
        let _ = writeln!(s);
    }
    let _ = writeln!(s, "## Findings\n");
    for f in &r.findings {
        let _ = writeln!(s, "- {f}");
    }
    let _ = writeln!(s, "\n## Sessions\n");
    let _ = writeln!(
        s,
        "| session | iface | bands | hours | avail % | outages (/h) | micro (/h) | router RTT | net RTT | signal | speed | observer |\n|---|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for x in &r.sessions {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {:.1} | {:.2}% | {} ({:.2}) | {} ({:.2}) | {} | {} | {} | {} | {} |",
            cell(&x.label),
            x.iface,
            if x.bands.is_empty() { "-".into() } else { x.bands.join(",") },
            x.hours,
            x.availability_pct,
            x.outages,
            x.outages_per_h,
            x.micro_drops,
            x.micro_per_h,
            x.gw_rtt_med.map_or("-".into(), |v| format!("{v:.1} ms")),
            x.net_rtt_med.map_or("-".into(), |v| format!("{v:.1} ms")),
            x.signal_med.map_or("-".into(), |v| format!("{v:.0} dBm")),
            x.speed_med_mbps.map_or("-".into(), |v| format!("{v:.1} Mb/s")),
            x.observer_incidents,
        );
    }
    if !r.network_matches.is_empty() {
        let _ = writeln!(s, "\n## Network fingerprint checks\n");
        for m in &r.network_matches {
            let _ = writeln!(s, "- {} ↔ {}: {:?} ({})", m.a, m.b, m.match_kind, m.reason);
        }
    }
    if !r.correlated.is_empty() {
        let _ = writeln!(s, "\n## Concurrent incidents (within ±{:.1} s)\n", r.tolerance_s);
        let _ = writeln!(s, "| start | end | kind | affected | unaffected | detail |\n|---|---|---|---|---|---|");
        for c in &r.correlated {
            let _ = writeln!(
                s,
                "| {} | {} | {:?} | {} | {} | {} |",
                lt(c.start),
                c.end.with_timezone(&Local).format("%H:%M:%S"),
                c.kind,
                cell(&c.affected.join(", ")),
                if c.unaffected.is_empty() { "-".into() } else { cell(&c.unaffected.join(", ")) },
                cell(&c.detail),
            );
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{BandStats, IfaceReport};
    use std::net::Ipv4Addr;

    fn mk_fp(gw_mac: Option<&str>, bssid: Option<&str>, subnet: Option<&str>) -> NetworkFingerprint {
        NetworkFingerprint {
            gateway_ip: Some(Ipv4Addr::new(192, 168, 0, 1)),
            gateway_mac: gw_mac.map(String::from),
            subnet: subnet.map(String::from),
            bssids: bssid.into_iter().map(String::from).collect(),
            isp_hop: Some(Ipv4Addr::new(198, 51, 100, 1)),
        }
    }

    fn mk_session(
        label: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        band: &str,
        avail: f64,
        eps: Vec<Episode>,
        fp: NetworkFingerprint,
    ) -> SessionView {
        SessionView {
            id: label.into(),
            label: label.into(),
            meta: None,
            network: fp,
            clock_synced: Some(true),
            clock_jumps: 0,
            gaps: vec![],
            report: Report {
                from: Some(from),
                to: Some(to),
                hours: (to - from).num_seconds() as f64 / 3600.0,
                ifaces: vec![IfaceReport {
                    iface: "wlo1".into(),
                    role: Some(IfaceRole::Wifi),
                    ticks: 3600,
                    availability_pct: avail,
                    episodes: eps.iter().filter(|e| e.origin != IncidentOrigin::Observer).count() as u32,
                    bands: vec![BandStats { band: band.into(), ticks: 3600, availability_pct: avail, ..Default::default() }],
                    ..Default::default()
                }],
                episodes: eps,
                ..Default::default()
            },
        }
    }

    fn mk_ep(start: DateTime<Utc>, secs: i64, origin: IncidentOrigin, band: Option<&str>) -> Episode {
        Episode {
            iface: "wlo1".into(),
            role: IfaceRole::Wifi,
            start,
            end: start + Duration::seconds(secs),
            duration_s: secs as f64,
            ticks: secs as u32,
            state: PathState::LanDown,
            cause: Some(Verdict::SinglePath),
            origin,
            band: band.map(String::from),
            speedtest_active: false,
            context: vec![],
            context_msg: vec![],
            finding: Default::default(),
        }
    }

    #[test]
    fn fingerprint_matching() {
        let a = mk_fp(Some("02:00:00:00:00:04"), Some("02:00:00:00:00:10"), Some("192.168.0.0/24"));
        let b = mk_fp(Some("02:00:00:00:00:04"), Some("02:00:00:00:00:11"), Some("192.168.0.0/24"));
        assert_eq!(match_networks(&a, &b).0, NetworkMatch::Same);

        let c = mk_fp(None, Some("02:00:00:00:00:10"), Some("192.168.0.0/24"));
        assert_eq!(match_networks(&a, &c).0, NetworkMatch::Same);

        let d = mk_fp(Some("02:00:00:00:00:99"), Some("02:00:00:00:00:98"), Some("192.168.0.0/24"));
        assert_eq!(match_networks(&a, &d).0, NetworkMatch::Different);

        let e = mk_fp(None, None, Some("192.168.0.0/24"));
        let f = mk_fp(None, None, Some("192.168.0.0/24"));
        assert_eq!(match_networks(&e, &f).0, NetworkMatch::Likely);
    }

    #[test]
    fn concurrent_shared_vs_local_and_observer_excluded() {
        let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let t1 = t0 + Duration::hours(2);
        let fp = mk_fp(Some("02:00:00:00:00:04"), None, Some("192.168.0.0/24"));

        // Shared outage at +600s with 1.5s clock offset (within default 2.0s tolerance).
        // Local-only outage on R4 at +1200s. Observer fault on R1 at +2400s (ignored).
        let s1 = mk_session(
            "B1/F1/R1",
            t0,
            t1,
            "5 GHz",
            99.8,
            vec![
                mk_ep(t0 + Duration::seconds(600), 10, IncidentOrigin::Network, Some("5 GHz")),
                mk_ep(t0 + Duration::seconds(2400), 6, IncidentOrigin::Observer, Some("5 GHz")),
            ],
            fp.clone(),
        );
        let s2 = mk_session(
            "B1/F2/R4",
            t0,
            t1,
            "5 GHz",
            98.5,
            vec![
                mk_ep(t0 + Duration::milliseconds(601_500), 10, IncidentOrigin::Network, Some("5 GHz")),
                mk_ep(t0 + Duration::seconds(1200), 15, IncidentOrigin::Network, Some("5 GHz")),
            ],
            fp,
        );
        let rep = compare(vec![s1, s2], &CompareOpts::default());
        assert!(rep.overlap_hours > 1.9);
        assert_eq!(rep.correlated.len(), 2, "{:#?}", rep.correlated);
        assert_eq!(rep.correlated[0].kind, CorrelatedKind::SharedOutage);
        assert_eq!(rep.correlated[1].kind, CorrelatedKind::LocalOnly);
        assert_eq!(rep.correlated[1].affected, vec!["B1/F2/R4".to_string()]);
    }

    #[test]
    fn sequential_comparison_and_unsynced_clock_warning() {
        let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let fp = mk_fp(Some("02:00:00:00:00:04"), None, Some("192.168.0.0/24"));
        let mut s1 = mk_session("2.4 GHz night", t0, t0 + Duration::hours(8), "2.4 GHz", 97.5, vec![], fp.clone());
        s1.clock_synced = Some(false);
        let s2 = mk_session("5 GHz night", t0 + Duration::hours(24), t0 + Duration::hours(32), "5 GHz", 99.9, vec![], fp);
        let rep = compare(vec![s1, s2], &CompareOpts::default());
        assert_eq!(rep.overlap_hours, 0.0);
        assert!(!rep.clock_warnings.is_empty());
        assert!(rep.findings.iter().any(|f| f.contains("Best vs worst")));
    }

    #[test]
    fn wifi_only_outage_not_labeled_shared_and_gapped_observer_excluded() {
        let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let t1 = t0 + Duration::hours(2);
        let fp = mk_fp(Some("02:00:00:00:00:04"), None, Some("192.168.0.0/24"));

        // Observer A (dual-interface: wired stayed up -> Verdict::WifiProblem) + Observer B (single Wi-Fi)
        // both fail on 5 GHz at +600s -> WifiOnlyOutage, NOT SharedOutage.
        let mut ep_a = mk_ep(t0 + Duration::seconds(600), 10, IncidentOrigin::Network, Some("5 GHz"));
        ep_a.cause = Some(Verdict::WifiProblem);
        let ep_a_local = mk_ep(t0 + Duration::seconds(1900), 10, IncidentOrigin::Network, Some("5 GHz"));
        let ep_b = mk_ep(t0 + Duration::seconds(601), 10, IncidentOrigin::Network, Some("5 GHz"));

        let s1 = mk_session("obs|A\nlab", t0, t1, "5 GHz", 99.0, vec![ep_a, ep_a_local], fp.clone());
        let mut s2 = mk_session("obs-B", t0, t1, "5 GHz", 99.5, vec![ep_b], fp);
        // Observer B had a monitor/suspend gap covering [t0 + 1800, t0 + 2100]: must not count as active at +1900.
        s2.gaps.push((t0 + Duration::seconds(1800), t0 + Duration::seconds(2100)));

        let rep = compare(vec![s1, s2], &CompareOpts::default());
        assert_eq!(rep.correlated.len(), 1, "{:#?}", rep.correlated);
        assert_eq!(rep.correlated[0].kind, CorrelatedKind::WifiOnlyOutage);
        assert!(rep.findings.iter().any(|f| f.contains("Wi-Fi-only outage")));

        let md = to_markdown(&rep);
        assert!(md.contains("obs\\|A lab"), "table cell should escape pipe and newline:\n{md}");
    }
}
