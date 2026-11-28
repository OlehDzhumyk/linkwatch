//! Stage `context`: what happened around each episode, and the session-wide lists of notices.
//!
//! [`annotate`] adds context notes to every episode: events of its interface, other Wi-Fi paths
//! that stayed up, a speed test nearby, a signal drop, a busy channel, router log lines and busy
//! LAN devices. [`notices`] builds the router log matches, the monitor gaps and the security
//! events of the report.

use super::super::engine::{IfAcc, med64};
use super::super::*;
use super::episodes::Tracked;
use super::windows::*;

/// A signal this far below the interface median (dB) is a drop worth a note.
/// Engineering estimate: about the step between "good" and "fair" Wi-Fi.
const SIGNAL_DROP_DB: f64 = 8.0;
/// A busy channel needs this many points above the median (and at least [`BUSY_MIN_PCT`]) for a note.
/// Engineering estimate: a short burst of other traffic is normal; this much is interference.
const BUSY_JUMP_PCT: f64 = 25.0;
/// A busy channel below this share never gets a note.
const BUSY_MIN_PCT: f64 = 60.0;
/// LAN devices active near an episode need this many more than the median (and [`LAN_JUMP_RATIO`] times).
/// Engineering estimate: a few devices more or less is the normal wobble of a home LAN.
const LAN_JUMP_ABS: f64 = 5.0;
const LAN_JUMP_RATIO: f64 = 1.5;
/// A LAN median needs at least this many samples.
/// Engineering estimate: fewer samples are one scan, not a baseline.
const LAN_BASELINE_MIN_SAMPLES: usize = 4;
/// A monitor restart gap longer than this (s) is listed as a gap.
/// Engineering estimate: shorter gaps are a normal service restart.
pub(super) const START_GAP_MIN_S: f64 = 5.0;

/// Everything outside the episodes that the notes need.
pub(in crate::analyze) struct ContextInput<'a> {
    /// Time-sorted events.
    pub events: &'a [(DateTime<Utc>, EventKind)],
    pub ifs: &'a BTreeMap<String, IfAcc>,
    pub speedtests: &'a [(DateTime<Utc>, String)],
    pub router_log: &'a [RouterLine],
    pub lan_samples: &'a [(DateTime<Utc>, LanSample)],
    /// Context window around an episode (s).
    pub context_s: i64,
}

/// Session-wide lists for the report.
#[derive(Debug, Default)]
pub(in crate::analyze) struct Notices {
    pub router_log_matches: Vec<String>,
    pub monitor_gaps: Vec<String>,
    pub security_events: Vec<String>,
}

/// Add the context notes to every episode.
pub(in crate::analyze) fn annotate(episodes: &mut [Tracked], inp: &ContextInput) {
    let lan_med = lan_baseline(inp.lan_samples);
    let notes: Vec<Vec<Msg>> = episodes.iter().map(|(ep, _)| episode_notes(ep, episodes, inp, lan_med)).collect();
    for ((ep, _), list) in episodes.iter_mut().zip(notes) {
        for m in list {
            ep.note(m);
        }
    }
}

/// Median number of active LAN devices over the session, when there are enough samples.
fn lan_baseline(samples: &[(DateTime<Utc>, LanSample)]) -> Option<f64> {
    (samples.len() >= LAN_BASELINE_MIN_SAMPLES)
        .then(|| med64(&mut samples.iter().map(|(_, l)| f64::from(l.arp_alive)).collect::<Vec<_>>()))
        .flatten()
}

/// The notes for one episode. `all` is the whole episode list (for the other-path notes).
fn episode_notes(ep: &Episode, all: &[Tracked], inp: &ContextInput, lan_med: Option<f64>) -> Vec<Msg> {
    let mut out = Vec::new();
    let w0 = ep.start - Duration::seconds(inp.context_s);
    let w1 = ep.end + Duration::seconds(inp.context_s);
    for (t, ev) in in_window(inp.events, w0, w1) {
        out.extend(event_note(ep, *t, ev));
    }
    if ep.role == IfaceRole::Wifi {
        out.extend(other_wifi_notes(ep, all, inp.ifs));
    }
    if inp.speedtests.iter().any(|(t, _)| *t >= w0 - Duration::seconds(SPEEDTEST_LEAD_S) && *t <= w1) {
        out.push(crate::msg!("c_speedtest", "speed test running nearby"));
    }
    if let Some(a) = inp.ifs.get(&ep.iface) {
        out.extend(signal_note(a, w0, w1));
        out.extend(busy_note(a, w0, w1));
    }
    for r in inp.router_log.iter().filter(|r| r.ts >= w0 - Duration::seconds(ROUTER_LOG_WINDOW_S) && r.ts <= w1 + Duration::seconds(ROUTER_LOG_WINDOW_S)) {
        out.push(crate::msg!("c_router_log", "router log: {prio} {line}", prio = r.priority, line = r.text));
    }
    out.extend(lan_note(ep, inp.lan_samples, lan_med));
    out
}

/// The note for one event near the episode; `None` when the event is not about it.
fn event_note(ep: &Episode, t: DateTime<Utc>, ev: &EventKind) -> Option<Msg> {
    let at = t.with_timezone(&Local).format("%H:%M:%S").to_string();
    match ev {
        EventKind::Roam { iface, from_bssid, to_bssid } if *iface == ep.iface => Some(crate::msg!("c_roam", "{at} roamed {from} → {to}",
            at = at, from = from_bssid.as_deref().unwrap_or("?"), to = to_bssid.as_deref().unwrap_or("?"))),
        EventKind::Reconnect { iface, .. } if *iface == ep.iface => Some(crate::msg!("c_reconnect", "{at} Wi-Fi re-associated to the same AP", at = at)),
        EventKind::WifiDisconnect { iface, reason_code, reason, by_ap, timed_out, .. } if *iface == ep.iface => {
            let code = reason_code.map_or_else(|| "?".into(), |c| c.to_string());
            let reason = reason.as_deref().unwrap_or("unknown");
            Some(match (*by_ap, *timed_out) {
                (Some(true), _) => crate::msg!("c_disc_ap", "{at} Wi-Fi disconnect (reason {code} {reason}, by AP)", at = at, code = code, reason = reason),
                (Some(false), _) => crate::msg!("c_disc_client", "{at} Wi-Fi disconnect (reason {code} {reason}, by client)", at = at, code = code, reason = reason),
                (None, true) => crate::msg!("c_disc_timeout", "{at} Wi-Fi disconnect (reason {code} {reason}, timed out)", at = at, code = code, reason = reason),
                (None, false) => crate::msg!("c_disc_unknown", "{at} Wi-Fi disconnect (reason {code} {reason}, unknown initiator)", at = at, code = code, reason = reason),
            })
        }
        EventKind::ChannelChange { iface, from_mhz, to_mhz } if *iface == ep.iface => Some(crate::msg!("c_channel", "{at} channel changed {from} → {to} MHz",
            at = at, from = from_mhz.map_or_else(|| "?".into(), |f| f.to_string()), to = to_mhz.map_or_else(|| "?".into(), |f| f.to_string()))),
        EventKind::LinkChange { iface, from, to } if *iface == ep.iface => Some(crate::msg!("c_link", "{at} link change: carrier {c1}→{c2}, ip {ip1}→{ip2}",
            at = at, c1 = from.carrier, c2 = to.carrier, ip1 = from.ipv4.map_or("-".into(), |a| a.to_string()), ip2 = to.ipv4.map_or("-".into(), |a| a.to_string()))),
        EventKind::SuspendGap { secs } => Some(crate::msg!("c_suspend", "{at} monitor host suspended {s}s", at = at, s = format!("{secs:.0}"))),
        EventKind::ClockJump { wall_delta_s, .. } => Some(crate::msg!("c_clock", "{at} clock jump {s}s", at = at, s = format!("{wall_delta_s:.0}"))),
        EventKind::HostAlert { alert, detail, .. } => Some(crate::msg!("c_host", "{at} host alert ({alert}): {detail}", at = at, alert = alert.as_str(), detail = detail)),
        _ => None,
    }
}

/// Other Wi-Fi interfaces that had link and did not fail while this one did.
fn other_wifi_notes(ep: &Episode, all: &[Tracked], ifs: &BTreeMap<String, IfAcc>) -> Vec<Msg> {
    let mut out = Vec::new();
    for (other_if, oa) in ifs {
        if *other_if != ep.iface
            && oa.role == Some(IfaceRole::Wifi)
            && oa.ticks > 0
            && !oa.no_link.iter().any(|(s, e)| *s < ep.end && ep.start < *e)
            && !all.iter().any(|(o, _)| o.iface == *other_if && o.start < ep.end && ep.start < o.end)
        {
            let b = if oa.bands.is_empty() {
                "unknown band".to_string()
            } else {
                oa.bands.keys().cloned().collect::<Vec<_>>().join("/")
            };
            out.push(crate::msg!("c_other_wifi", "other Wi-Fi {other} ({band}) was OK", other = other_if, band = b));
        }
    }
    out
}

/// The signal fell well below its usual level around the episode.
fn signal_note(a: &IfAcc, w0: DateTime<Utc>, w1: DateTime<Utc>) -> Option<Msg> {
    let near: Vec<i32> = in_window(&a.signal, w0, w1).iter().map(|(_, s)| *s).collect();
    let mut all: Vec<f64> = a.signal.iter().map(|(_, s)| *s as f64).collect();
    let (Some(min), Some(base)) = (near.iter().min(), med64(&mut all)) else { return None };
    ((*min as f64) < base - SIGNAL_DROP_DB).then(|| crate::msg!("c_signal", "signal dropped to {min} dBm (usual {base})", min = min, base = format!("{base:.0}")))
}

/// The channel was much busier than usual around the episode.
fn busy_note(a: &IfAcc, w0: DateTime<Utc>, w1: DateTime<Utc>) -> Option<Msg> {
    let busy: Vec<f64> = in_window(&a.busy, w0, w1).iter().map(|(_, b)| *b).collect();
    let mut ball: Vec<f64> = a.busy.iter().map(|(_, b)| *b).collect();
    let (Some(mx), Some(base)) = (busy.iter().cloned().fold(None, |m: Option<f64>, x| Some(m.map_or(x, |m| m.max(x)))), med64(&mut ball)) else { return None };
    (mx > (base + BUSY_JUMP_PCT).max(BUSY_MIN_PCT)).then(|| crate::msg!("c_busy", "channel busy {mx}% (usual {base}%)", mx = format!("{mx:.0}"), base = format!("{base:.0}")))
}

/// More LAN devices than usual were active around the episode.
fn lan_note(ep: &Episode, samples: &[(DateTime<Utc>, LanSample)], lan_med: Option<f64>) -> Option<Msg> {
    let base = lan_med?;
    let (_, l) = samples
        .iter()
        .filter(|(t, _)| *t >= ep.start - Duration::seconds(LAN_WINDOW_S) && *t <= ep.end + Duration::seconds(LAN_WINDOW_S))
        .max_by_key(|(_, l)| l.arp_alive)?;
    (f64::from(l.arp_alive) >= (base + LAN_JUMP_ABS).max(base * LAN_JUMP_RATIO))
        .then(|| crate::msg!("c_lan", "LAN devices active: {n} (usual {base})", n = l.arp_alive, base = format!("{base:.0}")))
}

/// Router log lines vs episodes, monitor gaps (restarts, suspend) and security events.
pub(in crate::analyze) fn notices(episodes: &[Tracked], events: &[(DateTime<Utc>, EventKind)], router_log: &[RouterLine]) -> Notices {
    let mut out = Notices { router_log_matches: router_log_matches(episodes, router_log), ..Default::default() };
    let day = |t: &DateTime<Utc>| t.with_timezone(&Local).format("%m-%d %H:%M");
    for (t, ev) in events {
        match ev {
            EventKind::Start { gap_s: Some(g), .. } if *g > START_GAP_MIN_S => out.monitor_gaps.push(format!("{} monitor was not running for {:.0}s", day(t), g)),
            EventKind::SuspendGap { secs } => out.monitor_gaps.push(format!("{} host suspended {:.0}s", day(t), secs)),
            EventKind::TaskRestart { task, error } => out.monitor_gaps.push(format!("{} task {task} restarted: {error}", day(t))),
            EventKind::DroppedRecords { count } => out.monitor_gaps.push(format!("{} {count} records dropped", day(t))),
            EventKind::Security { detector, severity, iface, detail } => {
                let who = iface.as_deref().unwrap_or("-");
                out.security_events.push(format!("{} [{severity}] {detector} ({who}): {detail}", t.with_timezone(&Local).format("%m-%d %H:%M:%S")));
            }
            _ => {}
        }
    }
    out
}

fn router_log_matches(episodes: &[Tracked], router_log: &[RouterLine]) -> Vec<String> {
    router_log
        .iter()
        .map(|r| {
            let hit = episodes
                .iter()
                .map(|(e, _)| e)
                .find(|e| r.ts >= e.start - Duration::seconds(ROUTER_LOG_WINDOW_S) && r.ts <= e.end + Duration::seconds(ROUTER_LOG_WINDOW_S));
            format!(
                "{} {} {} -> {}",
                r.ts.with_timezone(&Local).format("%m-%d %H:%M:%S"),
                r.priority,
                r.text,
                match hit {
                    Some(e) => format!("matches {} episode at {}", e.iface, e.start.with_timezone(&Local).format("%H:%M:%S")),
                    None => "no outage seen by linkwatch".into(),
                }
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{episode, t0, tracked};
    use super::*;

    fn at(s: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(s)
    }

    fn codes(ep: &Episode) -> Vec<&str> {
        ep.context_msg.iter().map(|m| m.code.as_str()).collect()
    }

    /// Annotate one Wi-Fi episode at t0+1000 (8 s) with the given inputs.
    fn annotated(events: Vec<(DateTime<Utc>, EventKind)>, ifs: BTreeMap<String, IfAcc>, speedtests: Vec<(DateTime<Utc>, String)>, router_log: Vec<RouterLine>) -> Episode {
        let mut eps = vec![tracked(episode("wlo1", IfaceRole::Wifi, 1000, 8, PathState::LanDown))];
        let inp = ContextInput { events: &events, ifs: &ifs, speedtests: &speedtests, router_log: &router_log, lan_samples: &[], context_s: 60 };
        annotate(&mut eps, &inp);
        eps.remove(0).0
    }

    #[test]
    fn events_of_this_interface_and_of_the_host_become_notes() {
        let ev = vec![
            (at(990), EventKind::Roam { iface: "wlo1".into(), from_bssid: Some("aa".into()), to_bssid: None }),
            (at(995), EventKind::Roam { iface: "wlan1".into(), from_bssid: None, to_bssid: None }),
            (at(1001), EventKind::SuspendGap { secs: 12.0 }),
            (at(1002), EventKind::HostAlert { alert: HostAlertKind::LowMemory, detail: "mem 97%".into(), iface: None }),
            (at(2000), EventKind::ClockJump { wall_delta_s: 3.0, mono_delta_s: 0.0 }),
        ];
        let ep = annotated(ev, BTreeMap::new(), vec![], vec![]);
        assert_eq!(codes(&ep), ["c_roam", "c_suspend", "c_host"], "other interface and far events are skipped");
        assert!(ep.context[0].ends_with("roamed aa → ?"), "{:?}", ep.context);
        assert_eq!(ep.context.len(), ep.context_msg.len(), "text and message stay in step");
    }

    #[test]
    fn disconnect_note_names_the_initiator() {
        let disc = |by_ap: Option<bool>, timed_out: bool| EventKind::WifiDisconnect { iface: "wlo1".into(), bssid: None, reason_code: Some(3), reason: None, by_ap, timed_out };
        let code = |by_ap, timed_out| {
            let ep = annotated(vec![(at(1000), disc(by_ap, timed_out))], BTreeMap::new(), vec![], vec![]);
            ep.context_msg[0].code.clone()
        };
        assert_eq!(code(Some(true), false), "c_disc_ap");
        assert_eq!(code(Some(false), false), "c_disc_client");
        assert_eq!(code(None, true), "c_disc_timeout");
        assert_eq!(code(None, false), "c_disc_unknown");
    }

    #[test]
    fn speed_test_note_counts_a_test_that_started_shortly_before_the_window() {
        let near = annotated(vec![], BTreeMap::new(), vec![(at(1000 - 60 - SPEEDTEST_LEAD_S), "wlo1".into())], vec![]);
        assert_eq!(codes(&near), ["c_speedtest"]);
        let far = annotated(vec![], BTreeMap::new(), vec![(at(1000 - 60 - SPEEDTEST_LEAD_S - 1), "wlo1".into())], vec![]);
        assert!(codes(&far).is_empty());
    }

    #[test]
    fn signal_drop_and_busy_channel_need_a_clear_departure_from_the_usual() {
        // Usual -60 dBm; -75 dBm near the episode. Usual busy 20 %; 90 % near the episode.
        let a = IfAcc {
            signal: (0..20).map(|i| (at(i * 10), -60)).chain([(at(1004), -75)]).collect(),
            busy: (0..20).map(|i| (at(i * 10), 20.0)).chain([(at(1004), 90.0)]).collect(),
            ..Default::default()
        };
        let ifs = BTreeMap::from([("wlo1".to_string(), a)]);
        let ep = annotated(vec![], ifs, vec![], vec![]);
        assert_eq!(codes(&ep), ["c_signal", "c_busy"]);
        assert!(ep.context[0].contains("-75"));

        let calm = IfAcc {
            signal: (0..20).map(|i| (at(i * 10), -60)).chain([(at(1004), -66)]).collect(),
            busy: (0..20).map(|i| (at(i * 10), 20.0)).chain([(at(1004), 50.0)]).collect(),
            ..Default::default()
        };
        let ep = annotated(vec![], BTreeMap::from([("wlo1".to_string(), calm)]), vec![], vec![]);
        assert!(codes(&ep).is_empty(), "6 dB and 50 % busy are inside the normal wobble: {:?}", ep.context);
    }

    #[test]
    fn other_wifi_that_stayed_up_is_noted_with_its_bands() {
        let mut other = IfAcc { role: Some(IfaceRole::Wifi), ticks: 100, ..Default::default() };
        other.bands.insert("5 GHz".into(), Default::default());
        let eth = IfAcc { role: Some(IfaceRole::Ethernet), ticks: 100, ..Default::default() };
        let ifs = BTreeMap::from([("wlan1".to_string(), other), ("eth0".to_string(), eth)]);
        let ep = annotated(vec![], ifs, vec![], vec![]);
        assert_eq!(codes(&ep), ["c_other_wifi"], "a wired path is not a Wi-Fi witness");
        assert!(ep.context[0].contains("wlan1 (5 GHz)"), "{:?}", ep.context);
    }

    #[test]
    fn router_log_line_near_the_episode_is_a_note_and_a_match() {
        let line = |s: i64| RouterLine { ts: at(s), priority: "Critical".into(), text: "SYNC Timing Synchronization failure".into() };
        let ep = annotated(vec![], BTreeMap::new(), vec![], vec![line(1000 + 60 + ROUTER_LOG_WINDOW_S), line(5000)]);
        assert_eq!(codes(&ep), ["c_router_log"]);

        let eps = [tracked(episode("wlo1", IfaceRole::Wifi, 1000, 8, PathState::LanDown))];
        let m = router_log_matches(&eps, &[line(1010), line(5000)]);
        assert!(m[0].contains("matches wlo1 episode at"), "{}", m[0]);
        assert!(m[1].ends_with("no outage seen by linkwatch"), "{}", m[1]);
    }

    #[test]
    fn lan_devices_note_needs_a_baseline_and_a_clear_jump() {
        let ls = |s: i64, arp: u32| (at(s), LanSample { arp_alive: arp, ..Default::default() });
        let mut samples: Vec<_> = (0..6).map(|i| ls(i * 100, 10)).collect();
        samples.push(ls(1004, 40));
        samples.sort_by_key(|(t, _)| *t);
        let base = lan_baseline(&samples);
        assert_eq!(base, Some(10.0));
        let ep = episode("wlo1", IfaceRole::Wifi, 1000, 8, PathState::LanDown);
        assert!(lan_note(&ep, &samples, base).expect("note").text.contains("40"));
        assert!(lan_note(&ep, &samples[..3], lan_baseline(&samples[..3])).is_none(), "three samples are no baseline");
    }

    #[test]
    fn notices_list_gaps_restarts_drops_and_security_events() {
        let start = |g: Option<f64>| EventKind::Start { version: "x".into(), gap_s: g, boot_id: "b".into(), prev_boot_id: None };
        let events = [
            (at(0), start(Some(3.0))),
            (at(10), start(Some(90.0))),
            (at(20), EventKind::SuspendGap { secs: 30.0 }),
            (at(30), EventKind::TaskRestart { task: "wifi".into(), error: "boom".into() }),
            (at(40), EventKind::DroppedRecords { count: 7 }),
            (at(50), EventKind::Security { detector: "arp".into(), severity: "warn".into(), iface: None, detail: "new gateway MAC".into() }),
        ];
        let n = notices(&[], &events, &[]);
        assert_eq!(n.monitor_gaps.len(), 4, "a 3 s restart gap is not listed: {:?}", n.monitor_gaps);
        assert!(n.monitor_gaps[0].ends_with("monitor was not running for 90s"));
        assert!(n.monitor_gaps[1].ends_with("host suspended 30s"));
        assert!(n.monitor_gaps[2].ends_with("task wifi restarted: boom"));
        assert!(n.monitor_gaps[3].ends_with("7 records dropped"));
        assert_eq!(n.security_events.len(), 1);
        assert!(n.security_events[0].ends_with("[warn] arp (-): new gateway MAC"));
        assert!(n.router_log_matches.is_empty());
    }
}
