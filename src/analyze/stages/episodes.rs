//! Stage `episodes`: bad ticks become episodes.
//!
//! The streaming half ([`OpenEp`]) collects the bad ticks of one interface while samples arrive.
//! The finishing half ([`finalize`]) closes the episodes that are still open, backfills the
//! Wi-Fi band from the Wi-Fi stream and sorts the list by start time.

use super::super::engine::IfAcc;
use super::super::*;
use super::windows::BAND_BACKFILL_S;

/// An episode with the per-episode counters that the later stages need.
pub(in crate::analyze) type Tracked = (Episode, EpFlags);

/// The open episode of one interface: counters of its bad ticks so far.
#[derive(Default)]
pub(in crate::analyze) struct OpenEp {
    start: Option<DateTime<Utc>>,
    last_bad: Option<DateTime<Utc>>,
    ticks: u32,
    overrun_ticks: u32,
    /// Bad ticks per state, in the order the states first appeared.
    states: Vec<(PathState, u32)>,
    bands: BTreeMap<String, u32>,
    hour_ticks: [u32; 24],
    /// Bad ticks with that flag (dose for the attribution).
    scan: u32,
    speedtest: u32,
    self_traffic: u32,
}

/// What the stage needs to know about one bad tick.
pub(in crate::analyze) struct BadTick {
    pub state: PathState,
    pub hour: usize,
    /// Wi-Fi band of the tick, when known.
    pub band: Option<String>,
    pub overrun: bool,
    pub scan: bool,
    pub speedtest: bool,
    pub self_traffic: bool,
}

/// Counters of a closed episode that are not part of the public [`Episode`].
#[derive(Clone, Default)]
pub(in crate::analyze) struct EpFlags {
    pub scan: u32,
    pub speedtest: u32,
    pub self_traffic: u32,
    pub overrun_ticks: u32,
    pub bands: BTreeMap<String, u32>,
    pub hour_ticks: [u32; 24],
}

impl OpenEp {
    /// The last bad tick is more than `gap_s` seconds before `ts`: the episode is over.
    pub(in crate::analyze) fn is_stale(&self, ts: DateTime<Utc>, gap_s: i64) -> bool {
        self.last_bad.is_some_and(|lb| (ts - lb).num_seconds() > gap_s)
    }

    pub(in crate::analyze) fn add_bad_tick(&mut self, ts: DateTime<Utc>, t: BadTick) {
        self.start.get_or_insert(ts);
        self.last_bad = Some(ts);
        self.ticks += 1;
        self.overrun_ticks += u32::from(t.overrun);
        self.scan += u32::from(t.scan);
        self.speedtest += u32::from(t.speedtest);
        self.self_traffic += u32::from(t.self_traffic);
        self.hour_ticks[t.hour] += 1;
        if let Some(band) = t.band {
            *self.bands.entry(band).or_default() += 1;
        }
        match self.states.iter_mut().find(|(st, _)| *st == t.state) {
            Some((_, c)) => *c += 1,
            None => self.states.push((t.state, 1)),
        }
    }

    /// Close the episode (if any) and reset the accumulator.
    pub(in crate::analyze) fn close(&mut self, iface: &str, role: Option<IfaceRole>, tick: Duration, tick_s: f64) -> Option<Tracked> {
        let (Some(st), Some(lb)) = (self.start, self.last_bad) else { return None };
        let open = std::mem::take(self);
        let end_base = lb.max(st);
        let state = dominant_state(&open.states);
        let dom_band = open.bands.iter().max_by_key(|(_, c)| **c).map(|(k, _)| k.clone());
        let context = open_context(&open);
        let ep = Episode {
            iface: iface.to_string(),
            role: role.unwrap_or(IfaceRole::Other),
            start: st,
            end: end_base + tick,
            duration_s: (end_base - st).num_milliseconds().max(0) as f64 / 1000.0 + tick_s,
            ticks: open.ticks,
            state,
            cause: None,
            origin: IncidentOrigin::Unknown,
            band: dom_band,
            speedtest_active: false,
            context: texts(&context),
            context_msg: context,
            finding: Default::default(),
        };
        let flags = EpFlags {
            scan: open.scan,
            speedtest: open.speedtest,
            self_traffic: open.self_traffic,
            overrun_ticks: open.overrun_ticks,
            bands: open.bands,
            hour_ticks: open.hour_ticks,
        };
        Some((ep, flags))
    }
}

/// Notes that the monitor's own activity during the episode needs.
fn open_context(o: &OpenEp) -> Vec<Msg> {
    let mut v = vec![];
    if o.scan > 0 {
        v.push(crate::msg!("c_own_scan", "monitor's own Wi-Fi scan was running (off-channel)"));
    }
    if o.speedtest > 0 {
        v.push(crate::msg!("c_own_speed", "monitor's own speed test was running"));
    }
    v
}

/// Close the episodes that are still open at the end of the data, backfill the Wi-Fi band of
/// episodes whose samples carried no frequency, and sort by start time (stable).
pub(in crate::analyze) fn finalize(mut episodes: Vec<Tracked>, ifs: &mut BTreeMap<String, IfAcc>, tick: Duration, tick_s: f64) -> Vec<Tracked> {
    for (name, a) in ifs.iter_mut() {
        if let Some(ep) = a.open.close(name, a.role, tick, tick_s) {
            episodes.push(ep);
        }
    }
    backfill_bands(&mut episodes, ifs);
    episodes.sort_by_key(|(e, _)| e.start);
    episodes
}

/// Backfill Wi-Fi episode band from the Wi-Fi stream if samples lacked `freq_mhz`.
fn backfill_bands(episodes: &mut [Tracked], ifs: &BTreeMap<String, IfAcc>) {
    for (ep, _) in episodes.iter_mut() {
        if ep.role == IfaceRole::Wifi
            && ep.band.is_none()
            && let Some(a) = ifs.get(&ep.iface)
            && !a.wifi_freqs.is_empty()
        {
            let mid = ep.start + Duration::milliseconds((ep.end - ep.start).num_milliseconds() / 2);
            let best = a
                .wifi_freqs
                .iter()
                .map(|(t, f)| ((*t - mid).num_seconds().abs(), *f))
                .filter(|(dt, _)| *dt <= BAND_BACKFILL_S)
                .min_by_key(|(dt, _)| *dt);
            if let Some((_, f)) = best {
                // Do not add backfilled ticks to flags.bands: the sample stage never added them to a.bands[b].
                ep.band = Some(wifi_band(f).to_string());
            }
        }
    }
}

/// Share of an episode's bad ticks that a nearer failure needs to name the episode.
/// Engineering estimate: a router reboot shows the dead gateway first and then a long WAN
/// reconnect; the gateway part is the cause. A one-tick blip of a nearer state is not.
const NEAR_STATE_SHARE: f64 = 0.25;

/// The state that names an episode: the failure nearest to the user among the states with at
/// least [`NEAR_STATE_SHARE`] of the bad ticks (the most frequent state always qualifies).
/// A dead gateway also hides the line and the internet, so the nearer failure explains the rest.
pub(super) fn dominant_state(states: &[(PathState, u32)]) -> PathState {
    let total: u32 = states.iter().map(|(_, c)| c).sum();
    let max = states.iter().map(|(_, c)| *c).max().unwrap_or(0);
    states
        .iter()
        .filter(|(_, c)| *c == max || f64::from(*c) >= NEAR_STATE_SHARE * f64::from(total))
        .min_by_key(|(st, _)| nearness_rank(*st))
        .map(|(st, _)| *st)
        .unwrap_or(PathState::Unknown)
}

/// How close to the measuring device a failure is (lower = nearer).
fn nearness_rank(s: PathState) -> u8 {
    match s {
        PathState::LinkDown => 0,
        PathState::NoIp => 1,
        PathState::LanDown => 2,
        PathState::IspDown => 3,
        PathState::WanDown => 4,
        PathState::DnsDown => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::t0;
    use super::*;

    fn tick(state: PathState) -> BadTick {
        BadTick { state, hour: 3, band: None, overrun: false, scan: false, speedtest: false, self_traffic: false }
    }

    fn at(s: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(s)
    }

    #[test]
    fn most_frequent_state_names_the_episode() {
        // 9 WAN ticks and 1 LAN tick: the LAN share (10 %) is below the near-state share.
        assert_eq!(dominant_state(&[(PathState::WanDown, 9), (PathState::LanDown, 1)]), PathState::WanDown);
    }

    #[test]
    fn nearer_state_with_a_quarter_share_names_the_episode() {
        assert_eq!(dominant_state(&[(PathState::WanDown, 3), (PathState::LanDown, 1)]), PathState::LanDown);
        assert_eq!(dominant_state(&[(PathState::DnsDown, 5), (PathState::IspDown, 5)]), PathState::IspDown, "tie goes to the nearer failure");
        assert_eq!(dominant_state(&[]), PathState::Unknown);
    }

    #[test]
    fn closed_episode_ends_one_tick_after_the_last_bad_tick() {
        let mut o = OpenEp::default();
        for s in [10, 11, 12] {
            o.add_bad_tick(at(s), tick(PathState::LanDown));
        }
        assert!(!o.is_stale(at(15), 5), "3 s after the last bad tick is inside the gap");
        assert!(o.is_stale(at(18), 5));
        let (ep, flags) = o.close("eth0", Some(IfaceRole::Ethernet), Duration::seconds(1), 1.0).expect("episode");
        assert_eq!((ep.start, ep.end), (at(10), at(13)));
        assert!((ep.duration_s - 3.0).abs() < 1e-9);
        assert_eq!((ep.ticks, ep.state, ep.role), (3, PathState::LanDown, IfaceRole::Ethernet));
        assert_eq!(flags.hour_ticks[3], 3);
        // The accumulator is empty again.
        assert!(o.close("eth0", None, Duration::seconds(1), 1.0).is_none());
        assert!(!o.is_stale(at(1000), 5));
    }

    #[test]
    fn own_scan_and_speed_test_are_noted_in_the_episode() {
        let mut o = OpenEp::default();
        o.add_bad_tick(at(0), BadTick { scan: true, speedtest: true, band: Some("5 GHz".into()), ..tick(PathState::WanDown) });
        let (ep, flags) = o.close("wlo1", Some(IfaceRole::Wifi), Duration::seconds(1), 1.0).expect("episode");
        let codes: Vec<&str> = ep.context_msg.iter().map(|m| m.code.as_str()).collect();
        assert_eq!(codes, ["c_own_scan", "c_own_speed"]);
        assert_eq!(ep.context.len(), 2);
        assert_eq!((flags.scan, flags.speedtest), (1, 1));
        assert_eq!(ep.band.as_deref(), Some("5 GHz"));
    }

    #[test]
    fn open_episodes_are_closed_and_the_band_is_backfilled_from_the_wifi_stream() {
        let mut ifs: BTreeMap<String, IfAcc> = BTreeMap::new();
        let w = ifs.entry("wlo1".into()).or_default();
        w.role = Some(IfaceRole::Wifi);
        w.open.add_bad_tick(at(100), tick(PathState::WanDown));
        w.wifi_freqs.push((at(90), 5180));
        w.wifi_freqs.push((at(400), 2412)); // too far from the episode
        let e = ifs.entry("eth0".into()).or_default();
        e.role = Some(IfaceRole::Ethernet);
        e.open.add_bad_tick(at(50), tick(PathState::LanDown));
        let done = vec![super::super::fixtures::tracked(super::super::fixtures::episode("eth0", IfaceRole::Ethernet, 10, 2, PathState::LanDown))];
        let out = finalize(done, &mut ifs, Duration::seconds(1), 1.0);
        let order: Vec<(&str, i64)> = out.iter().map(|(e, _)| (e.iface.as_str(), (e.start - t0()).num_seconds())).collect();
        assert_eq!(order, [("eth0", 10), ("eth0", 50), ("wlo1", 100)], "sorted by start");
        let wifi = &out[2].0;
        assert_eq!(wifi.band.as_deref(), Some("5 GHz"));
        assert_eq!(out[1].0.band, None, "wired episodes get no band");
        assert!(ifs.get_mut("wlo1").expect("iface").open.close("wlo1", None, Duration::seconds(1), 1.0).is_none(), "open episode was reset");
    }
}
