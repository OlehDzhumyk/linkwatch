//! Stage `observer`: how far can the measuring host be trusted?
//!
//! [`assess`] gives the observer findings (plain facts about the host) and the Observer Trust
//! level (`clean`, `caution`, `polluted`) with every reason as a translatable message.

use super::super::engine::{HostAcc, IfAcc};
use super::super::*;
use super::masking::POWER_SAVE_BLIND_PCT;

/// Host CPU at or above this share (%) is worth a finding and a caution.
/// Engineering estimate: a probe loop that has less than 15 % of a core free starts to run late.
const CPU_ALERT_PCT: f64 = 85.0;
/// Host temperature at or above this (°C) is worth a finding.
/// Engineering estimate: a Raspberry Pi starts to throttle at 80 °C; 75 °C is the warning.
const TEMP_ALERT_C: f64 = 75.0;
/// Own heavy traffic for at least this long (s) on one interface is worth a finding and a caution.
/// Engineering estimate: shorter bursts are one download, not a pattern.
const SELF_TRAFFIC_MIN_S: f64 = 60.0;
/// This share (%) of late ticks or more makes the observer polluted.
/// Engineering estimate: one late tick in a hundred already hides short outages.
const OVERRUN_POLLUTED_PCT: f64 = 1.0;
/// This share (%) of late ticks or more is a caution.
const OVERRUN_CAUTION_PCT: f64 = 0.1;
/// Throttled samples at this share of all host samples or more make the observer polluted.
const THROTTLED_POLLUTED_SHARE: f64 = 0.1;

/// What the observer assessment needs from the earlier stages.
pub(in crate::analyze) struct ObserverInput<'a> {
    pub host: &'a HostAcc,
    /// Per-interface totals (stage `iface_report`).
    pub ifaces: &'a [IfaceReport],
    pub observer_incidents: u32,
    /// Late ticks in percent of all ticks (worst interface).
    pub overrun_pct: f64,
    /// Thresholds from the options, named in the self-traffic finding.
    pub self_traffic_bps: f64,
    pub self_traffic_pps: f64,
}

pub(in crate::analyze) struct Observer {
    pub findings: Vec<Msg>,
    pub trust: ObserverTrust,
}

pub(in crate::analyze) fn assess(inp: &ObserverInput) -> Observer {
    let host = inp.host;
    let trust = observer_trust(&TrustInputs {
        power_save_ifaces: host.power_save_ifaces.iter().cloned().collect(),
        power_save_pct: (host.power_save_known > 0).then(|| host.power_save_on as f64 * 100.0 / host.power_save_known as f64),
        overrun_pct: inp.overrun_pct,
        throttled_samples: host.throttled_at.len() as u64,
        host_samples: host.samples,
        clock_unsynced: host.clock_unsynced,
        self_traffic_s: inp.ifaces.iter().map(|i| i.self_traffic_s).fold(0.0, f64::max),
        observer_incidents: inp.observer_incidents,
        max_cpu: host.max_cpu,
    });
    Observer { findings: findings(inp), trust }
}

/// Late ticks in percent of all ticks, for the worst interface.
pub(in crate::analyze) fn overrun_pct(ifs: &BTreeMap<String, IfAcc>) -> f64 {
    ifs.values().filter(|a| a.ticks > 0).map(|a| a.overrun_ticks as f64 * 100.0 / a.ticks as f64).fold(0.0, f64::max)
}

fn findings(inp: &ObserverInput) -> Vec<Msg> {
    let host = inp.host;
    let mut out = Vec::new();
    if !host.power_save_ifaces.is_empty() {
        let names: Vec<_> = host.power_save_ifaces.iter().cloned().collect();
        out.push(crate::msg!("o_power_save", "Wi-Fi power-save was ON on {ifs} (can double RTT and add jitter; disable with `iw dev <if> set power_save off`)", ifs = names.join(", ")));
    }
    if host.clock_unsynced {
        out.push(crate::msg!("o_ntp", "Observer clock was not NTP-synchronized during part of the session; cross-device comparisons need care."));
    }
    if !host.throttled_at.is_empty() {
        out.push(crate::msg!("o_throttled", "Observer reported undervoltage or thermal throttling in {n} host samples.", n = host.throttled_at.len()));
    }
    if let Some(c) = host.max_cpu
        && c >= CPU_ALERT_PCT
    {
        out.push(crate::msg!("o_cpu", "Observer CPU peaked at {v}%.", v = format!("{c:.0}")));
    }
    if let Some(t) = host.max_temp
        && t >= TEMP_ALERT_C
    {
        out.push(crate::msg!("o_temp", "Observer temperature peaked at {v}°C.", v = format!("{t:.1}")));
    }
    let busy: Vec<String> = inp
        .ifaces
        .iter()
        .filter(|i| i.self_traffic_s >= SELF_TRAFFIC_MIN_S)
        .map(|i| format!("{} ({:.0} min)", i.iface, i.self_traffic_s / 60.0))
        .collect();
    if !busy.is_empty() {
        out.push(crate::msg!(
            "o_self_traffic",
            "The observer's own traffic was above {mbps} Mbit/s or {pps} packets/s outside speed tests on {ifs}; stalls and short drops in that time are not counted as network faults.",
            mbps = format!("{:.0}", inp.self_traffic_bps / 1e6),
            pps = format!("{:.0}", inp.self_traffic_pps),
            ifs = busy.join(", "),
        ));
    }
    if inp.observer_incidents > 0 {
        out.push(crate::msg!("o_incidents", "{n} incident(s) attributed to the observer device (scan/overrun/suspend/throttling) and excluded from network totals.", n = inp.observer_incidents));
    }
    out
}

/// What [`observer_trust`] needs from a finished analysis.
#[derive(Debug, Default, Clone)]
pub(in crate::analyze) struct TrustInputs {
    pub power_save_ifaces: Vec<String>,
    /// Share of power-save readings that were "on" (percent); `None` when unknown.
    pub power_save_pct: Option<f64>,
    /// Late ticks in percent of all ticks (worst interface).
    pub overrun_pct: f64,
    pub throttled_samples: u64,
    pub host_samples: u64,
    pub clock_unsynced: bool,
    /// Seconds of the host's own heavy traffic (worst interface).
    pub self_traffic_s: f64,
    pub observer_incidents: u32,
    pub max_cpu: Option<f64>,
}

/// Observer Trust Score: `polluted` when the host distorted much of the run, `caution` for
/// short host effects, `clean` otherwise. Every reason is a translatable message.
pub(in crate::analyze) fn observer_trust(i: &TrustInputs) -> ObserverTrust {
    let mut polluted = Vec::new();
    let mut caution = Vec::new();
    if !i.power_save_ifaces.is_empty() {
        let m = crate::msg!("t_power_save", "Wi-Fi power-save was on ({ifs}) during the run: RTT and jitter are inflated.", ifs = i.power_save_ifaces.join(", "));
        // Same tolerance as the session blind (masking M4): a short power-save spell is a
        // caution, not a polluted observer.
        if i.power_save_pct.is_none_or(|p| p >= POWER_SAVE_BLIND_PCT) { polluted.push(m) } else { caution.push(m) }
    }
    let pct = format!("{:.1}", i.overrun_pct);
    if i.overrun_pct >= OVERRUN_POLLUTED_PCT {
        polluted.push(crate::msg!("t_overrun", "{pct}% of probe ticks were late (host CPU or disk stalls).", pct = pct));
    } else if i.overrun_pct >= OVERRUN_CAUTION_PCT {
        caution.push(crate::msg!("t_overrun", "{pct}% of probe ticks were late (host CPU or disk stalls).", pct = pct));
    }
    if i.throttled_samples > 0 {
        let share = i.throttled_samples as f64 / i.host_samples.max(1) as f64;
        let m = crate::msg!("t_throttled", "Undervoltage or thermal throttling in {n} host sample(s).", n = i.throttled_samples);
        if share >= THROTTLED_POLLUTED_SHARE { polluted.push(m) } else { caution.push(m) }
    }
    if i.clock_unsynced {
        caution.push(crate::msg!("t_ntp", "The clock was not NTP-synchronized for part of the run: compare times with other devices with care."));
    }
    if i.self_traffic_s >= SELF_TRAFFIC_MIN_S {
        caution.push(crate::msg!("t_self_traffic", "The host's own traffic was heavy for {min} min; stalls in that time are excluded.", min = format!("{:.0}", i.self_traffic_s / 60.0)));
    }
    if i.observer_incidents > 0 {
        caution.push(crate::msg!("t_observer_incidents", "{n} incident(s) were caused by the measuring device and are excluded.", n = i.observer_incidents));
    }
    if let Some(c) = i.max_cpu.filter(|c| *c >= CPU_ALERT_PCT) {
        caution.push(crate::msg!("t_cpu", "Host CPU peaked at {v}%.", v = format!("{c:.0}")));
    }
    let level = if !polluted.is_empty() {
        TrustLevel::Polluted
    } else if !caution.is_empty() {
        TrustLevel::Caution
    } else {
        TrustLevel::Clean
    };
    polluted.extend(caution);
    ObserverTrust { level, reasons: polluted }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(host: &'a HostAcc, ifaces: &'a [IfaceReport]) -> ObserverInput<'a> {
        ObserverInput { host, ifaces, observer_incidents: 0, overrun_pct: 0.0, self_traffic_bps: 10e6, self_traffic_pps: 2000.0 }
    }

    fn codes(m: &[Msg]) -> Vec<&str> {
        m.iter().map(|m| m.code.as_str()).collect()
    }

    #[test]
    fn a_quiet_host_has_no_findings_and_a_clean_trust() {
        let host = HostAcc { samples: 50, ..Default::default() };
        let o = assess(&input(&host, &[]));
        assert!(o.findings.is_empty());
        assert_eq!(o.trust.level, TrustLevel::Clean);
    }

    #[test]
    fn findings_follow_the_host_facts_in_a_fixed_order() {
        let mut host = HostAcc { samples: 10, clock_unsynced: true, max_cpu: Some(90.0), max_temp: Some(74.9), ..Default::default() };
        host.power_save_ifaces.insert("wlo1".into());
        host.throttled_at.push(DateTime::from_timestamp(1_800_000_000, 0).unwrap());
        let busy = IfaceReport { iface: "wlo1".into(), self_traffic_s: 120.0, ..Default::default() };
        let idle = IfaceReport { iface: "eth0".into(), self_traffic_s: 59.0, ..Default::default() };
        let ifaces = [busy, idle];
        let inp = ObserverInput { observer_incidents: 2, ..input(&host, &ifaces) };
        let o = assess(&inp);
        assert_eq!(codes(&o.findings), ["o_power_save", "o_ntp", "o_throttled", "o_cpu", "o_self_traffic", "o_incidents"], "74.9 °C is below the temperature alert");
        let st = o.findings.iter().find(|m| m.code == "o_self_traffic").expect("finding");
        assert!(st.text.contains("10 Mbit/s") && st.text.contains("2000 packets/s") && st.text.contains("wlo1 (2 min)"), "{}", st.text);
        assert!(!st.text.contains("eth0"));
    }

    #[test]
    fn trust_is_polluted_for_long_power_save_and_caution_for_a_short_one() {
        let base = TrustInputs { power_save_ifaces: vec!["wlo1".into()], host_samples: 100, ..Default::default() };
        assert_eq!(observer_trust(&TrustInputs { power_save_pct: Some(4.9), ..base.clone() }).level, TrustLevel::Caution);
        assert_eq!(observer_trust(&TrustInputs { power_save_pct: Some(5.0), ..base.clone() }).level, TrustLevel::Polluted);
        assert_eq!(observer_trust(&base).level, TrustLevel::Polluted, "unknown share counts as long");
    }

    #[test]
    fn late_ticks_and_throttling_have_two_levels() {
        let level = |i: TrustInputs| observer_trust(&i).level;
        assert_eq!(level(TrustInputs { overrun_pct: 0.09, ..Default::default() }), TrustLevel::Clean);
        assert_eq!(level(TrustInputs { overrun_pct: 0.1, ..Default::default() }), TrustLevel::Caution);
        assert_eq!(level(TrustInputs { overrun_pct: 1.0, ..Default::default() }), TrustLevel::Polluted);
        assert_eq!(level(TrustInputs { throttled_samples: 9, host_samples: 100, ..Default::default() }), TrustLevel::Caution);
        assert_eq!(level(TrustInputs { throttled_samples: 10, host_samples: 100, ..Default::default() }), TrustLevel::Polluted);
    }

    #[test]
    fn reasons_list_the_serious_ones_first() {
        let t = observer_trust(&TrustInputs { clock_unsynced: true, overrun_pct: 2.0, ..Default::default() });
        assert_eq!(codes(&t.reasons), ["t_overrun", "t_ntp"]);
    }

    #[test]
    fn overrun_is_the_share_of_the_worst_interface() {
        let mut ifs = BTreeMap::new();
        ifs.insert("a".to_string(), IfAcc { ticks: 1000, overrun_ticks: 5, ..Default::default() });
        ifs.insert("b".to_string(), IfAcc { ticks: 100, overrun_ticks: 2, ..Default::default() });
        ifs.insert("c".to_string(), IfAcc { ticks: 0, overrun_ticks: 9, ..Default::default() });
        assert!((overrun_pct(&ifs) - 2.0).abs() < 1e-9);
        assert_eq!(overrun_pct(&BTreeMap::new()), 0.0);
    }
}
