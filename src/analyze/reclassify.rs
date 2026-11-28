//! Re-runs the live path classifier over recorded samples.
//!
//! A recorded `Sample` keeps the raw probe results and the `state` that the classifier of the
//! recording version computed. The analyzer reads that recorded `state`, so a classifier fix
//! never reaches old sessions. [`Reclassifier`] replays `classify::PathClassifier` per interface,
//! in envelope order, and replaces `state` with the current classifier's answer.
//! It is a streaming transform: it keeps a small state per interface and never buffers samples.
//!
//! What the replay mirrors from the live loop (`run/tick.rs`):
//! - one classifier per interface, new for each run (`Envelope::run`), so `gw_seen` restarts;
//! - the classifier settings come from the session `meta.config` (`classify` and
//!   `intervals.probe_ms`), else the defaults;
//! - the sample time is `Sample::t`, else the envelope time;
//! - DNS: the latest `dns` result of the interface is the DNS input. A failed result counts only
//!   after 2 consecutive failures; a lost query during a speed test or Wi-Fi scan is ignored; a
//!   lost carrier clears the DNS memory;
//! - the recorded `state` is the instantaneous state (`feed` result), as in the live loop.
//!
//! `isp_known` rule: it is true from the first sample in which the ISP hop answered, and then
//! stays true for the rest of the session (all interfaces, all runs). The rule is causal, so one
//! pass is enough. On a DOCSIS line the first hop never answers: `isp_known` stays false and an
//! internet outage is `wan_down`, not `isp_down`. A hop that answered once and fails later is
//! `isp_down`, also during a very long outage (a time window would hide that).

use crate::classify::PathClassifier;
use crate::config::Classify;
use crate::model::{Envelope, ProbeResult, Record, SessionMeta};
use std::collections::HashMap;

/// Classifier input of one interface that lives as long as one run.
struct IfaceState {
    classifier: PathClassifier,
    last_dns: Option<ProbeResult>,
    dns_fails: u32,
}

pub struct Reclassifier {
    cfg: Classify,
    run: Option<String>,
    ifaces: HashMap<String, IfaceState>,
    isp_known: bool,
}

/// Classify settings of a session: `meta.config.classify` with ticks resolved for
/// `meta.config.intervals.probe_ms`. Defaults when `meta` or the keys are missing or invalid.
pub fn classify_cfg(meta: Option<&SessionMeta>) -> Classify {
    let probe_ms = meta
        .and_then(|m| m.config.pointer("/intervals/probe_ms"))
        .and_then(|v| v.as_u64())
        .filter(|v| *v > 0)
        .unwrap_or(1000);
    let mut cfg = meta
        .and_then(|m| m.config.get("classify"))
        .and_then(|v| serde_json::from_value::<Classify>(v.clone()).ok())
        .unwrap_or_default();
    cfg.resolve(probe_ms);
    cfg
}

impl Reclassifier {
    pub fn new(cfg: Classify) -> Self {
        Self { cfg, run: None, ifaces: HashMap::new(), isp_known: false }
    }

    pub fn for_session(meta: Option<&SessionMeta>) -> Self {
        Self::new(classify_cfg(meta))
    }

    /// Replaces `state` of a sample record. Other records stay as they are.
    /// Call it in the order of the samples stream.
    pub fn apply(&mut self, env: &mut Envelope) {
        let ts = env.ts;
        let Record::Sample(s) = &mut env.rec else { return };
        if self.run.as_deref() != Some(env.run.as_str()) {
            // A new run starts its classifiers from nothing.
            self.run = Some(env.run.clone());
            self.ifaces.clear();
        }
        if s.isp.as_ref().is_some_and(|i| i.ok) {
            self.isp_known = true;
        }
        let at = s.t.unwrap_or(ts);
        let cfg = &self.cfg;
        let st = self.ifaces.entry(s.iface.clone()).or_insert_with(|| IfaceState {
            classifier: PathClassifier::new(cfg.clone(), at),
            last_dns: None,
            dns_fails: 0,
        });
        // Same rules as `run/tick.rs`: our own load can lose a DNS query, so it does not count.
        let own_activity = s.speedtest_active || s.scan_active;
        if let Some(d) = s.dns.as_ref().filter(|d| d.ok || !own_activity) {
            st.dns_fails = if d.ok { 0 } else { st.dns_fails + 1 };
            st.last_dns = Some(d.clone());
        }
        if !s.link.carrier {
            st.last_dns = None;
            st.dns_fails = 0;
        }
        let dns = match &st.last_dns {
            Some(d) if !d.ok && st.dns_fails < 2 => None,
            other => other.as_ref(),
        };
        let (inst, _) = st.classifier.feed(s, self.isp_known, dns, at);
        s.state = inst;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IfaceRole, LinkState, MultiResult, PathState, Sample};
    use std::net::Ipv4Addr;

    fn link_ok() -> LinkState {
        LinkState {
            present: true,
            up: true,
            carrier: true,
            ipv4: Some(Ipv4Addr::new(192, 168, 0, 5)),
            prefix_len: Some(24),
            gateway: Some(Ipv4Addr::new(192, 168, 0, 1)),
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// `gw` and `isp`: None = not probed, Some(ok).
    fn env(n: u64, gw: Option<bool>, isp: Option<bool>, net: u8, recorded: PathState) -> Envelope {
        let probe = |ok: bool| if ok { ProbeResult::ok(5.0) } else { ProbeResult::fail("timeout") };
        let s = Sample {
            iface: "eth0".into(),
            role: IfaceRole::Ethernet,
            link: link_ok(),
            gw: gw.map(probe),
            isp: isp.map(probe),
            net: MultiResult { ok: net, of: 3, rtt_ms: if net > 0 { Some(15.0) } else { None } },
            tcp: None,
            dns: None,
            rx_delta: 0,
            tx_delta: 0,
            state: recorded,
            speedtest_active: false,
            scan_active: false,
            overrun: false,
            t: None,
            freq_mhz: None,
            pkt_delta: None,
        };
        Envelope {
            v: 1,
            run: "r1".into(),
            seq: n,
            ts: chrono::DateTime::from_timestamp(1_800_000_000 + n as i64, 0).unwrap(),
            mono_ns: n * 1_000_000_000,
            rec: Record::Sample(s),
        }
    }

    fn state(e: &Envelope) -> PathState {
        match &e.rec {
            Record::Sample(s) => s.state,
            _ => panic!("not a sample"),
        }
    }

    fn run(rc: &mut Reclassifier, mut v: Vec<Envelope>) -> Vec<PathState> {
        v.iter_mut().for_each(|e| rc.apply(e));
        v.iter().map(state).collect()
    }

    #[test]
    fn isp_hop_that_never_answered_is_wan_down() {
        // DOCSIS: the first hop never answers. The old recording says isp_down.
        let mut v = Vec::new();
        for i in 0..5 {
            v.push(env(i, Some(true), Some(false), 3, PathState::Ok));
        }
        for i in 5..10 {
            v.push(env(i, Some(true), Some(false), 0, PathState::IspDown));
        }
        let mut rc = Reclassifier::new(Classify { debounce_ticks: 3, window_ticks: 10, ..Classify::default() });
        let out = run(&mut rc, v);
        assert!(out[5..].iter().all(|s| *s == PathState::WanDown), "{out:?}");
        assert!(out[..5].iter().all(|s| *s == PathState::Ok), "{out:?}");
    }

    #[test]
    fn isp_hop_that_answered_before_stays_isp_down() {
        let mut v = vec![env(0, Some(true), Some(true), 3, PathState::Ok)];
        v.push(env(1, Some(true), Some(false), 0, PathState::IspDown));
        let mut rc = Reclassifier::new(Classify::default());
        assert_eq!(run(&mut rc, v), vec![PathState::Ok, PathState::IspDown]);
    }

    #[test]
    fn gateway_that_never_answered_is_not_lan_down() {
        let mut v = Vec::new();
        for i in 0..3 {
            v.push(env(i, Some(false), None, 3, PathState::Ok));
        }
        for i in 3..6 {
            v.push(env(i, Some(false), None, 0, PathState::LanDown));
        }
        let mut rc = Reclassifier::new(Classify::default());
        let out = run(&mut rc, v);
        assert!(out[3..].iter().all(|s| *s == PathState::WanDown), "{out:?}");
    }

    #[test]
    fn gateway_that_answered_before_is_lan_down() {
        let v = vec![env(0, Some(true), None, 3, PathState::Ok), env(1, Some(false), None, 0, PathState::LanDown)];
        let mut rc = Reclassifier::new(Classify::default());
        assert_eq!(run(&mut rc, v), vec![PathState::Ok, PathState::LanDown]);
    }

    #[test]
    fn states_the_classifier_agrees_with_stay_the_same() {
        let mut v = Vec::new();
        let mut want = Vec::new();
        for i in 0..4 {
            v.push(env(i, Some(true), Some(true), 3, PathState::Ok));
            want.push(PathState::Ok);
        }
        v.push(env(4, Some(true), Some(true), 0, PathState::WanDown));
        want.push(PathState::WanDown);
        v.push(env(5, Some(true), Some(false), 0, PathState::IspDown));
        want.push(PathState::IspDown);
        v.push(env(6, Some(false), Some(false), 0, PathState::LanDown));
        want.push(PathState::LanDown);
        let mut rc = Reclassifier::new(Classify::default());
        assert_eq!(run(&mut rc, v), want);
    }

    #[test]
    fn dns_needs_two_failures() {
        let dns_env = |n: u64, ok: bool| {
            let mut e = env(n, Some(true), None, 3, PathState::Ok);
            if let Record::Sample(s) = &mut e.rec {
                s.dns = Some(if ok { ProbeResult::ok(20.0) } else { ProbeResult::fail("timeout") });
            }
            e
        };
        let mut rc = Reclassifier::new(Classify::default());
        // One failed query is not DnsDown. The second consecutive failure is.
        let out = run(&mut rc, vec![dns_env(0, true), dns_env(1, false), dns_env(2, false)]);
        assert_eq!(out, vec![PathState::Ok, PathState::Ok, PathState::DnsDown]);
    }
}
