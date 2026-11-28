//! Incident attribution ("detective"): decides how much of an outage the measuring host itself
//! explains, with an explicit evidence list. Design and scenarios A1–A19:
//! docs/INCIDENT-ATTRIBUTION.md.
//!
//! A host effect explains an incident only when it can produce this symptom on this path
//! (scope), is strong enough for this duration (dose), came first (timing), and nothing
//! independent contradicts it (counter-evidence). Pure function, no I/O.

use super::Msg;
use crate::model::IfaceRole;
use serde::{Deserialize, Serialize};

/// Graded result of one incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    /// No host effect applies.
    #[default]
    Network,
    /// Host effects were present but cannot explain this outage (scope, dose or timing).
    NetworkDespiteHost,
    /// The host explains a part; the rest is the network.
    Mixed,
    /// A weak host effect covers the outage and nothing contradicts it.
    ObserverLikely,
    /// A strong or certain host effect covers the outage and nothing contradicts it.
    ObserverConfirmed,
}

impl Attribution {
    pub fn is_observer(self) -> bool {
        matches!(self, Self::ObserverLikely | Self::ObserverConfirmed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    #[default]
    Low,
    Medium,
    High,
}

/// Host effects the detective knows (section 4 of the design).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum Suspect {
    Scan,
    SpeedTest,
    SelfTraffic,
    Overrun,
    Suspend,
    DriverReset,
    Throttling,
    LowMemory,
    PowerSave,
    /// The wall clock was stepped: tick timing around it is not trustworthy.
    ClockJump,
}

/// What in the network most likely caused an incident (hints; several can apply).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "snake_case")]
pub enum NetworkCause {
    /// The router's uptime went back: it rebooted.
    RouterReboot,
    /// The router reported its WAN (line) down.
    RouterWanDown,
    /// An imported router (DOCSIS) log line at this time.
    RouterLog,
    /// The access point disconnected the client (or the association timed out).
    ApDisconnect,
    /// The Wi-Fi channel changed (DFS radar or the AP moved channel).
    ChannelSwitch,
    /// Carrier was lost on this wired path (cable, port or NIC).
    CarrierLoss,
    /// The client roamed to another access point.
    Roam,
    /// The path had a link but no address (DHCP).
    Dhcp,
    /// Weak Wi-Fi signal around the incident.
    WeakSignal,
    /// The Wi-Fi channel was very busy around the incident.
    BusyChannel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Strength {
    Weak,
    Strong,
    Confirmed,
}

/// Another interface that failed during this incident.
#[derive(Debug, Clone, PartialEq)]
pub struct OtherFailure {
    pub iface: String,
    pub role: IfaceRole,
    /// It had the host's own heavy traffic too.
    pub self_traffic: bool,
}

/// Everything the detective needs about one incident (section 3 of the design).
#[derive(Debug, Clone)]
pub struct IncidentFacts {
    pub role: IfaceRole,
    pub duration_s: f64,
    /// Bad ticks of the episode.
    pub ticks: u32,
    pub tick_s: f64,
    pub scan_ticks: u32,
    pub speedtest_ticks: u32,
    pub self_traffic_ticks: u32,
    pub overrun_ticks: u32,
    pub suspend_near: bool,
    /// First driver reset of this iface near the incident, seconds from its start.
    pub driver_reset_offset_s: Option<f64>,
    pub throttled_near: bool,
    pub low_memory_near: bool,
    pub power_save_on: bool,
    pub other_failed: Vec<OtherFailure>,
    /// Other interfaces that had link during the incident.
    pub comparable_paths: u32,
    pub router_hit: bool,
    pub ap_disconnect: bool,
    pub clock_jump_near: bool,
    pub router_reboot_near: bool,
    pub router_wan_down_near: bool,
    pub channel_switch_near: bool,
    pub roam_near: bool,
    pub carrier_loss_near: bool,
    /// The episode's main state was "link but no address".
    pub no_ip: bool,
    /// Median Wi-Fi signal (dBm) around the incident.
    pub signal_dbm: Option<f64>,
    /// Median channel busy (%) around the incident.
    pub busy_pct: Option<f64>,
}

impl IncidentFacts {
    /// An incident lasting `ticks` bad ticks of 1 s, with no host effects and no hints.
    #[allow(dead_code)] // used by tests and future callers
    pub fn new(role: IfaceRole, ticks: u32) -> Self {
        Self {
            role,
            duration_s: f64::from(ticks),
            ticks,
            tick_s: 1.0,
            scan_ticks: 0,
            speedtest_ticks: 0,
            self_traffic_ticks: 0,
            overrun_ticks: 0,
            suspend_near: false,
            driver_reset_offset_s: None,
            throttled_near: false,
            low_memory_near: false,
            power_save_on: false,
            other_failed: Vec::new(),
            comparable_paths: 0,
            router_hit: false,
            ap_disconnect: false,
            clock_jump_near: false,
            router_reboot_near: false,
            router_wan_down_near: false,
            channel_switch_near: false,
            roam_near: false,
            carrier_loss_near: false,
            no_ip: false,
            signal_dbm: None,
            busy_pct: None,
        }
    }
}

/// One line of the evidence list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Evidence {
    /// The host effect this line is about; `None` for network evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspect: Option<Suspect>,
    /// Seconds of the incident this line explains (host lines only).
    pub explains_s: f64,
    /// Points to the host (`true`) or to the network (`false`).
    pub host: bool,
    pub msg: Msg,
}

/// The detective's result for one incident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Finding {
    pub attribution: Attribution,
    pub confidence: Confidence,
    /// Seconds the host explains (0 when no host effect applies).
    pub host_s: f64,
    /// Seconds left for the network.
    pub network_s: f64,
    /// The strongest host effect that applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_suspect: Option<Suspect>,
    pub evidence: Vec<Evidence>,
    /// What would change the result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flip: Option<Msg>,
    /// Likely network causes, strongest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_causes: Vec<NetworkCause>,
}

struct Candidate {
    suspect: Suspect,
    explains_s: f64,
    strength: Strength,
    /// Breaks only this interface (other paths failing then contradicts it).
    iface_only: bool,
}

fn secs(v: f64) -> String {
    format!("{v:.0}")
}

/// Host effects that apply to this incident, with what they can explain.
fn candidates(f: &IncidentFacts) -> (Vec<Candidate>, Vec<Evidence>) {
    let t = f.tick_s.max(0.2);
    let d = f.duration_s.max(t);
    let mut c = Vec::new();
    let mut notes = Vec::new();
    if f.scan_ticks > 0 && f.role == IfaceRole::Wifi {
        c.push(Candidate { suspect: Suspect::Scan, explains_s: (f.scan_ticks as f64 * t + 2.0).min(12.0), strength: Strength::Strong, iface_only: true });
    }
    if f.speedtest_ticks > 0 {
        c.push(Candidate { suspect: Suspect::SpeedTest, explains_s: (f.speedtest_ticks as f64 * t + 5.0).min(30.0), strength: Strength::Strong, iface_only: false });
    }
    if f.self_traffic_ticks > 0 {
        c.push(Candidate { suspect: Suspect::SelfTraffic, explains_s: (f.self_traffic_ticks as f64 * t + 5.0).min(30.0), strength: Strength::Strong, iface_only: true });
    }
    if f.overrun_ticks > 0 {
        let strong = f.ticks > 0 && f.overrun_ticks * 2 >= f.ticks;
        c.push(Candidate {
            suspect: Suspect::Overrun,
            explains_s: f.overrun_ticks as f64 * t,
            strength: if strong { Strength::Strong } else { Strength::Weak },
            iface_only: false,
        });
    }
    if f.suspend_near {
        c.push(Candidate { suspect: Suspect::Suspend, explains_s: d, strength: Strength::Confirmed, iface_only: false });
    }
    match f.driver_reset_offset_s {
        Some(off) if off <= 5.0 => c.push(Candidate { suspect: Suspect::DriverReset, explains_s: d, strength: Strength::Strong, iface_only: true }),
        Some(off) => notes.push(Evidence {
            suspect: Some(Suspect::DriverReset),
            explains_s: 0.0,
            host: false,
            msg: crate::msg!("a_driver_reset_after", "The driver reset came {s} s after the outage began: a consequence, not the cause.", s = secs(off)),
        }),
        None => {}
    }
    if f.throttled_near {
        c.push(Candidate { suspect: Suspect::Throttling, explains_s: 15.0, strength: Strength::Weak, iface_only: false });
    }
    if f.low_memory_near {
        c.push(Candidate { suspect: Suspect::LowMemory, explains_s: 15.0, strength: Strength::Weak, iface_only: false });
    }
    if f.clock_jump_near {
        c.push(Candidate { suspect: Suspect::ClockJump, explains_s: 5.0, strength: Strength::Strong, iface_only: false });
    }
    if f.power_save_on && f.role == IfaceRole::Wifi {
        c.push(Candidate { suspect: Suspect::PowerSave, explains_s: if f.ticks <= 2 { d } else { 0.0 }, strength: Strength::Weak, iface_only: true });
    }
    for x in &mut c {
        x.explains_s = x.explains_s.clamp(0.0, d);
    }
    (c, notes)
}

fn suspect_msg(s: Suspect, explains_s: f64) -> Msg {
    let s_ = secs(explains_s);
    match s {
        Suspect::Scan => crate::msg!("a_scan", "Own Wi-Fi scan during the outage: explains up to {s} s.", s = s_),
        Suspect::SpeedTest => crate::msg!("a_speed_test", "Own speed test during the outage: explains up to {s} s.", s = s_),
        Suspect::SelfTraffic => crate::msg!("a_self_traffic", "The host's own heavy traffic on this path: explains up to {s} s.", s = s_),
        Suspect::Overrun => crate::msg!("a_overrun", "Late probe ticks (host CPU or disk stalls): explain {s} s.", s = s_),
        Suspect::Suspend => crate::msg!("a_suspend", "The host was suspended: it measured nothing during the outage."),
        Suspect::DriverReset => crate::msg!("a_driver_reset", "The Wi-Fi driver reset at the start of the outage."),
        Suspect::Throttling => crate::msg!("a_throttling", "Undervoltage or thermal throttling near the outage: explains up to {s} s.", s = s_),
        Suspect::LowMemory => crate::msg!("a_low_memory", "The host was low on memory near the outage: explains up to {s} s.", s = s_),
        Suspect::PowerSave => {
            if explains_s > 0.0 {
                crate::msg!("a_power_save", "Wi-Fi power-save was on: explains a {s} s drop (missed beacons).", s = s_)
            } else {
                crate::msg!("a_power_save_too_long", "Wi-Fi power-save was on, but it cannot cause a full outage this long.")
            }
        }
        Suspect::ClockJump => crate::msg!("a_clock_jump", "The host clock was stepped: explains up to {s} s of tick timing.", s = s_),
    }
}

pub fn attribute(f: &IncidentFacts) -> Finding {
    let d = f.duration_s.max(f.tick_s.max(0.2));
    let (cands, mut evidence) = candidates(f);
    for c in &cands {
        evidence.push(Evidence { suspect: Some(c.suspect), explains_s: c.explains_s, host: true, msg: suspect_msg(c.suspect, c.explains_s) });
    }

    // Network evidence (independent of the host) and likely network causes.
    let wifi = f.role == IfaceRole::Wifi;
    let mut causes = Vec::new();
    let mut hint = |c: NetworkCause, m: Msg, ev: &mut Vec<Evidence>| {
        causes.push(c);
        ev.push(Evidence { suspect: None, explains_s: 0.0, host: false, msg: m });
    };
    if f.router_reboot_near {
        hint(NetworkCause::RouterReboot, crate::msg!("a_router_reboot", "The router rebooted at this time (its uptime went back)."), &mut evidence);
    }
    if f.router_wan_down_near {
        hint(NetworkCause::RouterWanDown, crate::msg!("a_router_wan_down", "The router reported its internet line (WAN) down."), &mut evidence);
    }
    if f.carrier_loss_near && !wifi {
        hint(NetworkCause::CarrierLoss, crate::msg!("a_carrier_loss", "The cable lost carrier: check the cable, the port and the network card."), &mut evidence);
    }
    if f.channel_switch_near && wifi {
        hint(NetworkCause::ChannelSwitch, crate::msg!("a_channel_switch", "The Wi-Fi channel changed (radar detection or the router moved channel)."), &mut evidence);
    }
    if f.roam_near && wifi {
        hint(NetworkCause::Roam, crate::msg!("a_roam", "The device roamed to another access point."), &mut evidence);
    }
    if f.no_ip {
        hint(NetworkCause::Dhcp, crate::msg!("a_dhcp", "The path had a link but no address (DHCP)."), &mut evidence);
    }
    if wifi && f.signal_dbm.is_some_and(|s| s <= -75.0) {
        hint(NetworkCause::WeakSignal, crate::msg!("a_weak_signal", "The Wi-Fi signal was weak ({dbm} dBm).", dbm = format!("{:.0}", f.signal_dbm.unwrap_or_default())), &mut evidence);
    }
    if wifi && f.busy_pct.is_some_and(|b| b >= 70.0) {
        hint(NetworkCause::BusyChannel, crate::msg!("a_busy_channel", "The Wi-Fi channel was {pct}% busy.", pct = format!("{:.0}", f.busy_pct.unwrap_or_default())), &mut evidence);
    }
    let other_clean = f.other_failed.iter().filter(|o| !o.self_traffic).count();
    if !f.other_failed.is_empty() {
        let names: Vec<&str> = f.other_failed.iter().map(|o| o.iface.as_str()).collect();
        evidence.push(Evidence { suspect: None, explains_s: 0.0, host: false, msg: crate::msg!("a_other_path", "{ifs} failed at the same time.", ifs = names.join(", ")) });
    }
    if f.router_hit {
        causes.insert(0, NetworkCause::RouterLog);
        evidence.push(Evidence { suspect: None, explains_s: 0.0, host: false, msg: crate::msg!("a_router_log", "The router log has an event at this time.") });
    }
    if f.ap_disconnect && wifi {
        let at = causes.iter().position(|c| !matches!(c, NetworkCause::RouterLog | NetworkCause::RouterReboot | NetworkCause::RouterWanDown)).unwrap_or(causes.len());
        causes.insert(at, NetworkCause::ApDisconnect);
        evidence.push(Evidence { suspect: None, explains_s: 0.0, host: false, msg: crate::msg!("a_ap_disconnect", "The access point disconnected this device (or the association timed out).") });
    }
    // Independent of the host: the router or the AP acted, or the cable dropped.
    let router_side = f.router_hit || f.router_reboot_near || f.router_wan_down_near;
    let ap_side = wifi && (f.ap_disconnect || f.channel_switch_near);
    let cable_side = !wifi && f.carrier_loss_near;
    let confidence = if !f.other_failed.is_empty() || router_side || ap_side || cable_side {
        Confidence::High
    } else if f.comparable_paths > 0 {
        Confidence::Medium
    } else {
        Confidence::Low
    };

    // Does independent evidence contradict suspect `c`?
    let contradicted = |c: &Candidate| -> bool {
        if router_side {
            return true;
        }
        let ap = ap_side;
        if cable_side && (c.iface_only || c.strength == Strength::Weak) {
            return true;
        }
        match c.suspect {
            Suspect::SpeedTest => !f.other_failed.is_empty(),
            Suspect::SelfTraffic => other_clean > 0 || ap,
            Suspect::Scan | Suspect::PowerSave => !f.other_failed.is_empty() || ap,
            // A weak hint (throttling, low memory, a few late ticks) does not outweigh an
            // independent path failing at the same time.
            _ if c.iface_only || c.strength == Strength::Weak => !f.other_failed.is_empty(),
            _ => false,
        }
    };

    // Strongest suspect first; among equals the one that explains more.
    let main = cands.iter().max_by(|a, b| a.strength.cmp(&b.strength).then(a.explains_s.total_cmp(&b.explains_s)));
    let Some(main) = main else {
        // Only a single path with nothing independent needs the hint; a healthy second path
        // already makes the network result plausible.
        let flip = (confidence == Confidence::Low).then(|| crate::msg!("a_flip_unconfirmed", "Nothing independent confirms it: a second path or the router log would make this certain."));
        return Finding { attribution: Attribution::Network, confidence, host_s: 0.0, network_s: d, main_suspect: None, evidence, flip, network_causes: causes };
    };
    let host_s = cands.iter().map(|c| c.explains_s).fold(0.0, f64::max).min(d);
    let r = host_s / d;
    let counter = contradicted(main);

    let attribution = if counter {
        if main.suspect == Suspect::SpeedTest || (main.strength >= Strength::Strong && r >= 0.1) {
            Attribution::Mixed
        } else {
            Attribution::NetworkDespiteHost
        }
    } else if r >= 0.8 {
        if main.strength >= Strength::Strong { Attribution::ObserverConfirmed } else { Attribution::ObserverLikely }
    } else if r >= 0.1 {
        Attribution::Mixed
    } else {
        Attribution::NetworkDespiteHost
    };
    let (host_s, network_s) = match attribution {
        Attribution::Network | Attribution::NetworkDespiteHost => (if attribution == Attribution::Network { 0.0 } else { host_s }, d),
        // A load incident: our speed test provoked it, but the network really failed under
        // that load, so the whole outage also counts for the network.
        Attribution::Mixed if counter && main.suspect == Suspect::SpeedTest => (host_s, d),
        Attribution::Mixed => (host_s, (d - host_s).max(0.0)),
        Attribution::ObserverLikely | Attribution::ObserverConfirmed => (d, 0.0),
    };
    let flip = match attribution {
        Attribution::ObserverConfirmed | Attribution::ObserverLikely => Some(if main.iface_only {
            crate::msg!("a_flip_other_path", "If another path or the router log had failed at the same time, this would be a network fault.")
        } else {
            crate::msg!("a_flip_router_log", "If the router log showed an event at this time, this would be a network fault.")
        }),
        Attribution::Mixed => Some(crate::msg!("a_flip_mixed", "Without the host effect the outage would still last about {s} s.", s = secs(network_s))),
        Attribution::NetworkDespiteHost | Attribution::Network => None,
    };
    let confidence = if attribution.is_observer() { Confidence::default() } else { confidence };
    let network_causes = if attribution.is_observer() { Vec::new() } else { causes };
    Finding { attribution, confidence, host_s, network_s, main_suspect: Some(main.suspect), evidence, flip, network_causes }
}
