//! The one place that turns a [`Report`] into the headline a person reads
//! (docs/ARCHITECTURE.md §3.1, problems P2 and P4).
//!
//! Pure: no IO, no clock. The web report calls [`headline`] and [`explain`]. The Markdown report
//! shows no headline verdict. The support pack words its headline from compare evidence, not from
//! a layer verdict, so it does not use this module (see `support_report::build_pack`).
//!
//! # Rule that runs today
//!
//! 1. The layer verdict is the live verdict, if the caller has one.
//! 2. Otherwise it is the most frequent `Episode::cause` (ties: more outage seconds, then the
//!    later verdict in `key_of` order). Observer-origin episodes, load-provoked episodes and the
//!    causes `AllOk` and `Unknown` do not count.
//! 3. Otherwise it is `SinglePath` for a report with one interface, `AllOk` for more than one,
//!    and none for a report with no interface.
//!
//! # Planned rule (R8, not implemented)
//!
//! The *layer verdict* says where the path broke. The *attribution* says whether the network is
//! to blame and how sure the analyzer is. The headline will use the layer verdict of the incidents
//! that the attribution keeps as network incidents. An observer incident or an inconclusive
//! incident will never set the headline layer. Today step 2 looks only at origin, load and cause,
//! not at the attribution (`Episode::finding`).

use crate::analyze::{Report, is_load_provoked};
use crate::model::{IfaceRole, IncidentOrigin, Verdict};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

/// What a person reads about the state of the session.
#[derive(Debug, Clone, PartialEq)]
pub struct Headline {
    /// The layer verdict that the sentence describes. `None` when there is nothing to classify.
    pub verdict: Option<Verdict>,
    /// Stable message code. The UI translates the sentence by this code (`report.vc.<code>`).
    pub code: &'static str,
    /// Values for the placeholders of the sentence.
    pub args: BTreeMap<String, String>,
    /// The sentence in English.
    pub text: String,
}

/// Headline of a report. `live` is the verdict of the running monitor; it wins when present.
pub fn headline(report: &Report, live: Option<Verdict>) -> Headline {
    let verdict = live.or_else(|| dominant_cause(report)).or(match report.ifaces.len() {
        0 => None,
        1 => Some(Verdict::SinglePath),
        _ => Some(Verdict::AllOk),
    });
    let wifi_signal = report
        .ifaces
        .iter()
        .find(|i| i.role == Some(IfaceRole::Wifi))
        .and_then(|i| i.signal_med);
    explain(verdict, report.network_incidents, report.observer_incidents, wifi_signal)
}

/// The sentence for one verdict, without choosing the verdict.
///
/// Use it to put the live verdict on a report that was built earlier: the caller keeps the
/// incident counts and the Wi-Fi signal of that report. `wifi_signal_med` is the median signal
/// (dBm) of the first Wi-Fi interface.
pub fn explain(verdict: Option<Verdict>, net_inc: u32, obs_inc: u32, wifi_signal_med: Option<f64>) -> Headline {
    let one = |code, text: &str| Headline { verdict, code, args: BTreeMap::new(), text: text.into() };
    let with = |code, k: &str, v: String, text: String| Headline { verdict, code, args: BTreeMap::from([(k.to_string(), v)]), text };
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
        Some(Verdict::WifiProblem) => match wifi_signal_med {
            Some(s) if s < -75.0 => with("wifi_weak", "dbm", format!("{s:.0}"), format!("Ethernet stayed stable while Wi-Fi failed — weak Wi-Fi signal (median {s:.0} dBm).")),
            _ => one("wifi", "Ethernet stayed stable while Wi-Fi failed — issue is on the wireless hop."),
        },
        Some(Verdict::WiredProblem) => one("wired", "Wi-Fi stayed up while the wired path failed — check Ethernet cable or port."),
        Some(Verdict::RouterProblem) => one("router", "All monitored paths failed at the router — router rebooted, stalled, or LAN stopped responding."),
        Some(Verdict::LineProblem) => one("line", "All paths reached the router but failed at the ISP hop — issue is on the access line."),
        Some(Verdict::InternetProblem) => one("internet", "Local network and ISP hop answered, but external internet targets timed out."),
        Some(Verdict::Dns) => one("dns", "IP probes succeeded, but DNS name resolution failed."),
        Some(Verdict::Mixed) => one("mixed", "Paths failed at different points at the same time — see the incidents for each path."),
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

/// The failing layer that most episodes name. See "Rule that runs today" above.
fn dominant_cause(rep: &Report) -> Option<Verdict> {
    let mut counts: BTreeMap<usize, (Verdict, u32, f64)> = BTreeMap::new();
    // Ties go to the later key, so the vaguest verdict has the lowest key.
    let key_of = |v: Verdict| match v {
        Verdict::Mixed => 0,
        Verdict::AllOk => 1,
        Verdict::WifiProblem => 2,
        Verdict::WiredProblem => 3,
        Verdict::RouterProblem => 4,
        Verdict::LineProblem => 5,
        Verdict::InternetProblem => 6,
        Verdict::Dns => 7,
        Verdict::SinglePath => 8,
        Verdict::Unknown => 9,
    };
    for ep in &rep.episodes {
        if ep.origin == IncidentOrigin::Observer || is_load_provoked(ep) {
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
