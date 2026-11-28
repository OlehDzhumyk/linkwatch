//! Named thresholds of the classifier (docs/ARCHITECTURE.md, P8). Every number that decides a
//! path state or a layer verdict is here, with the reason for its value.
//!
//! "Engineering estimate" means that no measurement backs the value yet. Such a value can
//! change when a labelled session shows it is wrong (docs/ARCHITECTURE.md §4.3).
//!
//! The first group holds the defaults of the `[classify]` config keys (`config::Classify`
//! uses them). The second group holds the thresholds that are not configurable.

// ---------- defaults of the `[classify]` config keys ----------

/// A new state must hold this long (s) before a state change is recorded.
/// Engineering estimate: three seconds hides a single lost burst and still names a real outage
/// within one user-visible freeze.
pub const DEFAULT_DEBOUNCE_S: f64 = 3.0;
/// Loss and latency are judged over this window (s) for `Degraded`.
/// Engineering estimate: long enough for a stable median at one probe per second, short enough
/// to follow a degrading link within half a minute.
pub const DEFAULT_WINDOW_S: f64 = 30.0;
/// [`DEFAULT_DEBOUNCE_S`] in ticks at the default probe interval (1 s).
pub const DEFAULT_DEBOUNCE_TICKS: u32 = 3;
/// [`DEFAULT_WINDOW_S`] in ticks at the default probe interval (1 s).
pub const DEFAULT_WINDOW_TICKS: u32 = 30;
/// Loss above this share (%) of the window makes a path `Degraded`.
/// Engineering estimate: video calls and games notice 2 % loss; TCP throughput starts to fall.
pub const DEGRADED_LOSS_PCT: f64 = 2.0;
/// A median router RTT above this (ms) makes a path `Degraded`.
/// Engineering estimate: a healthy wired or Wi-Fi hop to the router answers in a few
/// milliseconds; 50 ms means a busy channel or a failing link.
pub const DEGRADED_GW_RTT_MS: f64 = 50.0;
/// A median internet RTT above this (ms) makes a path `Degraded`.
/// Engineering estimate: a typical home line answers in 10–40 ms; 150 ms is felt in calls.
pub const DEGRADED_NET_RTT_MS: f64 = 150.0;

// ---------- thresholds in the code ----------

/// `Degraded` needs at least this many counted ticks in the window.
/// Engineering estimate: with fewer ticks a median and a loss share are noise.
pub const MIN_EVIDENCE_TICKS: usize = 5;
/// `Degraded` also needs counted ticks for at least one part in this many of the window
/// (2 = half of the window).
/// Engineering estimate: ticks of our own speed tests and scans do not count, so a window that
/// is mostly ours says nothing about the path.
pub const EVIDENCE_WINDOW_DIVISOR: usize = 2;
/// A tick where only some of the internet targets answered counts as this share of a failed tick.
/// Engineering estimate: one of three targets lost is a partial loss; the path still carries
/// traffic, so it weighs half.
pub const PARTIAL_LOSS_WEIGHT: f64 = 0.5;
/// Router loss counts only after at least this many lost router probes in the window.
/// Engineering estimate: one lost ICMP reply is noise whatever the percentage says.
pub const MIN_LOST_GW_PROBES: usize = 2;
/// A cross-path verdict needs at least this many paths.
/// Rule, not a measurement: with one path nothing can be compared, so the verdict is
/// `SinglePath` or `Unknown`.
pub const MIN_COMPARABLE_PATHS: usize = 2;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Classify;

    #[test]
    fn config_defaults_use_these_limits() {
        let c = Classify::default();
        assert_eq!((c.debounce_ticks, c.window_ticks), (DEFAULT_DEBOUNCE_TICKS, DEFAULT_WINDOW_TICKS));
        assert_eq!((c.degraded_loss_pct, c.degraded_gw_rtt_ms, c.degraded_net_rtt_ms), (DEGRADED_LOSS_PCT, DEGRADED_GW_RTT_MS, DEGRADED_NET_RTT_MS));
        assert_eq!((Classify::DEFAULT_DEBOUNCE_S, Classify::DEFAULT_WINDOW_S), (DEFAULT_DEBOUNCE_S, DEFAULT_WINDOW_S));
    }

    #[test]
    fn default_ticks_match_the_default_seconds_at_one_probe_per_second() {
        let mut c = Classify::default();
        c.resolve(1000);
        assert_eq!((f64::from(c.debounce_ticks), f64::from(c.window_ticks)), (DEFAULT_DEBOUNCE_S, DEFAULT_WINDOW_S));
        assert_eq!((c.debounce_ticks, c.window_ticks), (DEFAULT_DEBOUNCE_TICKS, DEFAULT_WINDOW_TICKS));
    }

    #[test]
    fn limits_keep_their_documented_relations() {
        const { assert!(MIN_EVIDENCE_TICKS >= MIN_LOST_GW_PROBES) };
        const { assert!(EVIDENCE_WINDOW_DIVISOR >= 1) };
        const { assert!(MIN_COMPARABLE_PATHS >= 2) };
        const { assert!(PARTIAL_LOSS_WEIGHT > 0.0 && PARTIAL_LOSS_WEIGHT <= 1.0) };
        // The router is nearer than the internet, so its RTT limit is the lower one.
        const { assert!(DEGRADED_GW_RTT_MS < DEGRADED_NET_RTT_MS) };
    }
}
