//! Time windows around an episode, and the sorted-slice lookups that use them.
//! Used by the `facts` stage (what explains an episode) and the `context` stage (what to show).

use super::super::*;

/// Host alerts (driver reset, throttling, low memory) count from this long before the episode.
pub(super) const HOST_NEAR_BEFORE_S: i64 = 30;
/// Host alerts count up to this long after the episode ends (a reset can lag the loss).
pub(super) const HOST_NEAR_AFTER_S: i64 = 15;
/// An AP-initiated disconnect or timeout this close to an episode explains it.
pub(super) const AP_DISCONNECT_WINDOW_S: i64 = 15;
/// Router (DOCSIS) log lines this close to an episode are shown and count as router evidence.
pub(super) const ROUTER_LOG_WINDOW_S: i64 = 120;
/// A host suspend gap this close to an episode means the observer slept.
pub(super) const SUSPEND_WINDOW_S: i64 = 10;
/// A clock jump this close to an episode makes timing unreliable.
pub(super) const CLOCK_JUMP_WINDOW_S: i64 = 5;
/// A channel change shortly before the loss is a likely cause; a little after is tolerated.
pub(super) const CHANNEL_CHANGE_BEFORE_S: i64 = 15;
pub(super) const CHANNEL_CHANGE_AFTER_S: i64 = 5;
/// A roam shortly before the loss is a likely cause; a little after is tolerated.
pub(super) const ROAM_BEFORE_S: i64 = 10;
pub(super) const ROAM_AFTER_S: i64 = 5;
/// A carrier loss on the interface this close to the episode is its cause.
pub(super) const CARRIER_LOSS_WINDOW_S: i64 = 5;
/// A router reboot this close to an episode explains it (router uptime is polled slowly).
pub(super) const ROUTER_REBOOT_WINDOW_S: i64 = 60;
/// A router WAN-down sample this close to an episode explains it.
pub(super) const ROUTER_WAN_DOWN_WINDOW_S: i64 = 30;
/// Signal and busy-channel medians use samples this far around an episode.
pub(super) const SIGNAL_WINDOW_S: i64 = 60;
/// A speed test that started this long before the context window can still load the link.
pub(super) const SPEEDTEST_LEAD_S: i64 = 40;
/// LAN device activity is compared over this window around an episode.
pub(super) const LAN_WINDOW_S: i64 = 600;
/// Backfill an episode band from a Wi-Fi frequency reading at most this far from its middle.
pub(super) const BAND_BACKFILL_S: i64 = 120;
/// Local hours that count as evening.
pub(in crate::analyze) const EVENING_HOURS: std::ops::Range<usize> = 18..24;

/// Slice of a time-sorted vector with `lo <= t <= hi` (both ends inclusive), by binary search.
pub(super) fn in_window<T>(v: &[(DateTime<Utc>, T)], lo: DateTime<Utc>, hi: DateTime<Utc>) -> &[(DateTime<Utc>, T)] {
    let a = v.partition_point(|(t, _)| *t < lo);
    let b = v.partition_point(|(t, _)| *t <= hi);
    &v[a..b.max(a)]
}

/// Same as [`in_window`] for a sorted vector of bare timestamps.
pub(super) fn in_window_times(v: &[DateTime<Utc>], lo: DateTime<Utc>, hi: DateTime<Utc>) -> &[DateTime<Utc>] {
    let a = v.partition_point(|t| *t < lo);
    let b = v.partition_point(|t| *t <= hi);
    &v[a..b.max(a)]
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::t0;
    use super::*;

    fn at(s: i64) -> DateTime<Utc> {
        t0() + Duration::seconds(s)
    }

    #[test]
    fn window_includes_both_ends() {
        let v: Vec<(DateTime<Utc>, u8)> = (0..10).map(|i| (at(i), i as u8)).collect();
        let got: Vec<u8> = in_window(&v, at(3), at(5)).iter().map(|(_, x)| *x).collect();
        assert_eq!(got, vec![3, 4, 5]);
    }

    #[test]
    fn window_outside_or_inverted_is_empty() {
        let v: Vec<(DateTime<Utc>, u8)> = (0..5).map(|i| (at(i), i as u8)).collect();
        assert!(in_window(&v, at(10), at(20)).is_empty());
        assert!(in_window(&v, at(4), at(1)).is_empty());
        assert!(in_window::<u8>(&[], at(0), at(1)).is_empty());
    }

    #[test]
    fn bare_timestamps_use_the_same_rule() {
        let v: Vec<DateTime<Utc>> = (0..10).map(at).collect();
        assert_eq!(in_window_times(&v, at(2), at(2)), &[at(2)]);
        assert_eq!(in_window_times(&v, at(8), at(30)).len(), 2);
    }
}
