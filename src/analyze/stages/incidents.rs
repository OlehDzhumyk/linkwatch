//! Stage `incidents`: overlapping episodes of different interfaces are one real-world event.
//!
//! Observer-origin incidents and short speed-test-load incidents are counted separately and
//! stay out of the unprovoked network verdicts.

use super::super::*;

/// Incident totals of a session.
#[derive(Debug, Default, PartialEq)]
pub(in crate::analyze) struct IncidentCounts {
    /// Every episode of the incident came from the observer.
    pub observer: u32,
    /// The incident has network episodes only during our own load (short speed-test drops).
    pub load: u32,
    /// The incident has at least one unprovoked network episode.
    pub network: u32,
    /// Network incidents by the cause of their longest episode.
    pub by_cause: BTreeMap<String, u32>,
}

/// The report key of an episode cause.
pub(super) fn cause_key(v: Option<Verdict>) -> String {
    v.map_or("unknown", Verdict::as_str).to_string()
}

/// Episodes per cause, without observer and load-provoked episodes.
pub(in crate::analyze) fn cause_counts(episodes: &[Episode]) -> BTreeMap<String, u32> {
    let mut causes = BTreeMap::new();
    for e in episodes {
        if e.origin != IncidentOrigin::Observer && !is_load_provoked(e) {
            *causes.entry(cause_key(e.cause)).or_default() += 1;
        }
    }
    causes
}

/// The episodes that overlap in time, until the next gap.
struct Group<'a> {
    end: DateTime<Utc>,
    longest: &'a Episode,
    all_observer: bool,
    has_unprovoked: bool,
}

/// Merge episodes (sorted by start) into incidents and count them.
pub(in crate::analyze) fn merge(episodes: &[Episode]) -> IncidentCounts {
    let mut out = IncidentCounts::default();
    let mut cur: Option<Group> = None;
    for e in episodes {
        let obs = e.origin == IncidentOrigin::Observer;
        let unprovoked = !obs && !is_load_provoked(e);
        match &mut cur {
            Some(g) if e.start < g.end => {
                g.end = g.end.max(e.end);
                g.all_observer &= obs;
                g.has_unprovoked |= unprovoked;
                if e.duration_s > g.longest.duration_s {
                    g.longest = e;
                }
            }
            _ => {
                if let Some(g) = cur.take() {
                    out.record(&g);
                }
                cur = Some(Group { end: e.end, longest: e, all_observer: obs, has_unprovoked: unprovoked });
            }
        }
    }
    if let Some(g) = cur {
        out.record(&g);
    }
    out
}

impl IncidentCounts {
    fn record(&mut self, g: &Group) {
        if g.all_observer {
            self.observer += 1;
        } else if !g.has_unprovoked {
            self.load += 1;
        } else {
            self.network += 1;
            *self.by_cause.entry(cause_key(g.longest.cause)).or_default() += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::episode;
    use super::*;

    fn with(mut e: Episode, cause: Verdict, origin: IncidentOrigin, speedtest: bool) -> Episode {
        e.cause = Some(cause);
        e.origin = origin;
        e.speedtest_active = speedtest;
        e
    }

    #[test]
    fn overlapping_episodes_of_two_interfaces_are_one_incident_named_by_the_longest() {
        let w = with(episode("wlo1", IfaceRole::Wifi, 100, 20, PathState::IspDown), Verdict::LineProblem, IncidentOrigin::Network, false);
        let e = with(episode("eth0", IfaceRole::Ethernet, 105, 5, PathState::IspDown), Verdict::WiredProblem, IncidentOrigin::Network, false);
        let far = with(episode("wlo1", IfaceRole::Wifi, 500, 4, PathState::LanDown), Verdict::WifiProblem, IncidentOrigin::Network, false);
        let c = merge(&[w, e, far]);
        assert_eq!(c.network, 2);
        assert_eq!(c.by_cause.get("line_problem"), Some(&1), "the longest episode names the first incident");
        assert_eq!(c.by_cause.get("wifi_problem"), Some(&1));
        assert!(!c.by_cause.contains_key("wired_problem"));
    }

    #[test]
    fn an_incident_with_one_unprovoked_episode_is_a_network_incident() {
        let obs = with(episode("wlo1", IfaceRole::Wifi, 100, 20, PathState::LanDown), Verdict::WifiProblem, IncidentOrigin::Observer, false);
        let net = with(episode("eth0", IfaceRole::Ethernet, 110, 5, PathState::LanDown), Verdict::WiredProblem, IncidentOrigin::Network, false);
        let c = merge(&[obs, net]);
        assert_eq!((c.observer, c.load, c.network), (0, 0, 1));
        assert_eq!(c.by_cause.get("wifi_problem"), Some(&1), "the longest episode names the cause, even an observer one");
    }

    #[test]
    fn observer_only_and_load_only_incidents_are_counted_apart() {
        let obs = with(episode("wlo1", IfaceRole::Wifi, 100, 10, PathState::LanDown), Verdict::WifiProblem, IncidentOrigin::Observer, false);
        let load = with(episode("wlo1", IfaceRole::Wifi, 300, 10, PathState::LanDown), Verdict::WifiProblem, IncidentOrigin::Network, true);
        let long_load = with(episode("wlo1", IfaceRole::Wifi, 600, 60, PathState::LanDown), Verdict::WifiProblem, IncidentOrigin::Network, true);
        let c = merge(&[obs, load, long_load]);
        assert_eq!((c.observer, c.load, c.network), (1, 1, 1), "a load drop longer than 45 s is not provoked by the test");
    }

    #[test]
    fn no_episodes_no_incidents() {
        assert_eq!(merge(&[]), IncidentCounts::default());
        assert!(cause_counts(&[]).is_empty());
    }

    #[test]
    fn cause_counts_skip_observer_and_load_episodes_and_name_a_missing_cause_unknown() {
        let net = with(episode("wlo1", IfaceRole::Wifi, 0, 5, PathState::LanDown), Verdict::WifiProblem, IncidentOrigin::Network, false);
        let obs = with(episode("wlo1", IfaceRole::Wifi, 100, 5, PathState::LanDown), Verdict::WifiProblem, IncidentOrigin::Observer, false);
        let load = with(episode("wlo1", IfaceRole::Wifi, 200, 5, PathState::LanDown), Verdict::WifiProblem, IncidentOrigin::Network, true);
        let mut unknown = episode("wlo1", IfaceRole::Wifi, 300, 5, PathState::LanDown);
        unknown.origin = IncidentOrigin::Network;
        let c = cause_counts(&[net, obs, load, unknown]);
        assert_eq!(c.get("wifi_problem"), Some(&1));
        assert_eq!(c.get("unknown"), Some(&1));
        assert_eq!(c.len(), 2);
    }
}
