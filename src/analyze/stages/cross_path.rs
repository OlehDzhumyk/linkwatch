//! Stage `cross_path`: what were the other interfaces doing during each episode?
//!
//! The answer is the episode `cause` (the layer verdict of [`crate::classify::verdict`]) and the
//! list of other paths that failed too, which the `facts` stage hands to the attribution.

use super::super::engine::IfAcc;
use super::super::*;
use super::episodes::Tracked;

/// The cross-path result for one episode.
pub(in crate::analyze) struct PathContext {
    pub cause: Verdict,
    /// Other interfaces whose outage covers a real part of this one.
    pub others: Vec<attribution::OtherFailure>,
    /// Other interfaces that had link and traffic during the episode (so they could be compared).
    pub comparable: u32,
}

/// One result per episode, in the order of `episodes`.
///
/// Another path counts as failing too only when its outage covers a real part (at least half,
/// or 3 ticks) of this one; a 1-tick blip there must not flip the cause.
pub(in crate::analyze) fn analyze(episodes: &[Tracked], ifs: &BTreeMap<String, IfAcc>, isp_known: bool, tick_s: f64) -> Vec<PathContext> {
    episodes
        .iter()
        .map(|(ep, _)| {
            let need = overlap_needed_s(ep.duration_s, tick_s);
            let others: Vec<&Tracked> = episodes
                .iter()
                .filter(|(o, _)| o.iface != ep.iface && o.start < ep.end && ep.start < o.end)
                .filter(|(o, _)| overlap_s(o, ep) >= need)
                .collect();
            let comparable = comparable_paths(ep, ifs);
            let states: Vec<(IfaceRole, PathState)> = others.iter().map(|(o, _)| (o.role, o.state)).collect();
            PathContext {
                cause: decide(ep.role, ep.state, &states, comparable, isp_known),
                others: others
                    .iter()
                    .map(|(o, f)| attribution::OtherFailure { iface: o.iface.clone(), role: o.role, self_traffic: f.self_traffic > 0 })
                    .collect(),
                comparable: comparable as u32,
            }
        })
        .collect()
}

/// Seconds of overlap another path's episode needs to count as "failing too".
fn overlap_needed_s(duration_s: f64, tick_s: f64) -> f64 {
    (duration_s / 2.0).min(3.0 * tick_s).max(tick_s * 0.99)
}

fn overlap_s(a: &Episode, b: &Episode) -> f64 {
    (a.end.min(b.end) - a.start.max(b.start)).num_milliseconds() as f64 / 1000.0
}

/// Other paths that were connected during this episode (with link, so comparable).
fn comparable_paths(ep: &Episode, ifs: &BTreeMap<String, IfAcc>) -> usize {
    ifs.iter()
        .filter(|(n, a)| **n != ep.iface && a.ticks > 0)
        .filter(|(_, a)| !a.no_link.iter().any(|(s, e)| *s < ep.end && ep.start < *e))
        .count()
}

/// The cause of one episode from the states of the other failing paths.
fn decide(role: IfaceRole, state: PathState, others: &[(IfaceRole, PathState)], comparable: usize, isp_known: bool) -> Verdict {
    if comparable == 0 {
        Verdict::SinglePath
    } else if others.is_empty() {
        if role == IfaceRole::Wifi { Verdict::WifiProblem } else { Verdict::WiredProblem }
    } else {
        let mut st = others.to_vec();
        st.push((role, state));
        crate::classify::verdict(&st, isp_known)
    }
}

#[cfg(test)]
mod tests {
    use super::super::episodes::EpFlags;
    use super::super::fixtures::{episode, t0, tracked};
    use super::*;

    fn acc(ticks: u64) -> IfAcc {
        IfAcc { ticks, ..Default::default() }
    }

    #[test]
    fn needed_overlap_is_half_the_episode_capped_at_three_ticks() {
        assert!((overlap_needed_s(1.0, 1.0) - 0.99).abs() < 1e-9, "never less than one tick");
        assert!((overlap_needed_s(4.0, 1.0) - 2.0).abs() < 1e-9);
        assert!((overlap_needed_s(100.0, 1.0) - 3.0).abs() < 1e-9);
        assert!((overlap_needed_s(100.0, 5.0) - 15.0).abs() < 1e-9);
    }

    #[test]
    fn cause_without_a_comparable_path_is_single_path() {
        assert_eq!(decide(IfaceRole::Wifi, PathState::LanDown, &[], 0, true), Verdict::SinglePath);
    }

    #[test]
    fn cause_of_a_lone_failure_names_the_failing_kind_of_path() {
        assert_eq!(decide(IfaceRole::Wifi, PathState::LanDown, &[], 1, true), Verdict::WifiProblem);
        assert_eq!(decide(IfaceRole::Ethernet, PathState::LanDown, &[], 1, true), Verdict::WiredProblem);
    }

    #[test]
    fn cause_of_a_joint_failure_comes_from_the_layer_verdict() {
        let others = [(IfaceRole::Ethernet, PathState::WanDown)];
        assert_eq!(decide(IfaceRole::Wifi, PathState::WanDown, &others, 1, true), Verdict::InternetProblem);
        assert_eq!(decide(IfaceRole::Wifi, PathState::WanDown, &others, 1, false), Verdict::LineProblem);
    }

    #[test]
    fn joint_outage_gives_a_line_problem_and_names_the_other_path() {
        let mut ifs = BTreeMap::new();
        ifs.insert("wlo1".to_string(), acc(100));
        ifs.insert("eth0".to_string(), acc(100));
        let mut eth = episode("eth0", IfaceRole::Ethernet, 10, 8, PathState::IspDown);
        eth.ticks = 8;
        let flags = EpFlags { self_traffic: 2, ..Default::default() };
        let eps = [tracked(episode("wlo1", IfaceRole::Wifi, 10, 8, PathState::IspDown)), (eth, flags)];
        let out = analyze(&eps, &ifs, true, 1.0);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].cause, Verdict::LineProblem);
        assert_eq!(out[0].comparable, 1);
        assert_eq!(out[0].others.len(), 1);
        assert_eq!(out[0].others[0].iface, "eth0");
        assert!(out[0].others[0].self_traffic, "the flag of the other episode is passed on");
        assert!(!out[1].others[0].self_traffic);
    }

    #[test]
    fn a_one_tick_blip_on_the_other_path_does_not_flip_the_cause() {
        let mut ifs = BTreeMap::new();
        ifs.insert("wlo1".to_string(), acc(100));
        ifs.insert("eth0".to_string(), acc(100));
        let eps = [
            tracked(episode("wlo1", IfaceRole::Wifi, 10, 20, PathState::LanDown)),
            tracked(episode("eth0", IfaceRole::Ethernet, 20, 1, PathState::LanDown)),
        ];
        let out = analyze(&eps, &ifs, true, 1.0);
        assert!(out[0].others.is_empty());
        assert_eq!(out[0].cause, Verdict::WifiProblem);
    }

    #[test]
    fn a_path_without_link_during_the_episode_is_not_comparable() {
        let mut other = acc(100);
        other.no_link.push((t0() + Duration::seconds(5), t0() + Duration::seconds(40)));
        let mut ifs = BTreeMap::new();
        ifs.insert("wlo1".to_string(), acc(100));
        ifs.insert("eth0".to_string(), other);
        let eps = [tracked(episode("wlo1", IfaceRole::Wifi, 10, 8, PathState::LanDown))];
        let out = analyze(&eps, &ifs, true, 1.0);
        assert_eq!(out[0].comparable, 0);
        assert_eq!(out[0].cause, Verdict::SinglePath);
    }
}
