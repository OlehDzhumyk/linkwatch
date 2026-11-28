//! Named thresholds of the analyzer (docs/ARCHITECTURE.md, P8), with the reason for each value.
//!
//! "Engineering estimate" means that no measurement backs the value yet. Such a value can
//! change when a labelled session shows it is wrong (docs/ARCHITECTURE.md §4.3). The thresholds
//! of the per-tick classifier are in `classify::limits`.

/// A path that was `Degraded` for at least this share (%) of its ticks gets a quality finding.
/// Engineering estimate: the classifier already needs 2 % loss or a slow median to say
/// `Degraded`; if that holds for one tick in twenty, a user feels it every day, while a few
/// stray windows stay below the line.
pub const DEGRADED_SHARE_PCT: f64 = 5.0;
/// A path that stayed `Degraded` for one unbroken run of at least this many seconds gets a
/// quality finding, even when the run is a small share of a long session.
/// Engineering estimate: five minutes is longer than a video call needs to fall apart and
/// longer than any single burst the 30 s classifier window can explain.
pub const DEGRADED_RUN_S: f64 = 300.0;
/// The share rule needs at least this many seconds of `Degraded` time in total.
/// Engineering estimate: a share of a very short session is noise (3 ticks of 50 are 6 %);
/// one minute is two classifier windows.
pub const DEGRADED_MIN_S: f64 = 60.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_keep_their_documented_relations() {
        // One run that meets the run rule also meets the minimum of the share rule.
        const { assert!(DEGRADED_RUN_S >= DEGRADED_MIN_S) };
        const { assert!(DEGRADED_SHARE_PCT > 0.0 && DEGRADED_SHARE_PCT < 100.0) };
    }
}
