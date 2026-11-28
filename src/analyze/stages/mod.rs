//! The stages of `Analyzer::finish` (docs/ARCHITECTURE.md §3.1), in the order they run.
//!
//! Each stage is a function with typed input and output. `Analyzer::finish` only calls them in
//! this order:
//!
//! 1. [`episodes`]: close open episodes, backfill the Wi-Fi band, sort.
//! 2. [`cross_path`]: what the other paths did during each episode, and the episode `cause`.
//! 3. [`facts`]: host and router facts around each episode, the attribution and the origin.
//! 4. [`context`]: notes around each episode, router log matches, monitor gaps, security events.
//! 5. [`iface_report`]: per-interface totals, per-band and per-hour rows, anomalies.
//! 6. [`incidents`]: merge episodes into incidents, split observer and load incidents.
//! 7. [`telemetry`]: router and LAN reports.
//! 8. [`observer`]: observer findings and Observer Trust.
//! 9. [`masking`]: session blinds and the confidence cap.
//! 10. [`summary`]: assemble the `Report`.
//!
//! [`windows`] holds the time windows and the sorted-slice lookups that stages 3 and 4 share.

pub(super) mod context;
pub(super) mod cross_path;
pub(super) mod episodes;
pub(super) mod facts;
pub(super) mod iface_report;
pub(super) mod incidents;
pub(super) mod masking;
pub(super) mod observer;
pub(super) mod summary;
pub(super) mod telemetry;
pub(super) mod windows;

/// Small builders for the stage unit tests.
#[cfg(test)]
pub(super) mod fixtures {
    use super::super::*;
    use super::episodes::{EpFlags, Tracked};

    pub fn t0() -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000, 0).unwrap()
    }

    /// An episode on `iface` that starts `start_s` after [`t0`] and lasts `dur_s`.
    pub fn episode(iface: &str, role: IfaceRole, start_s: i64, dur_s: i64, state: PathState) -> Episode {
        Episode {
            iface: iface.into(),
            role,
            start: t0() + Duration::seconds(start_s),
            end: t0() + Duration::seconds(start_s + dur_s),
            duration_s: dur_s as f64,
            ticks: dur_s as u32,
            state,
            cause: None,
            origin: IncidentOrigin::Unknown,
            band: None,
            speedtest_active: false,
            context: vec![],
            context_msg: vec![],
            finding: Default::default(),
        }
    }

    pub fn tracked(ep: Episode) -> Tracked {
        (ep, EpFlags::default())
    }
}
