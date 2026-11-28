//! Map & Plan tab: resolved site geometry and the measurement plan.

use super::index::{IndexedSession, MIN_SESSION_S, index_sessions};
use super::{ApiError, ApiResult, blocking, json_body};
use crate::site::{BuildingView, Site};
use crate::web::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// `GET /api/site`: resolved site geometry and the point of the running session.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SiteResponse<'a> {
    pub buildings: Vec<BuildingView<'a>>,
    pub current_point: Option<String>,
}

pub(super) async fn site(State(st): State<AppState>) -> ApiResult {
    let site = st
        .site
        .as_ref()
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no site file configured".into()))?;
    let current_point = st.live.read(|s| s.session.as_ref().and_then(|m| m.point.clone()));
    Ok(json_body(&SiteResponse { buildings: site.view(), current_point }))
}

/// Progress of one plan item.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
#[serde(rename_all = "lowercase")]
pub(crate) enum PlanStatus {
    /// Not measured yet.
    Todo,
    /// The running session is at this point.
    Active,
    /// Measured, but less than planned (or not planned at all).
    Partial,
    /// Measured at least as long as planned.
    Done,
}

/// One point of the plan, or a point that was measured without being planned.
#[derive(Serialize, Debug, Clone)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct PlanItem {
    pub point: String,
    /// In `[[plan]]` of the site file.
    pub planned: bool,
    /// Room or point name (the id when the site does not know the point).
    pub name: String,
    pub building: Option<String>,
    pub building_name: Option<String>,
    pub unit: Option<String>,
    pub unit_label: Option<String>,
    pub floor: Option<i32>,
    /// Note of the plan entry.
    pub note: Option<String>,
    /// Planned seconds (None when not planned).
    pub target_s: Option<f64>,
    /// Sum of the durations of the sessions at this point (sessions under a minute excluded).
    pub measured_s: f64,
    pub sessions: u32,
    pub status: PlanStatus,
    /// Duration-weighted availability from the session summaries.
    pub availability_pct: Option<f64>,
    /// Drops per hour from the session summaries.
    pub drops_per_h: Option<f64>,
    /// Newest session at this point.
    pub last_session: Option<String>,
}

/// `GET /api/plan`: plan items in file order, then measured points that are not planned.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct PlanResponse {
    /// A site file is configured.
    pub site: bool,
    pub current_point: Option<String>,
    pub min_session_s: f64,
    pub items: Vec<PlanItem>,
}

#[derive(Default)]
struct PointAcc {
    measured_s: f64,
    sessions: u32,
    avail: (f64, f64),
    drops: (u64, f64),
    last: Option<String>,
}

/// Plan progress from the session index. `current` is the running session (id, point).
pub(crate) fn build_plan(
    site: Option<&Site>,
    sessions: &[Arc<IndexedSession>],
    current: Option<(&str, Option<&str>)>,
    now: DateTime<Utc>,
) -> Vec<PlanItem> {
    let cur_id = current.map(|c| c.0);
    let cur_point = current.and_then(|c| c.1);
    let mut acc: BTreeMap<&str, PointAcc> = BTreeMap::new();
    for s in sessions {
        let Some(p) = s.point.as_deref() else { continue };
        if s.tiny(cur_id, now) {
            continue;
        }
        let d = s.duration_s(cur_id, now).unwrap_or(0.0);
        let a = acc.entry(p).or_default();
        a.measured_s += d;
        a.sessions += 1;
        if let Some(v) = s.availability_pct() {
            a.avail.0 += v * d;
            a.avail.1 += d;
        }
        if let Some(n) = s.drops() {
            a.drops.0 += n;
            a.drops.1 += d;
        }
        a.last = Some(s.id.clone());
    }
    let item = |point: &str, planned: Option<&crate::site::PlanEntry>| -> PlanItem {
        let a = acc.get(point);
        let rp = site.and_then(|s| s.point(point));
        let measured_s = a.map_or(0.0, |a| a.measured_s);
        let target_s = planned.map(|e| e.hours * 3600.0);
        let status = if cur_point == Some(point) {
            PlanStatus::Active
        } else if target_s.is_some_and(|t| measured_s >= t) {
            PlanStatus::Done
        } else if measured_s > 0.0 {
            PlanStatus::Partial
        } else {
            PlanStatus::Todo
        };
        PlanItem {
            point: point.to_string(),
            planned: planned.is_some(),
            name: rp.as_ref().map_or_else(|| point.to_string(), |p| p.name.clone()),
            building_name: rp.as_ref().and_then(|p| site?.building_name(&p.building)).map(str::to_string),
            unit_label: rp.as_ref().and_then(|p| site?.unit_label(&p.building, &p.unit)).map(str::to_string),
            building: rp.as_ref().map(|p| p.building.clone()),
            unit: rp.as_ref().map(|p| p.unit.clone()),
            floor: rp.as_ref().map(|p| p.floor),
            note: planned.and_then(|e| e.note.clone()),
            target_s,
            measured_s,
            sessions: a.map_or(0, |a| a.sessions),
            status,
            availability_pct: a.filter(|a| a.avail.1 > 0.0).map(|a| a.avail.0 / a.avail.1),
            drops_per_h: a.filter(|a| a.drops.1 > 0.0).map(|a| a.drops.0 as f64 / (a.drops.1 / 3600.0)),
            last_session: a.and_then(|a| a.last.clone()),
        }
    };
    let plan = site.map(Site::plan).unwrap_or_default();
    let mut items: Vec<PlanItem> = plan.iter().map(|e| item(&e.point, Some(e))).collect();
    let mut extra: Vec<&str> = acc.keys().copied().filter(|p| !plan.iter().any(|e| e.point == *p)).collect();
    if let Some(c) = cur_point
        && !acc.contains_key(c)
        && !plan.iter().any(|e| e.point == c)
    {
        extra.push(c);
    }
    extra.sort_unstable();
    items.extend(extra.into_iter().map(|p| item(p, None)));
    items
}

/// The running session: (id, point, started).
fn current_session(st: &AppState) -> Option<(String, Option<String>, DateTime<Utc>)> {
    st.live.read(|s| s.session.as_ref().map(|m| (m.session.clone(), m.point.clone(), m.started)))
}

pub(super) async fn plan(State(st): State<AppState>) -> ApiResult {
    let data_dir = st.data_dir.clone();
    let cache = st.index.clone();
    let site = st.site.clone();
    let cur = current_session(&st);
    let current_point = cur.as_ref().and_then(|c| c.1.clone());
    let items = blocking(&st, move || {
        let all = index_sessions(&data_dir, &cache);
        build_plan(site.as_deref(), &all, cur.as_ref().map(|c| (c.0.as_str(), c.1.as_deref())), Utc::now())
    })
    .await?;
    Ok(json_body(&PlanResponse { site: st.site.is_some(), current_point, min_session_s: MIN_SESSION_S, items }))
}
