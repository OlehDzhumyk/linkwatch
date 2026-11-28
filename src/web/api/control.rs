//! System tab: measurement control (`GET /api/control`, `POST /api/control/session`).

use super::auth::{NO_TOKEN, control_off, rate_limited, require_post_auth};
use super::index::index_sessions;
use super::{ApiError, ApiResult, blocking, json_body};
use crate::control::{SendError, SessionRequest};
use crate::web::{AppState, Authed};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Extension;
use chrono::{DateTime, Utc};
use serde::Serialize;

/// Shortest time between two accepted session switches.
pub(crate) const SWITCH_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// Largest accepted request body of `POST /api/control/session`.
pub(crate) const CONTROL_BODY_LIMIT: usize = 4096;
/// How long a switch may take (tasks stop, summary, new session opens).
const SWITCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Most suggestions of earlier points.
const MAX_KNOWN_POINTS: usize = 50;

/// `GET /api/control`: whether this client may switch sessions, and the current choice.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ControlResponse {
    pub enabled: bool,
    /// Why control is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(test, ts(optional))]
    pub reason: Option<String>,
    pub point: Option<String>,
    pub label: Option<String>,
    pub note: Option<String>,
    pub session: Option<String>,
    pub started: Option<DateTime<Utc>>,
    /// A site file is configured: the point must be one of its points. Otherwise the point
    /// is free text (1..=64 of `[A-Za-z0-9 _./-]`).
    pub site: bool,
    /// Points of earlier sessions (and the running one), newest first, for suggestions.
    pub known_points: Vec<String>,
    pub min_interval_s: u32,
}

/// `POST /api/control/session` answer: id of the new session.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ControlSessionResponse {
    pub session: String,
}

pub(super) async fn control_get(State(st): State<AppState>, Extension(Authed(authed)): Extension<Authed>) -> ApiResult {
    let data_dir = st.data_dir.clone();
    let cache = st.index.clone();
    let cur = st.live.read(|s| s.session.as_ref().map(|m| (m.session.clone(), m.point.clone(), m.label.clone(), m.note.clone(), m.started)));
    let cur_point = cur.as_ref().and_then(|c| c.1.clone());
    let known_points = blocking(&st, move || {
        let mut out: Vec<String> = Vec::new();
        if let Some(p) = cur_point {
            out.push(p);
        }
        for s in index_sessions(&data_dir, &cache).iter().rev() {
            if let Some(p) = &s.point
                && !out.contains(p)
            {
                out.push(p.clone());
                if out.len() >= MAX_KNOWN_POINTS {
                    break;
                }
            }
        }
        out
    })
    .await?;
    let off = control_off(&st, authed);
    let (session, point, label, note, started) = match cur {
        Some((id, p, l, n, t)) => (Some(id), p, l, n, Some(t)),
        None => (None, None, None, None, None),
    };
    Ok(json_body(&ControlResponse {
        enabled: off.is_none(),
        reason: off.map(str::to_string),
        point,
        label,
        note,
        session,
        started,
        site: st.site.is_some(),
        known_points,
        min_interval_s: SWITCH_MIN_INTERVAL.as_secs() as u32,
    }))
}

/// Starts a new session with `{point?, label?, note?}`. Needs a configured token (and so an
/// authenticated request), JSON, the same origin, and at most one switch per 10 s.
pub(super) async fn control_session(State(st): State<AppState>, headers: HeaderMap, body: axum::body::Bytes) -> ApiResult {
    if let Some(r) = control_off(&st, true) {
        return Err(ApiError(StatusCode::FORBIDDEN, r.into()));
    }
    let Some(ctl) = st.control.clone() else {
        return Err(ApiError(StatusCode::FORBIDDEN, NO_TOKEN.into()));
    };
    require_post_auth(&st, &headers, NO_TOKEN)?;
    let req: SessionRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    let req = req.validated(st.site.as_deref()).map_err(|e| ApiError(StatusCode::BAD_REQUEST, e))?;
    if let Some(r) = rate_limited(&st.last_switch, SWITCH_MIN_INTERVAL, "switch") {
        return Ok(r);
    }
    match tokio::time::timeout(SWITCH_TIMEOUT, ctl.start_session(req)).await {
        Ok(Ok(session)) => Ok(json_body(&ControlSessionResponse { session })),
        Ok(Err(SendError::Busy)) => Err(ApiError(StatusCode::CONFLICT, "another switch is in progress".into())),
        Ok(Err(SendError::Closed)) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "the monitor is stopping".into())),
        Ok(Err(SendError::Failed(e))) => Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, e)),
        Err(_) => Err(ApiError(StatusCode::GATEWAY_TIMEOUT, "the switch takes too long; reload the page later".into())),
    }
}
