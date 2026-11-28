//! JSON API handlers. Live endpoints read [`crate::live::Live`]; history endpoints read
//! session files on a blocking thread with hard limits on lines and results.
//!
//! One file per UI tab: `live`, `report`, `sessions`, `site` (map and plan), `router`,
//! `control`. `auth` has the checks for requests that change state and `index` the session
//! index that several tabs share. This file has the route table, the error type and the
//! helpers that more than one tab uses.

mod auth;
mod control;
mod index;
mod live;
mod report;
mod router;
mod sessions;
mod site;

use crate::session::LoadOpts;
use crate::web::AppState;
use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use control::{CONTROL_BODY_LIMIT, control_get, control_session};
use live::{events, live_sse, minutes, scan, speed, status};
use report::{report, report_export};
use router::{advice_get, cve_routes, router_audit_routes};
use serde::{Deserialize, Serialize};
use sessions::{compare_sessions, session_events, session_summary, sessions, support_report};
use site::{plan, site};
use std::path::PathBuf;

pub(crate) use index::SessionIndex;
pub(crate) use live::HistoryCache;
pub(crate) use report::ReportCache;

// The tests in `web/tests.rs` reach these through `api::`.
#[cfg(test)]
pub(crate) use index::IndexedSession;
#[cfg(test)]
pub(crate) use live::{EventsResponse, MinutesResponse, ScanResponse, SpeedResponse, StatusResponse};
#[cfg(test)]
pub(crate) use report::{REPORT_FRESH, ReportResponse};
#[cfg(test)]
pub(crate) use sessions::{SessionEventsResponse, SessionsResponse};
#[cfg(test)]
pub(crate) use site::{PlanResponse, PlanStatus, SiteResponse, build_plan};
#[cfg(test)]
pub(crate) use control::{ControlResponse, ControlSessionResponse};

/// Most lines read from one session stream for one request.
const MAX_SCAN_LINES: usize = 3_000_000;

/// How the web reads a session: like `linkwatch analyze`, but with the line limit
/// ([`MAX_SCAN_LINES`]) and without `--reclassify`.
fn web_load_opts() -> LoadOpts {
    LoadOpts { max_lines: Some(MAX_SCAN_LINES), ..Default::default() }
}

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/minutes", get(minutes))
        .route("/api/events", get(events))
        .route("/api/speed", get(speed))
        .route("/api/scan", get(scan))
        .route("/api/site", get(site))
        .route("/api/sessions", get(sessions))
        .route("/api/report", get(report))
        .route("/api/report/export", get(report_export))
        .route("/api/compare", get(compare_sessions))
        .route("/api/support-report", get(support_report))
        .route("/api/sessions/{id}/summary", get(session_summary))
        .route("/api/sessions/{id}/events", get(session_events))
        .route("/api/live", get(live_sse))
        .route("/api/plan", get(plan))
        .route("/api/control", get(control_get))
        .route(
            "/api/control/session",
            post(control_session).layer(DefaultBodyLimit::max(CONTROL_BODY_LIMIT)),
        )
        .route("/api/advice", get(advice_get))
        .merge(router_audit_routes())
        .merge(cve_routes())
}

// ---------- response bodies ----------
//
// Every JSON body the UI reads is a named type here. `cargo test` writes their TypeScript
// declarations to src/web/ui/src/api/ (ts-rs); the UI imports them from there. Fields that
// are `Option` without `skip_serializing_if` are always present (`null` when unknown).

/// Body of every error response.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct ErrorResponse {
    pub error: String,
}

/// Error response with a JSON body `{"error": "..."}`.
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorResponse { error: self.1 })).into_response()
    }
}

type ApiResult = Result<Response, ApiError>;

/// JSON response from a body that may borrow the live state: serialise while the borrow lasts.
fn json_body<T: Serialize>(v: &T) -> Response {
    match serde_json::to_vec(v) {
        Ok(body) => ([(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))], body).into_response(),
        Err(e) => internal(e).into_response(),
    }
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Runs blocking file reads off the async threads, at most `MAX_DISK_READS` at a time.
async fn blocking<T: Send + 'static>(
    st: &AppState,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    let _permit = tokio::time::timeout(std::time::Duration::from_secs(10), st.disk.clone().acquire_owned())
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "busy: too many history requests".into()))?
        .map_err(internal)?;
    tokio::task::spawn_blocking(f).await.map_err(internal)
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

/// Session directory for an id from the URL. Only plain names of existing sessions.
fn session_dir(st: &AppState, id: &str) -> Result<PathBuf, ApiError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid session id".into(),
        ));
    }
    let dir = st.data_dir.join(id);
    if !dir.join("meta.json").is_file() {
        return Err(ApiError(StatusCode::NOT_FOUND, format!("no session {id}")));
    }
    Ok(dir)
}

fn attachment_response(content_type: &'static str, filename: &str, body: Vec<u8>) -> Response {
    let mut r = ([(header::CONTENT_TYPE, HeaderValue::from_static(content_type))], body).into_response();
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    r
}

fn safe_slug(raw: &str, fallback: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
        .collect();
    let trimmed = s.trim_matches('_');
    if trimmed.is_empty() { fallback.into() } else { trimmed.into() }
}
