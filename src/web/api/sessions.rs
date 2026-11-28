//! Sessions tab: the session list, per-session summary and events, comparison and the
//! support report.

use super::index::index_sessions;
use super::report::resolve_report_target;
use super::{ApiError, ApiResult, LimitQuery, MAX_SCAN_LINES, attachment_response, blocking, internal, json_body, safe_slug, session_dir, web_load_opts};
use crate::live::EVENTS_KEPT;
use crate::model::{Envelope, Record, Stream};
use crate::session;
use crate::store::read;
use crate::web::{AppState, Authed};
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::VecDeque;

/// Most sessions listed.
const MAX_SESSIONS: usize = 500;

/// `GET /api/sessions/{id}/events`: newest first.
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SessionEventsResponse {
    pub events: Vec<Envelope>,
    /// Lines that could not be parsed.
    pub skipped_lines: u64,
}

/// `GET /api/sessions`: newest first. Sessions shorter than a minute are left out
/// (except the running one).
#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SessionsResponse {
    pub sessions: Vec<SessionEntry>,
}

#[derive(Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub(crate) struct SessionEntry {
    /// Directory name of the session.
    pub id: String,
    /// This is the running session.
    pub current: bool,
    pub started: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub host: String,
    pub version: String,
    pub point: Option<String>,
    pub label: Option<String>,
    pub note: Option<String>,
    /// Last heartbeat minus start (up to now for the running session).
    pub duration_s: Option<f64>,
    /// From summary.json.
    pub availability_pct: Option<f64>,
    pub verdict: Option<String>,
    pub drops_per_h: Option<f64>,
    /// summary.json as written at the end of the session (free-form).
    pub summary: Option<Value>,
}

/// Sessions (newest first) with meta, duration and summary; tiny ones left out.
pub(super) async fn sessions(State(st): State<AppState>) -> ApiResult {
    let data_dir = st.data_dir.clone();
    let cache = st.index.clone();
    let current = st.live.read(|s| s.session.as_ref().map(|m| m.session.clone()));
    let list = blocking(&st, move || {
        let now = Utc::now();
        let cur = current.as_deref();
        index_sessions(&data_dir, &cache)
            .iter()
            .rev()
            .filter(|s| !s.tiny(cur, now))
            .take(MAX_SESSIONS)
            .map(|s| {
                let duration_s = s.duration_s(cur, now);
                SessionEntry {
                    id: s.id.clone(),
                    current: cur == Some(s.id.as_str()),
                    started: s.started,
                    last_seen: s.last_seen,
                    host: s.host.clone(),
                    version: s.version.clone(),
                    point: s.point.clone(),
                    label: s.label.clone(),
                    note: s.note.clone(),
                    duration_s,
                    availability_pct: s.availability_pct(),
                    verdict: s.verdict(),
                    drops_per_h: s
                        .drops()
                        .zip(s.recorded_s())
                        .filter(|(_, d)| *d > 0.0)
                        .map(|(n, d)| n as f64 / (d / 3600.0)),
                    summary: s.summary.clone(),
                }
            })
            .collect()
    })
    .await?;
    Ok(json_body(&SessionsResponse { sessions: list }))
}

pub(super) async fn session_summary(State(st): State<AppState>, UrlPath(id): UrlPath<String>) -> ApiResult {
    let dir = session_dir(&st, &id)?;
    let s = blocking(&st, move || read::summary(&dir)).await?;
    s.map(|v| Json(v).into_response()).ok_or_else(|| {
        ApiError(
            StatusCode::NOT_FOUND,
            format!("session {id} has no summary yet"),
        )
    })
}

/// Last `limit` events of a session, newest first (heartbeats excluded).
pub(super) async fn session_events(
    State(st): State<AppState>,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<LimitQuery>,
) -> ApiResult {
    let dir = session_dir(&st, &id)?;
    let limit = q.limit.unwrap_or(200).clamp(1, EVENTS_KEPT);
    let (events, skipped) = blocking(&st, move || {
        let mut ring: VecDeque<Envelope> = VecDeque::with_capacity(limit);
        let mut it = read::iter(&dir, Stream::Events);
        for env in it.by_ref().take(MAX_SCAN_LINES) {
            if matches!(env.rec, Record::Event(_)) {
                if ring.len() == limit {
                    ring.pop_front();
                }
                ring.push_back(env);
            }
        }
        (ring.into_iter().rev().collect::<Vec<_>>(), it.skipped())
    })
    .await?;
    Ok(json_body(&SessionEventsResponse { events, skipped_lines: skipped }))
}

#[derive(Deserialize)]
pub(super) struct CompareQuery {
    sessions: String,
    tolerance_s: Option<f64>,
    format: Option<String>,
}

pub(super) async fn compare_sessions(State(st): State<AppState>, Query(q): Query<CompareQuery>) -> ApiResult {
    let fmt = q.format.as_deref().unwrap_or("json");
    if !matches!(fmt, "json" | "md") {
        return Err(ApiError(StatusCode::BAD_REQUEST, "format must be json or md".into()));
    }
    let tol = q.tolerance_s.unwrap_or(2.0);
    if !tol.is_finite() || !(0.0..=60.0).contains(&tol) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "tolerance_s must be 0..=60".into()));
    }
    let mut dirs = Vec::new();
    let mut seen = Vec::new();
    for part in q.sessions.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if seen.iter().any(|s| s == part) {
            return Err(ApiError(StatusCode::BAD_REQUEST, format!("duplicate session id {part}")));
        }
        dirs.push(session_dir(&st, part)?);
        seen.push(part.to_string());
    }
    if !(2..=8).contains(&dirs.len()) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "sessions must list 2..=8 session ids".into()));
    }
    let site = st.site.clone();
    let rep = blocking(&st, move || {
        let mut views = Vec::with_capacity(dirs.len());
        for d in dirs {
            views.push(session::load(&d, &web_load_opts())?);
        }
        let mut rep = crate::compare::compare(views, &crate::compare::CompareOpts { tolerance_s: tol });
        if let Some(site) = site.as_deref() {
            crate::compare::attach_site_rf(&mut rep, site);
        }
        Ok::<_, anyhow::Error>(rep)
    })
    .await?
    .map_err(internal)?;

    if fmt == "md" {
        let md = crate::compare::to_markdown(&rep);
        Ok(attachment_response("text/markdown; charset=utf-8", "linkwatch-compare.md", md.into_bytes()))
    } else {
        Ok(json_body(&rep))
    }
}

#[derive(Deserialize)]
pub(super) struct SupportReportQuery {
    sessions: Option<String>,
    audience: Option<String>,
    lang: Option<String>,
    redact: Option<String>,
    format: Option<String>,
    tolerance_s: Option<f64>,
}

pub(super) async fn support_report(
    State(st): State<AppState>,
    Extension(Authed(authed)): Extension<Authed>,
    Query(q): Query<SupportReportQuery>,
) -> ApiResult {
    use crate::support_report::{
        RedactionLevel, SupportAudience, SupportFormat, SupportInput, SupportLang, SupportOpts, build_pack, render_html,
        render_markdown,
    };

    let audience = match q.audience.as_deref().unwrap_or("isp") {
        "isp" => SupportAudience::Isp,
        "landlord" => SupportAudience::Landlord,
        "admin" => SupportAudience::Admin,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "audience must be isp, landlord, or admin".into())),
    };
    let lang = match q.lang.as_deref().unwrap_or("en") {
        "en" => SupportLang::En,
        "uk" => SupportLang::Uk,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "lang must be en or uk".into())),
    };
    let mut redaction = match q.redact.as_deref().unwrap_or("standard") {
        "standard" => RedactionLevel::Standard,
        "strict" => RedactionLevel::Strict,
        "none" => RedactionLevel::None,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "redact must be standard, strict, or none".into())),
    };
    if !authed && redaction == RedactionLevel::None {
        redaction = RedactionLevel::Standard;
    }
    let format = match q.format.as_deref().unwrap_or("json") {
        "json" => SupportFormat::Json,
        "text" => SupportFormat::Text,
        "md" => SupportFormat::Md,
        "html" => SupportFormat::Html,
        _ => return Err(ApiError(StatusCode::BAD_REQUEST, "format must be json, text, md, or html".into())),
    };
    let tolerance_s = q.tolerance_s.unwrap_or(2.0);
    if !tolerance_s.is_finite() || !(0.0..=60.0).contains(&tolerance_s) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "tolerance_s must be 0..=60".into()));
    }

    let mut dirs = Vec::new();
    let mut seen = Vec::new();
    if let Some(raw) = q.sessions.as_deref() {
        for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if seen.iter().any(|s| s == part) {
                return Err(ApiError(StatusCode::BAD_REQUEST, format!("duplicate session id {part}")));
            }
            dirs.push(session_dir(&st, part)?);
            seen.push(part.to_string());
        }
        if dirs.len() > 8 {
            return Err(ApiError(StatusCode::BAD_REQUEST, "sessions must list at most 8 session ids".into()));
        }
    }
    let slug_src = if dirs.is_empty() {
        let (id, opt_dir) = resolve_report_target(&st, None)?;
        let Some(dir) = opt_dir else {
            return Err(ApiError(StatusCode::NOT_FOUND, "session has no recorded data yet".into()));
        };
        dirs.push(dir);
        id
    } else if seen.len() == 1 {
        seen[0].clone()
    } else {
        "multi".to_string()
    };

    let audit = st.router_audit.lock().await.clone();
    let site = st.site.clone();
    let pack = blocking(&st, move || {
        let mut views = Vec::with_capacity(dirs.len());
        for d in dirs {
            views.push(session::load(&d, &web_load_opts())?);
        }
        Ok::<_, anyhow::Error>(build_pack(
            &SupportInput {
                sessions: &views,
                site: site.as_deref(),
                router_audit: audit.as_ref(),
                cve: None,
                router_log: &[],
            },
            &SupportOpts { audience, lang, redaction, tolerance_s },
        ))
    })
    .await?
    .map_err(internal)?;

    let slug = safe_slug(&slug_src, "session");
    match format {
        SupportFormat::Json => Ok(json_body(&pack)),
        SupportFormat::Text => Ok(([(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"))], pack.short_text).into_response()),
        SupportFormat::Md => Ok(attachment_response("text/markdown; charset=utf-8", &format!("support-report-{slug}.md"), render_markdown(&pack).into_bytes())),
        SupportFormat::Html => Ok(attachment_response("text/html; charset=utf-8", &format!("support-report-{slug}.html"), render_html(&pack).into_bytes())),
    }
}
