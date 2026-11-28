//! Router audit, CVE lookup and advice. The audit and CVE handlers sit behind the
//! `router-audit` and `cve` features; without them the routes answer with a clear error.

use super::{ApiError, ApiResult, json_body};
use crate::web::AppState;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;

#[cfg(any(feature = "router-audit", feature = "cve"))]
use super::auth::{rate_limited, require_post_auth};
#[cfg(any(feature = "router-audit", feature = "cve"))]
use super::control::CONTROL_BODY_LIMIT;
#[cfg(any(feature = "router-audit", feature = "cve"))]
use axum::extract::DefaultBodyLimit;
#[cfg(any(feature = "router-audit", feature = "cve"))]
use axum::http::HeaderMap;
#[cfg(any(feature = "router-audit", feature = "cve"))]
use axum::routing::post;
#[cfg(feature = "router-audit")]
use axum::routing::get;
#[cfg(feature = "router-audit")]
use chrono::Utc;

/// Routes of the `router-audit` feature.
#[cfg(feature = "router-audit")]
pub(super) fn router_audit_routes() -> Router<AppState> {
    Router::new().route("/api/router/audit", get(router_audit_get)).route(
        "/api/router/probe",
        post(router_probe_post).layer(DefaultBodyLimit::max(CONTROL_BODY_LIMIT)),
    )
}

/// Without the feature the routes stay, so a client gets a clear error and not an empty 404.
#[cfg(not(feature = "router-audit"))]
pub(super) fn router_audit_routes() -> Router<AppState> {
    Router::new().route("/api/router/audit", axum::routing::any(router_audit_off)).route("/api/router/probe", axum::routing::any(router_audit_off))
}

#[cfg(not(feature = "router-audit"))]
async fn router_audit_off() -> ApiResult {
    Err(feature_off("router-audit"))
}

/// Routes of the `cve` feature.
#[cfg(feature = "cve")]
pub(super) fn cve_routes() -> Router<AppState> {
    Router::new().route("/api/router/cve", post(router_cve_post).layer(DefaultBodyLimit::max(CONTROL_BODY_LIMIT)))
}

#[cfg(not(feature = "cve"))]
pub(super) fn cve_routes() -> Router<AppState> {
    Router::new().route("/api/router/cve", axum::routing::any(cve_off))
}

#[cfg(not(feature = "cve"))]
async fn cve_off() -> ApiResult {
    Err(feature_off("cve"))
}

#[cfg(not(all(feature = "router-audit", feature = "cve")))]
fn feature_off(feature: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("not built with the `{feature}` feature"))
}

/// Shortest time between two active router probes or CVE lookups.
#[cfg(any(feature = "router-audit", feature = "cve"))]
const PROBE_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

// ---------- router audit, CVE lookup & advisor ----------

#[cfg(feature = "router-audit")]
fn live_gateway(live: &crate::live::Live) -> (Option<std::net::Ipv4Addr>, Option<String>) {
    live.read(|s| {
        let gw = s
            .ifaces
            .values()
            .find_map(|i| i.last.as_ref().and_then(|l| l.link.gateway));
        let mac = s
            .session
            .as_ref()
            .and_then(|m| m.network.as_ref())
            .and_then(|n| n.gateway_mac.clone());
        (gw, mac)
    })
}

/// Last audit result only. A GET never sends anything to the network: viewers (possibly without
/// a token) must not be able to trigger port checks or adapter logins. Probes run only through
/// `POST /api/router/probe`, which needs the token.
#[cfg(feature = "router-audit")]
async fn router_audit_get(State(st): State<AppState>) -> ApiResult {
    if let Some(cached) = st.router_audit.lock().await.clone() {
        return Ok(json_body(&cached));
    }
    let (gw, gw_mac) = live_gateway(&st.live);
    Ok(json_body(&crate::router::RouterAudit {
        probed_at: Utc::now(),
        gateway_ip: gw.map(|g| g.to_string()),
        gateway_mac: gw_mac,
        adapter_used: "none".into(),
        warnings: vec![if gw.is_some() {
            "Not probed yet: run a probe (needs the web token).".into()
        } else {
            "Default gateway IP not detected yet.".into()
        }],
        ..Default::default()
    }))
}

#[cfg(feature = "router-audit")]
async fn router_probe_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult {
    require_post_auth(&st, &headers, "set [web] token to probe router with credentials")?;
    let req: crate::router::audit::RouterProbeRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    let (live_gw, gw_mac) = live_gateway(&st.live);
    let target = match req.host.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => crate::router::audit::validate_local_host(raw)
            .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("{e:#}")))?,
        None => live_gw.ok_or_else(|| {
            ApiError(StatusCode::BAD_REQUEST, "gateway IP not known; specify a local host".into())
        })?,
    };
    if let Some(r) = rate_limited(&st.last_probe, PROBE_MIN_INTERVAL, "router probe") {
        return Ok(r);
    }
    let audit = crate::router::audit::run_probe(target, gw_mac, &req, st.router_upnp_url.as_deref()).await;
    *st.router_audit.lock().await = Some(audit.clone());
    Ok(json_body(&audit))
}

#[cfg(feature = "cve")]
fn validate_cve_field(name: &str, raw: &str, required: bool) -> Result<(), ApiError> {
    let t = raw.trim();
    if required && t.is_empty() {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("{name} must not be empty")));
    }
    if t.chars().count() > 128 {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("{name} is too long (max 128 chars)")));
    }
    if t.chars().any(char::is_control) {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("{name} contains control characters")));
    }
    Ok(())
}

#[cfg(feature = "cve")]
async fn router_cve_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> ApiResult {
    require_post_auth(&st, &headers, "set [web] token to query external CVE databases")?;
    let req: crate::router::cve::CveLookupRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("invalid request: {e}")))?;
    validate_cve_field("model", &req.model, true)?;
    if let Some(v) = &req.vendor {
        validate_cve_field("vendor", v, false)?;
    }
    if let Some(fw) = &req.firmware {
        validate_cve_field("firmware", fw, false)?;
    }
    if let Some(r) = rate_limited(&st.last_cve, PROBE_MIN_INTERVAL, "CVE lookup") {
        return Ok(r);
    }
    let res = crate::router::cve::lookup_cves(&st.data_dir, &req, st.nvd_api_key.as_deref())
        .await
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("CVE lookup failed: {e:#}")))?;
    Ok(json_body(&res))
}

pub(super) async fn advice_get(State(st): State<AppState>) -> ApiResult {
    let audit = st.router_audit.lock().await.clone();
    let resp = st.live.read(|snap| crate::router::advice::evaluate(snap, audit.as_ref()));
    Ok(json_body(&resp))
}
