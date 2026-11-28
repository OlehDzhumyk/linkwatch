//! Checks for requests that change state: token, same origin, JSON body, rate limit, and the
//! reason why measurement control is off.

use super::ApiError;
use crate::web::AppState;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

pub(super) const NO_TOKEN: &str = "set [web] token to enable control";

/// Reason why control is off, or None when on. The token middleware has already
/// authenticated every request that reaches a handler when a token is configured.
pub(super) fn control_off(st: &AppState, authed: bool) -> Option<&'static str> {
    if st.token.is_none() {
        Some(NO_TOKEN)
    } else if !authed {
        Some(READ_ONLY)
    } else if st.control.is_none() {
        Some("measurement control is not available in this process")
    } else {
        None
    }
}

/// Reason shown to viewers of an open (`view = "open"`) UI without the token.
pub(super) const READ_ONLY: &str = "read-only view: open the UI once with ?token=<token> to control measurements";

/// Host part of an `Origin` value (`scheme://host[:port]`), or None when it is not one.
fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://"))?;
    (!rest.is_empty() && !rest.contains('/')).then_some(rest)
}

/// CSRF defence: an `Origin` header, when present, must name this host; a browser that says
/// the request is cross-site is refused too.
fn same_origin(headers: &HeaderMap) -> bool {
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return false;
    }
    let Some(origin) = headers.get(header::ORIGIN) else { return true };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    match (origin.to_str().ok().and_then(origin_host), host) {
        (Some(o), Some(h)) => o.eq_ignore_ascii_case(h),
        _ => false,
    }
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}


pub(super) fn rate_limited(
    slot: &std::sync::Mutex<Option<std::time::Instant>>,
    min_interval: std::time::Duration,
    action: &str,
) -> Option<Response> {
    let mut last = slot.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = *last {
        let since = t.elapsed();
        if since < min_interval {
            let wait = (min_interval - since).as_secs() + 1;
            let mut r = ApiError(StatusCode::TOO_MANY_REQUESTS, format!("wait {wait} s before the next {action}")).into_response();
            if let Ok(v) = HeaderValue::from_str(&wait.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            return Some(r);
        }
    }
    *last = Some(std::time::Instant::now());
    None
}

pub(super) fn require_post_auth(st: &AppState, headers: &HeaderMap, no_token_msg: &str) -> Result<(), ApiError> {
    if st.token.is_none() {
        return Err(ApiError(StatusCode::FORBIDDEN, no_token_msg.into()));
    }
    if !same_origin(headers) {
        return Err(ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into()));
    }
    if !is_json(headers) {
        return Err(ApiError(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json".into()));
    }
    Ok(())
}
