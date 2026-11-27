//! Web UI and JSON API (axum 0.7).
//!
//! The page and its script/style are embedded with `include_str!` and use no external
//! resources, so the UI works on a LAN without internet. Live data comes from
//! [`Live`]; history comes from session files read on blocking threads with limits.
//! A slow client never blocks the monitor: the live feed is a broadcast channel and
//! lagging SSE clients skip records.

mod api;

use crate::control::ControlHandle;
use crate::live::Live;
use crate::site::Site;
use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;

const INDEX_HTML: &str = include_str!("ui/index.html");
const STYLE_CSS: &str = include_str!("ui/style.css");

/// The UI script: ES modules compiled from TypeScript (src/web/ui/src, `npm run build`).
/// The compiled files are committed, so building the binary needs no Node. Served at
/// `/js/<name>`; index.html loads `main.js`, which imports the others by relative path.
/// Only names in this table are served (no file system access, no path traversal).
const UI_MODULES: &[(&str, &str)] = &[
    ("audit.js", include_str!("ui/dist/audit.js")),
    ("cards.js", include_str!("ui/dist/cards.js")),
    ("client.js", include_str!("ui/dist/client.js")),
    ("dom.js", include_str!("ui/dist/dom.js")),
    ("events.js", include_str!("ui/dist/events.js")),
    ("format.js", include_str!("ui/dist/format.js")),
    ("i18n.js", include_str!("ui/dist/i18n.js")),
    ("live.js", include_str!("ui/dist/live.js")),
    ("locale_en.js", include_str!("ui/dist/locale_en.js")),
    ("locale_uk.js", include_str!("ui/dist/locale_uk.js")),
    ("main.js", include_str!("ui/dist/main.js")),
    ("measure.js", include_str!("ui/dist/measure.js")),
    ("now.js", include_str!("ui/dist/now.js")),
    ("points.js", include_str!("ui/dist/points.js")),
    ("report.js", include_str!("ui/dist/report.js")),
    ("sessions.js", include_str!("ui/dist/sessions.js")),
    ("site.js", include_str!("ui/dist/site.js")),
    ("state.js", include_str!("ui/dist/state.js")),
    ("status.js", include_str!("ui/dist/status.js")),
    ("system.js", include_str!("ui/dist/system.js")),
    ("timeline.js", include_str!("ui/dist/timeline.js")),
    ("tips.js", include_str!("ui/dist/tips.js")),
    ("ui.js", include_str!("ui/dist/ui.js")),
    ("wifi.js", include_str!("ui/dist/wifi.js")),
];

async fn ui_module(axum::extract::Path(name): axum::extract::Path<String>) -> Response {
    match UI_MODULES.iter().find(|(n, _)| *n == name) {
        Some((_, body)) => asset("text/javascript; charset=utf-8", body),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Time open connections get to finish after shutdown before the server stops anyway.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct AppState {
    pub live: Live,
    pub data_dir: Arc<PathBuf>,
    pub site: Option<Arc<Site>>,
    /// Becomes true on shutdown; ends SSE streams.
    pub stop: watch::Receiver<bool>,
    /// Optional access token (see `config::Web::token`).
    pub token: Option<Arc<str>>,
    /// Limits concurrent history reads from disk: they share the blocking thread pool
    /// with the store writer, which must never starve.
    pub disk: Arc<tokio::sync::Semaphore>,
    /// Limits concurrent live (SSE) streams.
    pub sse: Arc<tokio::sync::Semaphore>,
    /// Results of history reads, keyed by the state of the files they were built from.
    pub history: Arc<std::sync::Mutex<api::HistoryCache>>,
    /// Session switching (None when the monitor does not accept commands, e.g. in tests).
    pub control: Option<ControlHandle>,
    /// Time of the last accepted switch (rate limit).
    pub last_switch: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// Per-session facts (meta, last heartbeat, summary), reused while the files are unchanged.
    pub index: Arc<std::sync::Mutex<api::SessionIndex>>,
    /// Cached per-session analyzer reports, keyed by stream file stamps.
    pub reports: Arc<std::sync::Mutex<api::ReportCache>>,
    /// Serialises report analyses so parallel viewers share one result.
    pub report_build: Arc<tokio::sync::Mutex<()>>,
    /// Cached result of the most recent passive/active router audit.
    pub router_audit: Arc<tokio::sync::Mutex<Option<crate::router_audit::RouterAudit>>>,
    /// Time of the last active router probe (rate limit).
    pub last_probe: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// Time of the last CVE lookup (rate limit).
    pub last_cve: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// Optional explicit UPnP IGD URL from `[router] upnp_url`.
    pub router_upnp_url: Option<Arc<str>>,
    /// Optional NVD API key from `[router] nvd_api_key`.
    pub nvd_api_key: Option<Arc<str>>,
    /// Read access without a token (see [`WebRouterOpts::open_view`]).
    pub open_view: bool,
}

/// Whether the request carried the configured token (always true when no token is set).
/// The guard middleware adds it to every request that reaches a handler.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Authed(pub bool);

/// Optional router diagnostic settings passed from `[router]` config.
#[derive(Clone, Default)]
pub struct WebRouterOpts {
    pub upnp_url: Option<String>,
    pub nvd_api_key: Option<String>,
    /// `[web] view = "open"`: GET requests need no token; everything else still does.
    pub open_view: bool,
}

/// Concurrent history reads.
const MAX_DISK_READS: usize = 2;
/// Concurrent SSE clients.
const MAX_SSE: usize = 16;
const TOKEN_COOKIE: &str = "linkwatch_token";

/// Serves the UI and API on `listen` until `shutdown` completes.
///
/// Returns an error when the address cannot be bound (the caller logs it and the
/// monitor keeps running).
#[allow(dead_code)]
pub async fn serve(
    listen: SocketAddr,
    live: Live,
    data_dir: PathBuf,
    site: Option<Arc<Site>>,
    token: Option<String>,
    control: Option<ControlHandle>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    serve_with_router(listen, live, data_dir, site, token, control, WebRouterOpts::default(), shutdown).await
}

/// Serves the UI and API on `listen` with router diagnostics options until `shutdown` completes.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_router(
    listen: SocketAddr,
    live: Live,
    data_dir: PathBuf,
    site: Option<Arc<Site>>,
    token: Option<String>,
    control: Option<ControlHandle>,
    opts: WebRouterOpts,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| anyhow::anyhow!("web: cannot listen on {listen}: {e}"))?;
    tracing::info!("web: UI on http://{listen}/{}", if token.is_some() { " (token required)" } else { "" });
    if token.is_none() && !listen.ip().is_loopback() {
        tracing::warn!("web: listening on {listen} without a token: everyone on this network can read the UI");
    }
    if token.is_none() && control.is_some() {
        tracing::info!("web: measurement control is off; set [web] token to switch sessions from the UI");
    }
    serve_on_with_opts(listener, live, data_dir, site, token, control, opts, shutdown).await
}

#[cfg(test)]
pub(crate) async fn serve_on(
    listener: TcpListener,
    live: Live,
    data_dir: PathBuf,
    site: Option<Arc<Site>>,
    token: Option<String>,
    control: Option<ControlHandle>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    serve_on_with_opts(listener, live, data_dir, site, token, control, WebRouterOpts::default(), shutdown).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_on_with_opts(
    listener: TcpListener,
    live: Live,
    data_dir: PathBuf,
    site: Option<Arc<Site>>,
    token: Option<String>,
    control: Option<ControlHandle>,
    opts: WebRouterOpts,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut stop_wait = stop_rx.clone();
    let state = AppState {
        live,
        data_dir: Arc::new(data_dir),
        site,
        stop: stop_rx,
        token: token.map(Arc::from),
        disk: Arc::new(tokio::sync::Semaphore::new(MAX_DISK_READS)),
        sse: Arc::new(tokio::sync::Semaphore::new(MAX_SSE)),
        history: Arc::default(),
        control,
        last_switch: Arc::default(),
        index: Arc::default(),
        reports: Arc::default(),
        report_build: Arc::default(),
        router_audit: Arc::default(),
        last_probe: Arc::default(),
        last_cve: Arc::default(),
        router_upnp_url: opts.upnp_url.map(Arc::from),
        nvd_api_key: opts.nvd_api_key.map(Arc::from),
        open_view: opts.open_view,
    };
    let server = axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            shutdown.await;
            let _ = stop_tx.send(true);
        })
        .into_future();
    tokio::select! {
        r = server => r.map_err(|e| anyhow::anyhow!("web: server error: {e}")),
        _ = async {
            let _ = stop_wait.wait_for(|v| *v).await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => {
            tracing::warn!("web: connections still open at shutdown, stopping anyway");
            Ok(())
        }
    }
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { asset("text/html; charset=utf-8", INDEX_HTML) }),
        )
        .route(
            "/index.html",
            get(|| async { asset("text/html; charset=utf-8", INDEX_HTML) }),
        )
        .route("/js/:name", get(ui_module))
        .route(
            "/style.css",
            get(|| async { asset("text/css; charset=utf-8", STYLE_CSS) }),
        )
        .merge(api::routes())
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Host names a browser may use for the UI without a token. Anything else is refused so a
/// web page cannot read the API through DNS rebinding (attacker domain resolving to this box).
fn host_allowed(host: &str) -> bool {
    let h = match host.strip_prefix('[') {
        Some(v6) => {
            let Some((addr, rest)) = v6.split_once(']') else { return false };
            let port_ok = rest.is_empty()
                || rest
                    .strip_prefix(':')
                    .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
            return port_ok && addr.parse::<std::net::Ipv6Addr>().is_ok();
        }
        None => host.rsplit_once(':').map_or(host, |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { host }),
    };
    let h = h.to_ascii_lowercase();
    h.parse::<std::net::Ipv4Addr>().is_ok()
        || h == "localhost"
        || !h.contains('.')
        || [".local", ".lan", ".home.arpa", ".internal"].iter().any(|s| h.ends_with(s))
}

fn eq_const(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Access control (optional token, Host check) and security headers for every response.
async fn guard(
    axum::extract::State(st): axum::extract::State<AppState>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let headers = req.headers();
    let mut set_cookie = false;
    let mut authed = true;
    // Host check (DNS rebinding defence) for every request that is served without a token.
    let host_refused = |headers: &axum::http::HeaderMap| -> Option<Response> {
        let hdr = headers.get(header::HOST)?;
        let Ok(host) = hdr.to_str() else {
            return Some(secured((StatusCode::FORBIDDEN, "invalid Host header").into_response(), false, None));
        };
        (!host.is_empty() && !host_allowed(host))
            .then(|| secured((StatusCode::FORBIDDEN, "unexpected Host header").into_response(), false, None))
    };
    match &st.token {
        Some(tok) => {
            let tok = tok.as_bytes();
            let bearer = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|v| eq_const(v.trim().as_bytes(), tok));
            let cookie = headers
                .get_all(header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(';'))
                .filter_map(|kv| kv.trim().split_once('='))
                .any(|(k, v)| k == TOKEN_COOKIE && eq_const(v.as_bytes(), tok));
            let query = req
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter_map(|kv| kv.split_once('='))
                .any(|(k, v)| k == "token" && eq_const(v.as_bytes(), tok));
            if bearer || cookie || query {
                set_cookie = query && !cookie;
            } else {
                let read_only = matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD);
                if !(st.open_view && read_only) {
                    return secured((StatusCode::UNAUTHORIZED, "token required: open the UI once with ?token=<token>").into_response(), false, None);
                }
                if let Some(r) = host_refused(headers) {
                    return r;
                }
                authed = false;
            }
        }
        None => {
            if let Some(r) = host_refused(headers) {
                return r;
            }
        }
    }
    req.extensions_mut().insert(Authed(authed));
    let tok = st.token.clone();
    secured(next.run(req).await, set_cookie, tok.as_deref())
}

fn secured(mut r: Response, set_cookie: bool, token: Option<&str>) -> Response {
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if let (true, Some(t)) = (set_cookie, token)
        && let Ok(v) = HeaderValue::from_str(&format!("{TOKEN_COOKIE}={t}; Path=/; HttpOnly; SameSite=Strict"))
    {
        h.insert(header::SET_COOKIE, v);
    }
    r
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    r
}

#[cfg(test)]
mod demo;
#[cfg(test)]
mod tests;
