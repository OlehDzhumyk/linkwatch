//! Optional webhook / ntfy alert notifications (pure Rust HTTP/HTTPS, non-blocking, rate-limited).

use crate::config::{Alerts, WebhookTarget, parse_webhook_url};
use chrono::{DateTime, TimeDelta, Utc};
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

const CHANNEL_CAP: usize = 32;
const MAX_COOLDOWN_KEYS: usize = 256;
const POST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct AlertMsg {
    pub key: String,
    pub title: String,
    pub body: String,
    pub urgent: bool,
}

#[derive(Clone)]
pub struct Notifier {
    tx: mpsc::Sender<AlertMsg>,
}

impl Notifier {
    /// Queues an alert without blocking the caller; drops if the channel is full.
    pub fn send(&self, msg: AlertMsg) {
        if let Err(e) = self.tx.try_send(msg) {
            debug!("alert dropped (queue full or closed): {e}");
        }
    }
}

pub fn channel() -> (Notifier, mpsc::Receiver<AlertMsg>) {
    let (tx, rx) = mpsc::channel(CHANNEL_CAP);
    (Notifier { tx }, rx)
}

#[derive(Debug, Default)]
pub struct CooldownTracker {
    last: HashMap<String, DateTime<Utc>>,
}

impl CooldownTracker {
    pub fn allow(&mut self, key: &str, now: DateTime<Utc>, cooldown_s: u64) -> bool {
        if let Some(&prev) = self.last.get(key)
            && now - prev < TimeDelta::seconds(cooldown_s as i64)
        {
            return false;
        }
        if self.last.len() >= MAX_COOLDOWN_KEYS && !self.last.contains_key(key)
            && let Some(oldest) = self.last.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| k.clone())
        {
            self.last.remove(&oldest);
        }
        self.last.insert(key.to_string(), now);
        true
    }
}

fn sanitize_hdr(v: &str) -> String {
    v.chars()
        .filter(|&c| !c.is_control())
        .take(180)
        .collect()
}

/// Builds an HTTP/1.1 POST request compatible with both JSON webhooks and ntfy servers.
pub fn build_http_request(t: &WebhookTarget, bearer: Option<&str>, msg: &AlertMsg) -> Vec<u8> {
    let payload = serde_json::json!({
        "key": msg.key,
        "title": msg.title,
        "message": msg.body,
        "urgent": msg.urgent,
        "ts": Utc::now().to_rfc3339(),
    })
    .to_string();
    let host_hdr = if (t.https && t.port == 443) || (!t.https && t.port == 80) {
        t.host.clone()
    } else {
        format!("{}:{}", t.host, t.port)
    };
    let mut req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: linkwatch\r\nContent-Type: application/json\r\nTitle: {}\r\nPriority: {}\r\n",
        t.path,
        host_hdr,
        sanitize_hdr(&msg.title),
        if msg.urgent { "high" } else { "default" }
    );
    if let Some(tok) = bearer.filter(|s| !s.is_empty()) {
        req.push_str(&format!("Authorization: Bearer {}\r\n", sanitize_hdr(tok)));
    }
    req.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n{}", payload.len(), payload));
    req.into_bytes()
}

pub async fn post_alert(cfg: &Alerts, msg: &AlertMsg) -> anyhow::Result<u16> {
    let url = cfg
        .webhook_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("alerts.webhook_url is not set"))?;
    let target = parse_webhook_url(url)?;
    let req = build_http_request(&target, cfg.bearer_token.as_deref(), msg);

    tokio::time::timeout(POST_TIMEOUT, async {
        let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
        let mut head_buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        if target.https {
            let connector = crate::tls::connector()?;
            let sni = ServerName::try_from(target.host.clone())
                .map_err(|_| anyhow::anyhow!("invalid TLS host: {}", target.host))?;
            let mut tls = connector.connect(sni, tcp).await?;
            tls.write_all(&req).await?;
            while head_buf.len() < 8192 {
                let n = tls.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                head_buf.extend_from_slice(&chunk[..n]);
                if head_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        } else {
            let mut tcp = tcp;
            tcp.write_all(&req).await?;
            while head_buf.len() < 8192 {
                let n = tcp.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                head_buf.extend_from_slice(&chunk[..n]);
                if head_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
        let status: u16 = String::from_utf8_lossy(&head_buf)
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        anyhow::ensure!((200..300).contains(&status), "webhook returned HTTP {status}");
        Ok(status)
    })
    .await
    .map_err(|_| anyhow::anyhow!("webhook POST timed out"))?
}

/// Dispatches queued webhook alerts until `shutdown` becomes true.
pub async fn run_loop(cfg: Alerts, mut rx: mpsc::Receiver<AlertMsg>, mut shutdown: watch::Receiver<bool>) {
    let mut tracker = CooldownTracker::default();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            maybe = rx.recv() => {
                let Some(msg) = maybe else { return; };
                if !tracker.allow(&msg.key, Utc::now(), cfg.cooldown_s) {
                    continue;
                }
                if let Err(e) = post_alert(&cfg, &msg).await {
                    warn!(key = %msg.key, "alert delivery failed: {e:#}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_and_https_urls_and_rejects_invalid() {
        assert_eq!(
            parse_webhook_url("https://ntfy.example.com/linkwatch").unwrap(),
            WebhookTarget { https: true, host: "ntfy.example.com".into(), port: 443, path: "/linkwatch".into() }
        );
        assert_eq!(
            parse_webhook_url("http://127.0.0.1:9000/hook").unwrap(),
            WebhookTarget { https: false, host: "127.0.0.1".into(), port: 9000, path: "/hook".into() }
        );
        assert!(parse_webhook_url("ftp://127.0.0.1/x").is_err());
        assert!(parse_webhook_url("http://user:pw@127.0.0.1/hook").is_err());
        assert!(parse_webhook_url("http://").is_err());
    }

    #[test]
    fn cooldown_suppresses_within_window_and_caps_entries() {
        let mut tr = CooldownTracker::default();
        let t0 = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        assert!(tr.allow("k1", t0, 300));
        assert!(!tr.allow("k1", t0 + TimeDelta::seconds(120), 300));
        assert!(tr.allow("k1", t0 + TimeDelta::seconds(301), 300));

        for i in 0..300 {
            assert!(tr.allow(&format!("key-{i}"), t0 + TimeDelta::seconds(i), 10));
        }
        assert!(tr.last.len() <= MAX_COOLDOWN_KEYS);
    }

    #[test]
    fn builds_ntfy_compatible_post_request() {
        let target = parse_webhook_url("https://ntfy.example.com:8443/alerts").unwrap();
        let msg = AlertMsg {
            key: "outage".into(),
            title: "Line down\r\nInjected".into(),
            body: "ISP hop unreachable for 60s".into(),
            urgent: true,
        };
        let raw = String::from_utf8(build_http_request(&target, Some("tok123"), &msg)).unwrap();
        assert!(raw.starts_with("POST /alerts HTTP/1.1\r\n"));
        assert!(raw.contains("Host: ntfy.example.com:8443\r\n"));
        assert!(raw.contains("Title: Line downInjected\r\n"));
        assert!(raw.contains("Priority: high\r\n"));
        assert!(raw.contains("Authorization: Bearer tok123\r\n"));
        assert!(raw.contains("\"urgent\":true"));
    }
}
