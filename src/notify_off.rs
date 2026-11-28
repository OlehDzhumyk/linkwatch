//! Stand-in for `notify` in a build without the `alerts` feature. The core (`run`) keeps one code
//! path: it builds `AlertMsg` values and hands them to a `Notifier`. Here the `Notifier` drops them
//! and the loop only tells the user once that alerts are not available. The `[alerts]` config
//! section still parses and validates (see `config::parse_webhook_url`).

use crate::config::Alerts;
use tokio::sync::watch;
use tracing::warn;

/// Same fields as the real message. Nothing reads them in this build.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AlertMsg {
    pub key: String,
    pub title: String,
    pub body: String,
    pub urgent: bool,
}

#[derive(Clone)]
pub struct Notifier;

impl Notifier {
    pub fn send(&self, _msg: AlertMsg) {}
}

pub fn channel() -> (Notifier, ()) {
    (Notifier, ())
}

pub async fn run_loop(_cfg: Alerts, _rx: (), _shutdown: watch::Receiver<bool>) {
    warn!("alerts.enabled = true, but this build has no `alerts` feature: no alert is sent");
}
