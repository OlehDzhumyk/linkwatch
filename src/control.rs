//! Measurement control: start a new session (another point, label or note) without a restart.
//!
//! The web API validates a [`SessionRequest`] and sends a [`Command`] over a bounded channel to
//! the run loop (`run::run`). The run loop stops the current session cleanly (`stop` event with
//! reason `"switch"`, summary.json), opens a new one and answers with its id.
//!
//! The active choice is kept in `<data_dir>/control.json` (written atomically), so a restart
//! or reboot continues at the chosen point. Precedence at start: command-line flags, then
//! control.json, then `[site]` in the config.

use crate::site::Site;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::sync::{mpsc, oneshot};

/// File in the data directory that keeps the active choice.
pub const CONTROL_FILE: &str = "control.json";
/// Longest point, label or note (characters).
pub const MAX_TEXT: usize = 200;
/// Commands waiting for the run loop. A full queue means a switch is in progress.
const QUEUE: usize = 2;

/// What to measure next. Empty strings are the same as no value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    #[serde(default)]
    pub point: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

fn clean(what: &str, v: Option<String>) -> Result<Option<String>, String> {
    let Some(v) = v else { return Ok(None) };
    let v = v.trim();
    if v.is_empty() {
        return Ok(None);
    }
    if v.chars().count() > MAX_TEXT {
        return Err(format!("{what} is longer than {MAX_TEXT} characters"));
    }
    if v.chars().any(char::is_control) {
        return Err(format!("{what} contains control characters"));
    }
    Ok(Some(v.to_string()))
}

/// Longest free-text point id (used when no site file is configured).
pub const MAX_FREE_POINT: usize = 64;

/// Without a site file a point is a free-text id: 1..=64 characters of `[A-Za-z0-9 _./-]`.
fn check_free_point(p: &str) -> Result<(), String> {
    if p.chars().count() > MAX_FREE_POINT {
        return Err(format!("point is longer than {MAX_FREE_POINT} characters"));
    }
    if !p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '.' | '/' | '-')) {
        return Err("point may only contain letters A-Z, digits, spaces and _ . / -".into());
    }
    Ok(())
}

impl SessionRequest {
    /// Trims the fields and checks them. When a site is configured, the point must be one of
    /// its points. The error text is shown to the user.
    pub fn validated(self, site: Option<&Site>) -> Result<SessionRequest, String> {
        let point = clean("point", self.point)?;
        let label = clean("label", self.label)?;
        let note = clean("note", self.note)?;
        if let Some(p) = &point {
            match site {
                Some(s) if s.point(p).is_none() => {
                    return Err(format!("point {p:?} is not defined in the site file"));
                }
                Some(_) => {}
                None => check_free_point(p)?,
            }
        }
        Ok(SessionRequest { point, label, note })
    }
}

/// Answer of the run loop: the new session id, or why the switch failed.
pub type Reply = oneshot::Sender<Result<String, String>>;

pub enum Command {
    /// Close the running session and start a new one with these (validated) parameters.
    StartSession { req: SessionRequest, reply: Reply },
}

/// Sender side, held by the web server.
#[derive(Clone)]
pub struct ControlHandle {
    tx: mpsc::Sender<Command>,
}

pub fn channel() -> (ControlHandle, mpsc::Receiver<Command>) {
    let (tx, rx) = mpsc::channel(QUEUE);
    (ControlHandle { tx }, rx)
}

/// Why a command did not reach the run loop or got no answer.
#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// Another switch is being processed.
    Busy,
    /// The run loop has stopped.
    Closed,
    /// The run loop answered with an error.
    Failed(String),
}

impl ControlHandle {
    /// Asks the run loop to start a new session; waits for the new id.
    pub async fn start_session(&self, req: SessionRequest) -> Result<String, SendError> {
        let (reply, rx) = oneshot::channel();
        self.tx.try_send(Command::StartSession { req, reply }).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => SendError::Busy,
            mpsc::error::TrySendError::Closed(_) => SendError::Closed,
        })?;
        match rx.await {
            Ok(Ok(id)) => Ok(id),
            Ok(Err(e)) => Err(SendError::Failed(e)),
            Err(_) => Err(SendError::Closed),
        }
    }
}

/// Contents of control.json.
#[derive(Debug, Serialize)]
struct Persisted {
    v: u32,
    #[serde(flatten)]
    req: SessionRequest,
    set_at: chrono::DateTime<chrono::Utc>,
}

/// The persisted choice, if control.json exists and is valid.
pub fn load(data_dir: &Path) -> Option<SessionRequest> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        point: Option<String>,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        note: Option<String>,
    }
    let path = data_dir.join(CONTROL_FILE);
    if !path.exists() {
        return None;
    }
    match crate::store::read::read_json_file::<Raw>(&path) {
        Some(r) => Some(SessionRequest { point: r.point, label: r.label, note: r.note }),
        None => {
            tracing::warn!(path = %path.display(), "control: cannot read the saved measurement choice; ignored");
            None
        }
    }
}

/// Writes control.json atomically (temporary file, fsync, rename).
pub fn save(data_dir: &Path, req: &SessionRequest) -> std::io::Result<()> {
    let p = Persisted { v: 1, req: req.clone(), set_at: chrono::Utc::now() };
    let bytes = serde_json::to_vec_pretty(&p).map_err(std::io::Error::other)?;
    crate::store::write_atomic(&data_dir.join(CONTROL_FILE), &bytes)
}

/// Where the parameters of the first session come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Cli,
    ControlFile,
    Config,
}

/// Parameters of the first session: command-line flags, else control.json, else `[site]`.
/// A saved point that the site file no longer has is ignored (with a warning).
pub fn initial(
    cli: &SessionRequest,
    saved: Option<SessionRequest>,
    config: &SessionRequest,
    site: Option<&Site>,
) -> (SessionRequest, Source) {
    if cli.point.is_some() || cli.label.is_some() {
        let req = SessionRequest {
            point: cli.point.clone().or_else(|| config.point.clone()),
            label: cli.label.clone().or_else(|| config.label.clone()),
            note: None,
        };
        return (req, Source::Cli);
    }
    if let Some(s) = saved {
        match s.validated(site) {
            Ok(v) => return (v, Source::ControlFile),
            Err(e) => tracing::warn!("control: saved measurement choice ignored: {e}"),
        }
    }
    (config.clone(), Source::Config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(point: Option<&str>, label: Option<&str>, note: Option<&str>) -> SessionRequest {
        SessionRequest { point: point.map(Into::into), label: label.map(Into::into), note: note.map(Into::into) }
    }

    #[test]
    fn validation_trims_and_rejects() {
        let r = req(Some(" B1/F1/R1 "), Some(""), Some("  window open ")).validated(None).unwrap();
        assert_eq!(r, req(Some("B1/F1/R1"), None, Some("window open")));
        let long = "x".repeat(MAX_TEXT + 1);
        assert!(req(None, Some(&long), None).validated(None).unwrap_err().contains("longer"));
        assert!(req(None, Some(&"é".repeat(MAX_TEXT)), None).validated(None).is_ok());
        assert!(req(None, None, Some("a\nb")).validated(None).unwrap_err().contains("control"));
        assert!(req(None, None, Some("a\u{1b}[31m")).validated(None).is_err());
        // Without a site: free-text point ids.
        assert_eq!(req(Some("Living room/desk 2"), None, None).validated(None).unwrap().point.as_deref(), Some("Living room/desk 2"));
        assert!(req(Some(&"p".repeat(MAX_FREE_POINT + 1)), None, None).validated(None).unwrap_err().contains("longer"));
        assert!(req(Some("kitchen<script>"), None, None).validated(None).unwrap_err().contains("only contain"));
        assert!(req(Some("Küche"), None, None).validated(None).is_err());
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site.toml");
        let site = Site::load(&path).unwrap();
        assert!(req(Some("B1/F2/R3"), None, None).validated(Some(&site)).is_ok());
        assert!(req(Some("Living room"), None, None).validated(Some(&site)).is_err());
        let e = req(Some("B9/F1/R1"), None, None).validated(Some(&site)).unwrap_err();
        assert!(e.contains("not defined"), "{e}");
    }

    #[test]
    fn json_body_rejects_unknown_fields() {
        assert!(serde_json::from_str::<SessionRequest>(r#"{"point":"a","x":1}"#).is_err());
        let r: SessionRequest = serde_json::from_str(r#"{"label":"night"}"#).unwrap();
        assert_eq!(r, req(None, Some("night"), None));
    }

    #[test]
    fn save_load_and_precedence() {
        let d = tempfile::tempdir().unwrap();
        assert!(load(d.path()).is_none());
        save(d.path(), &req(Some("B1/F1/K"), Some("night 2"), Some("door closed"))).unwrap();
        assert!(!d.path().join("control.json.tmp").exists());
        let saved = load(d.path()).unwrap();
        assert_eq!(saved, req(Some("B1/F1/K"), Some("night 2"), Some("door closed")));

        let cfg = req(Some("B1/F2/R3"), Some("cfg"), None);
        let none = SessionRequest::default();
        assert_eq!(initial(&none, Some(saved.clone()), &cfg, None), (saved.clone(), Source::ControlFile));
        let cli = req(Some("B2/F1/R1"), None, None);
        assert_eq!(initial(&cli, Some(saved.clone()), &cfg, None), (req(Some("B2/F1/R1"), Some("cfg"), None), Source::Cli));
        assert_eq!(initial(&none, None, &cfg, None), (cfg.clone(), Source::Config));

        // A saved point that the site no longer has falls back to the config.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/site.toml");
        let site = Site::load(&path).unwrap();
        let gone = req(Some("B7/F1/R1"), None, None);
        assert_eq!(initial(&none, Some(gone), &cfg, Some(&site)).1, Source::Config);

        std::fs::write(d.path().join(CONTROL_FILE), b"{not json").unwrap();
        assert!(load(d.path()).is_none());
    }

    #[tokio::test]
    async fn handle_reports_busy_and_closed() {
        let (h, mut rx) = channel();
        let t = tokio::spawn(async move {
            if let Some(Command::StartSession { req, reply }) = rx.recv().await {
                let _ = reply.send(Ok(format!("id-{}", req.point.unwrap_or_default())));
            }
            if let Some(Command::StartSession { reply, .. }) = rx.recv().await {
                let _ = reply.send(Err("disk full".into()));
            }
        });
        assert_eq!(h.start_session(req(Some("p"), None, None)).await, Ok("id-p".into()));
        assert_eq!(h.start_session(SessionRequest::default()).await, Err(SendError::Failed("disk full".into())));
        t.await.unwrap();
        assert_eq!(h.start_session(SessionRequest::default()).await, Err(SendError::Closed));
    }
}
