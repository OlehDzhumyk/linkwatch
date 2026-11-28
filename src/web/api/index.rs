//! Session index: per-session facts (meta, last heartbeat, summary) read once and reused
//! while the files are unchanged. Shared by `/api/sessions`, `/api/plan` and `/api/control`.

use crate::store::read;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Sessions shorter than this are hidden in lists and do not count in the plan
/// (a quick restart or a wrong choice that was corrected at once).
pub(crate) const MIN_SESSION_S: f64 = 60.0;
/// Most session directories scanned for one index.
const MAX_INDEX_DIRS: usize = 2000;

/// What the API needs of one session directory (meta without its config, heartbeat, summary).
#[derive(Debug, Clone)]
pub(crate) struct IndexedSession {
    pub id: String,
    pub started: DateTime<Utc>,
    pub host: String,
    pub version: String,
    pub point: Option<String>,
    pub label: Option<String>,
    pub note: Option<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub summary: Option<Value>,
}

impl IndexedSession {
    /// Last heartbeat minus start; None without a heartbeat.
    pub fn recorded_s(&self) -> Option<f64> {
        self.last_seen.map(|t| ((t - self.started).num_milliseconds() as f64 / 1000.0).max(0.0))
    }

    /// Duration for lists and the plan: up to now for the running session.
    pub(super) fn duration_s(&self, current: Option<&str>, now: DateTime<Utc>) -> Option<f64> {
        if current == Some(self.id.as_str()) {
            Some(((now - self.started).num_milliseconds() as f64 / 1000.0).max(0.0))
        } else {
            self.recorded_s()
        }
    }

    /// Too short to list or count (never true for the running session).
    pub(super) fn tiny(&self, current: Option<&str>, now: DateTime<Utc>) -> bool {
        current != Some(self.id.as_str()) && self.duration_s(current, now).is_none_or(|d| d < MIN_SESSION_S)
    }

    pub(super) fn availability_pct(&self) -> Option<f64> {
        self.summary.as_ref()?.get("availability_pct")?.as_f64().filter(|v| v.is_finite())
    }

    /// Drops in the summary: state changes of the worst interface, two per drop (down and up).
    pub(super) fn drops(&self) -> Option<u64> {
        let t = self.summary.as_ref()?.get("transitions")?.as_object()?;
        let worst = t.values().filter_map(Value::as_u64).max().unwrap_or(0);
        Some(worst.div_ceil(2))
    }

    pub(super) fn verdict(&self) -> Option<String> {
        self.summary.as_ref()?.get("verdict")?.as_str().map(str::to_string)
    }
}

/// Cached [`IndexedSession`]s by directory name with a stamp of their small files.
#[derive(Default)]
pub(crate) struct SessionIndex {
    entries: HashMap<String, (String, Arc<IndexedSession>)>,
}

fn file_stamp(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(m) => {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            format!("{}:{mtime}", m.len())
        }
        Err(_) => "-".into(),
    }
}

/// All sessions of `data_dir` (at most `MAX_INDEX_DIRS`, the newest by name), oldest first.
/// Only directories whose meta, heartbeat or summary changed are read again.
pub(crate) fn index_sessions(data_dir: &Path, cache: &std::sync::Mutex<SessionIndex>) -> Vec<Arc<IndexedSession>> {
    let Ok(rd) = std::fs::read_dir(data_dir) else { return Vec::new() };
    let mut names: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    names.sort_unstable_by(|a, b| b.cmp(a));
    names.truncate(MAX_INDEX_DIRS);
    let mut idx = cache.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = Vec::with_capacity(names.len());
    let mut seen = std::collections::HashSet::new();
    for name in names {
        let dir = data_dir.join(&name);
        let stamp = [crate::store::META_FILE, crate::store::HEARTBEAT_FILE, crate::store::SUMMARY_FILE]
            .iter()
            .map(|f| file_stamp(&dir.join(f)))
            .collect::<Vec<_>>()
            .join("|");
        seen.insert(name.clone());
        if let Some((s, e)) = idx.entries.get(&name)
            && *s == stamp
        {
            out.push(e.clone());
            continue;
        }
        let Some(meta) = read::read_json_file::<crate::model::SessionMeta>(&dir.join(crate::store::META_FILE)) else {
            idx.entries.remove(&name);
            continue;
        };
        let e = Arc::new(IndexedSession {
            id: name.clone(),
            started: meta.started,
            host: meta.host,
            version: meta.version,
            point: meta.point,
            label: meta.label,
            note: meta.note,
            last_seen: read::last_heartbeat(&dir),
            summary: read::summary(&dir),
        });
        idx.entries.insert(name, (stamp, e.clone()));
        out.push(e);
    }
    idx.entries.retain(|k, _| seen.contains(k));
    out.sort_by(|a, b| a.started.cmp(&b.started).then_with(|| a.id.cmp(&b.id)));
    out
}
