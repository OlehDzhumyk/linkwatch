//! Crash-safe JSON Lines storage.
//!
//! One writer task owns all files of a session directory. Producers call
//! [`StoreHandle::send`], which never blocks; when the queue is full the record is
//! counted and a single `DroppedRecords` event is written later.
//!
//! Layout of `<data_dir>/<session>/`:
//! - `meta.json` — [`SessionMeta`], written once (kept when the session is reopened);
//! - `<stream>-YYYYMMDD.jsonl` — one [`Envelope`] per line, per UTC day and stream
//!   (`samples`, `events`, `wifi`, `speed`, `host`); files of earlier days become `.jsonl.gz`;
//! - `heartbeat` — last heartbeat (ts, boot id, monotonic ns), replaced atomically;
//! - `summary.json` — written by [`StoreHandle::close`].
//!
//! `<data_dir>/.lock` is flock-ed for as long as the writer runs, so a second instance
//! on the same data directory fails to open.
//!
//! Crash safety: every line is written in one piece and flushed after each batch, files
//! are fsync-ed every `fsync_s` seconds, and on open a partial or invalid last line is
//! truncated. `seq` continues after the last valid line, so a gap in `seq` means lost records.

mod compress;
mod disk;
pub use disk::free_bytes;
pub mod read;
mod recover;
mod writer;

use crate::config::Storage;
use crate::live::Live;
use crate::model::{Record, SessionMeta, Stream};
use chrono::{DateTime, NaiveDate, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use writer::{Writer, WriterInit};

pub(crate) const META_FILE: &str = "meta.json";
pub(crate) const SUMMARY_FILE: &str = "summary.json";
pub(crate) const HEARTBEAT_FILE: &str = "heartbeat";
const LOCK_FILE: &str = ".lock";
/// Upper bound for waiting on background compression at close.
const CLOSE_COMPRESS_WAIT: Duration = Duration::from_secs(60);

/// Source of wall-clock time for the writer (injectable for tests).
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> DateTime<Utc>;
}

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

type FreeSpaceFn = Arc<dyn Fn(&Path) -> Option<u64> + Send + Sync>;

/// Replaceable dependencies of the writer.
#[derive(Clone)]
pub(crate) struct Hooks {
    pub clock: Arc<dyn Clock>,
    pub free_space: FreeSpaceFn,
    pub disk_check_every: Duration,
}

impl Default for Hooks {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            free_space: Arc::new(disk::free_bytes),
            disk_check_every: Duration::from_secs(10),
        }
    }
}

/// Facts found while opening a session.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenInfo {
    /// Seconds since the last heartbeat of a previous run (this session, else the newest in data_dir).
    pub gap_s: Option<f64>,
    /// Boot id stored in that heartbeat.
    pub prev_boot_id: Option<String>,
    /// First `seq` this run will write.
    pub next_seq: u64,
}

enum Control {
    Close {
        summary: serde_json::Value,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
}

/// Producer side of the store. Cheap to clone.
#[derive(Clone)]
pub struct StoreHandle {
    pub tx: mpsc::Sender<Record>,
    ctl: mpsc::Sender<Control>,
    dropped: Arc<AtomicU64>,
    /// False once the writer task has stopped without a close (records are lost from then on).
    alive: Arc<std::sync::atomic::AtomicBool>,
}

impl StoreHandle {
    /// Never blocks: on a full (or closed) queue the record is counted as dropped and a
    /// `DroppedRecords` event is written later.
    pub fn send(&self, rec: Record) {
        if self.tx.try_send(rec).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records dropped because the queue was full, since open.
    #[cfg(test)]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// True while the writer task runs. The monitor stops feeding the systemd watchdog
    /// when this turns false, so a dead writer leads to a restart instead of silent data loss.
    pub fn writer_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed) && !self.tx.is_closed()
    }

    /// Drains the queue, flushes, fsyncs, writes summary.json and stops the writer.
    pub async fn close(self, summary: serde_json::Value) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.ctl
            .send(Control::Close { summary, reply })
            .await
            .map_err(|_| anyhow::anyhow!("store writer is not running"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("store writer stopped before close finished"))?
    }
}

/// Boot id of the running kernel, or "unknown".
pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Creates/opens `<data_dir>/<session>/`, takes the exclusive lock, writes meta.json,
/// repairs files after a crash, continues `seq`, and starts the writer task.
pub async fn open(
    data_dir: &Path,
    meta: SessionMeta,
    cfg: &Storage,
    live: Live,
) -> anyhow::Result<(StoreHandle, OpenInfo)> {
    open_with(data_dir, meta, cfg, live, Hooks::default()).await
}

pub(crate) async fn open_with(
    data_dir: &Path,
    meta: SessionMeta,
    cfg: &Storage,
    live: Live,
    hooks: Hooks,
) -> anyhow::Result<(StoreHandle, OpenInfo)> {
    validate_session_name(&meta.session)?;
    let data_dir = data_dir.to_path_buf();
    let clock = hooks.clock.clone();
    let prep = tokio::task::spawn_blocking(move || prepare(&data_dir, &meta, clock.as_ref()))
        .await
        .map_err(|e| anyhow::anyhow!("store open task failed: {e}"))??;

    let queue_dropped = Arc::new(AtomicU64::new(0));
    let run = uuid::Uuid::new_v4().simple().to_string();
    let (tx, rx) = mpsc::channel(cfg.queue.max(1));
    let (ctl, ctl_rx) = mpsc::channel(1);
    let info = prep.info.clone();
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut w = Writer::new(WriterInit {
        dir: prep.session_dir,
        data_dir: prep.data_dir,
        run,
        next_seq: prep.info.next_seq,
        last_day: prep.last_day,
        cfg: cfg.clone(),
        live,
        hooks,
        rt: tokio::runtime::Handle::current(),
        queue_dropped: queue_dropped.clone(),
        boot_id: boot_id(),
        lock: prep.lock,
    });
    w.compress_old(prep.old_files);
    let alive2 = alive.clone();
    tokio::spawn(async move {
        run_writer(w, rx, ctl_rx).await;
        alive2.store(false, Ordering::Relaxed);
    });
    Ok((
        StoreHandle {
            tx,
            ctl,
            dropped: queue_dropped,
            alive,
        },
        info,
    ))
}

struct Prepared {
    data_dir: PathBuf,
    session_dir: PathBuf,
    lock: fd_lock::RwLock<File>,
    info: OpenInfo,
    last_day: Option<NaiveDate>,
    old_files: Vec<PathBuf>,
}

fn validate_session_name(s: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !s.is_empty()
            && s.len() <= 128
            && !s.starts_with('.')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
        "invalid session name {s:?}: use letters, digits, '-', '_' or '.'"
    );
    Ok(())
}

/// Blocking part of `open`.
fn prepare(data_dir: &Path, meta: &SessionMeta, clock: &dyn Clock) -> anyhow::Result<Prepared> {
    fs::create_dir_all(data_dir)
        .map_err(|e| anyhow::anyhow!("cannot create data dir {}: {e}", data_dir.display()))?;
    let lock = take_lock(data_dir)?;
    let session_dir = data_dir.join(&meta.session);
    fs::create_dir_all(&session_dir)
        .map_err(|e| anyhow::anyhow!("cannot create session dir {}: {e}", session_dir.display()))?;

    let meta_path = session_dir.join(META_FILE);
    if read::read_json_file::<SessionMeta>(&meta_path).is_none() {
        let bytes = serde_json::to_vec_pretty(meta)?;
        write_atomic(&meta_path, &bytes)
            .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", meta_path.display()))?;
    }

    let now = clock.now();
    let rec = recover::recover_session(&session_dir, now.date_naive()).map_err(|e| {
        anyhow::anyhow!("cannot recover session dir {}: {e}", session_dir.display())
    })?;
    let hb = recover::latest_heartbeat(&session_dir);
    let info = OpenInfo {
        gap_s: hb
            .as_ref()
            .map(|h| (now - h.ts).num_milliseconds() as f64 / 1000.0),
        prev_boot_id: hb.map(|h| h.boot_id),
        next_seq: rec.next_seq,
    };
    tracing::info!(
        dir = %session_dir.display(),
        next_seq = info.next_seq,
        gap_s = ?info.gap_s,
        truncated_bytes = rec.truncated_bytes,
        "store: session opened"
    );
    Ok(Prepared {
        data_dir: data_dir.to_path_buf(),
        session_dir,
        lock,
        info,
        last_day: rec.last_day,
        old_files: rec.old_files,
    })
}

/// Takes the exclusive flock on `<data_dir>/.lock`.
fn take_lock(data_dir: &Path) -> anyhow::Result<fd_lock::RwLock<File>> {
    let path = data_dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("cannot open lock file {}: {e}", path.display()))?;
    let mut lock = fd_lock::RwLock::new(file);
    match lock.try_write() {
        // The flock belongs to the open file; it stays until the file is closed
        // (when the writer drops `lock`). Forgetting the guard keeps it held.
        Ok(guard) => std::mem::forget(guard),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            anyhow::bail!(
                "data dir {} is in use by another linkwatch instance (lock {} is held)",
                data_dir.display(),
                path.display()
            )
        }
        Err(e) => anyhow::bail!("cannot lock {}: {e}", path.display()),
    }
    Ok(lock)
}

/// Async half of the writer: receives batches and runs [`Writer`] methods on a blocking thread.
async fn run_writer(w: Writer, mut rx: mpsc::Receiver<Record>, mut ctl: mpsc::Receiver<Control>) {
    let mut w = Some(w);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ctl_open = true;
    loop {
        let mut batch = Vec::new();
        tokio::select! {
            biased;
            c = ctl.recv(), if ctl_open => match c {
                Some(Control::Close { summary, reply }) => {
                    rx.close();
                    let mut rest = Vec::new();
                    while rx.recv_many(&mut rest, 1024).await > 0 {}
                    let res = match w.take() {
                        Some(writer) => finish(writer, rest, Some(summary)).await,
                        None => Err(anyhow::anyhow!("store writer failed earlier")),
                    };
                    let _ = reply.send(res);
                    return;
                }
                None => ctl_open = false,
            },
            n = rx.recv_many(&mut batch, 512) => {
                if n == 0 {
                    // Every handle dropped without close: flush and stop.
                    if let Some(writer) = w.take()
                        && let Err(e) = finish(writer, Vec::new(), None).await
                    {
                        tracing::error!(error = %e, "store: final flush failed");
                    }
                    return;
                }
                w = blocking(w, move |w| w.process(batch)).await;
            }
            _ = tick.tick() => {
                w = blocking(w, |w| w.maintain()).await;
            }
        }
        if w.is_none() {
            tracing::error!("store: writer task lost its state; records are no longer stored");
            return;
        }
    }
}

async fn blocking(
    w: Option<Writer>,
    f: impl FnOnce(&mut Writer) + Send + 'static,
) -> Option<Writer> {
    let mut w = w?;
    match tokio::task::spawn_blocking(move || {
        f(&mut w);
        w
    })
    .await
    {
        Ok(w) => Some(w),
        Err(e) => {
            tracing::error!(error = %e, "store: writer step failed");
            None
        }
    }
}

async fn finish(
    w: Writer,
    rest: Vec<Record>,
    summary: Option<serde_json::Value>,
) -> anyhow::Result<()> {
    let joined = tokio::task::spawn_blocking(move || {
        let mut w = w;
        if !rest.is_empty() {
            w.process(rest);
        }
        let res = w.finish(summary);
        (w.take_compressions(), res, w)
    })
    .await
    .map_err(|e| anyhow::anyhow!("store close task failed: {e}"))?;
    let (compressions, res, w) = joined;
    let wait = async {
        for h in compressions {
            let _ = h.await;
        }
    };
    if tokio::time::timeout(CLOSE_COMPRESS_WAIT, wait)
        .await
        .is_err()
    {
        tracing::warn!("store: compression still running at close");
    }
    // Releases the lock after compression is done.
    drop(w);
    res
}

/// `<stream>-YYYYMMDD.jsonl`.
pub(crate) fn stream_file_name(stream: Stream, day: NaiveDate) -> String {
    format!("{}-{}.jsonl", stream.name(), day.format("%Y%m%d"))
}

/// A stream file found in a session directory.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StreamFile {
    pub stream: Stream,
    pub day: NaiveDate,
    pub gz: bool,
    pub path: PathBuf,
}

fn stream_from_name(s: &str) -> Option<Stream> {
    Stream::ALL.into_iter().find(|st| st.name() == s)
}

pub(crate) fn parse_stream_file(path: &Path) -> Option<StreamFile> {
    let name = path.file_name()?.to_str()?;
    let (base, gz) = match name.strip_suffix(".jsonl.gz") {
        Some(b) => (b, true),
        None => (name.strip_suffix(".jsonl")?, false),
    };
    let (stream, date) = base.split_once('-')?;
    if date.len() != 8 {
        return None;
    }
    let day = NaiveDate::parse_from_str(date, "%Y%m%d").ok()?;
    Some(StreamFile {
        stream: stream_from_name(stream)?,
        day,
        gz,
        path: path.to_path_buf(),
    })
}

/// Stream files of `dir`, sorted by day; for one day the `.gz` comes before the `.jsonl`.
pub(crate) fn list_stream_files(dir: &Path) -> io::Result<Vec<StreamFile>> {
    let mut v: Vec<StreamFile> = fs::read_dir(dir)?
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| parse_stream_file(&e.path()))
        .collect();
    v.sort_by(|a, b| {
        a.day
            .cmp(&b.day)
            .then(b.gz.cmp(&a.gz))
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(v)
}

/// Writes `path` atomically: `<path>.tmp`, fsync, rename, fsync of the directory.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let res = (|| {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res?;
    if let Some(dir) = path.parent() {
        sync_dir(dir);
    }
    Ok(())
}

/// Best-effort fsync of a directory (makes renames durable on Linux).
pub(crate) fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(test)]
mod tests;
