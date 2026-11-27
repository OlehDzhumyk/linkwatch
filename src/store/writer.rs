//! The synchronous half of the store. [`Writer`] owns every open file of a session.
//! Its methods run on a blocking thread, one call at a time (see `super::run_writer`).
//! No method panics or returns early on IO errors: failures are logged, the affected
//! stream backs off and is reopened later, and lost records are counted.

use super::recover::{self, Heartbeat};
use super::{HEARTBEAT_FILE, Hooks, SUMMARY_FILE, compress, stream_file_name, write_atomic};
use crate::config::Storage;
use crate::live::{EVENTS_KEPT, Live};
use crate::model::{Envelope, EventKind, Record, SCHEMA_VERSION, Stream, mono_ns};
use chrono::{DateTime, NaiveDate, SubsecRound, Utc};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// What the writer stores, decided from free disk space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiskMode {
    Normal,
    /// Below `min_free_bytes`: drop samples and Wi-Fi records, keep events and speed tests.
    EventsOnly,
    /// Below `critical_free_bytes`: write nothing (live feed still works).
    Stopped,
}

impl DiskMode {
    pub(crate) fn name(self) -> &'static str {
        match self {
            DiskMode::Normal => "normal",
            DiskMode::EventsOnly => "events_only",
            DiskMode::Stopped => "stopped",
        }
    }

    fn allows(self, s: Stream) -> bool {
        match self {
            DiskMode::Normal => true,
            DiskMode::EventsOnly => matches!(s, Stream::Events | Stream::Speed),
            DiskMode::Stopped => false,
        }
    }

    pub(crate) fn classify(free: u64, cfg: &Storage) -> Self {
        if free < cfg.critical_free_bytes {
            DiskMode::Stopped
        } else if free < cfg.min_free_bytes {
            DiskMode::EventsOnly
        } else {
            DiskMode::Normal
        }
    }
}

struct OpenFile {
    day: NaiveDate,
    path: PathBuf,
    w: BufWriter<File>,
    /// Lines written into the buffer since the last successful flush.
    unflushed: u64,
    unsynced: bool,
}

struct Retry {
    at: Instant,
    delay: Duration,
}

/// Everything the writer needs, built by `super::open`.
pub(crate) struct WriterInit {
    pub dir: PathBuf,
    pub data_dir: PathBuf,
    pub run: String,
    pub next_seq: u64,
    pub last_day: Option<NaiveDate>,
    pub cfg: Storage,
    pub live: Live,
    pub hooks: Hooks,
    pub rt: tokio::runtime::Handle,
    pub queue_dropped: Arc<AtomicU64>,
    pub boot_id: String,
    pub lock: fd_lock::RwLock<File>,
}

pub(crate) struct Writer {
    dir: PathBuf,
    data_dir: PathBuf,
    run: String,
    next_seq: u64,
    last_day: Option<NaiveDate>,
    cfg: Storage,
    live: Live,
    hooks: Hooks,
    rt: tokio::runtime::Handle,
    files: HashMap<Stream, OpenFile>,
    retry: HashMap<Stream, Retry>,
    mode: DiskMode,
    last_disk_check: Option<Instant>,
    last_fsync: Instant,
    queue_dropped: Arc<AtomicU64>,
    io_lost: u64,
    disk_skipped: u64,
    reported_drops: u64,
    published_drops: u64,
    heartbeat_failing: bool,
    compressions: Vec<JoinHandle<()>>,
    boot_id: String,
    /// Holds the flock on `<data_dir>/.lock`; released when the writer is dropped.
    _lock: fd_lock::RwLock<File>,
}

impl Writer {
    pub(crate) fn new(i: WriterInit) -> Self {
        Self {
            dir: i.dir,
            data_dir: i.data_dir,
            run: i.run,
            next_seq: i.next_seq,
            last_day: i.last_day,
            cfg: i.cfg,
            live: i.live,
            hooks: i.hooks,
            rt: i.rt,
            files: HashMap::new(),
            retry: HashMap::new(),
            mode: DiskMode::Normal,
            last_disk_check: None,
            last_fsync: Instant::now(),
            queue_dropped: i.queue_dropped,
            io_lost: 0,
            disk_skipped: 0,
            reported_drops: 0,
            published_drops: 0,
            heartbeat_failing: false,
            compressions: Vec::new(),
            boot_id: i.boot_id,
            _lock: i.lock,
        }
    }

    /// Writes one batch from the queue.
    pub(crate) fn process(&mut self, batch: Vec<Record>) {
        self.check_disk();
        self.emit_pending_drops();
        for rec in batch {
            self.write_record(rec);
        }
        self.flush_all();
        self.maybe_fsync(false);
        self.publish_drop_total();
    }

    /// Periodic work without new records (called about once per second).
    pub(crate) fn maintain(&mut self) {
        self.check_disk();
        self.rotate_idle();
        self.emit_pending_drops();
        self.flush_all();
        self.maybe_fsync(false);
        self.publish_drop_total();
        self.compressions.retain(|h| !h.is_finished());
    }

    /// Final flush and fsync; writes summary.json when given.
    pub(crate) fn finish(&mut self, summary: Option<serde_json::Value>) -> anyhow::Result<()> {
        self.emit_pending_drops();
        self.flush_all();
        self.maybe_fsync(true);
        self.publish_drop_total();
        let lost = self.queue_dropped.load(Ordering::Relaxed) + self.io_lost;
        if lost > 0 || self.disk_skipped > 0 {
            tracing::warn!(
                lost,
                disk_skipped = self.disk_skipped,
                "store: closing with lost records"
            );
        }
        for (_, f) in self.files.drain() {
            drop(f.w.into_parts());
        }
        if let Some(s) = summary {
            let bytes = serde_json::to_vec_pretty(&s)?;
            write_atomic(&self.dir.join(SUMMARY_FILE), &bytes).map_err(|e| {
                anyhow::anyhow!(
                    "cannot write {}: {e}",
                    self.dir.join(SUMMARY_FILE).display()
                )
            })?;
        }
        Ok(())
    }

    /// Background gzip tasks still running (awaited by `close`).
    pub(crate) fn take_compressions(&mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.compressions)
    }

    /// Starts background compression of files from earlier days (found on open).
    pub(crate) fn compress_old(&mut self, files: Vec<PathBuf>) {
        if !self.cfg.compress_old {
            return;
        }
        for p in files {
            self.spawn_compress(p);
        }
    }

    fn now(&self) -> DateTime<Utc> {
        self.hooks.clock.now().trunc_subsecs(3)
    }

    fn write_record(&mut self, rec: Record) {
        let env = Envelope {
            v: SCHEMA_VERSION,
            run: self.run.clone(),
            seq: self.next_seq,
            ts: self.now(),
            mono_ns: mono_ns(),
            rec,
        };
        self.next_seq += 1;
        let stream = env.rec.stream();
        if self.mode.allows(stream) {
            if self.append(stream, &env).is_err() {
                self.io_lost += 1;
            }
            if matches!(env.rec, Record::Heartbeat { .. }) {
                self.write_heartbeat(&env);
            }
        } else {
            self.disk_skipped += 1;
        }
        self.publish(env);
    }

    fn publish(&self, env: Envelope) {
        let env = Arc::new(env);
        if matches!(env.rec, Record::Event(_)) {
            self.live.update(|s| {
                s.events.push_back((*env).clone());
                while s.events.len() > EVENTS_KEPT {
                    s.events.pop_front();
                }
            });
        }
        // No receivers is normal (no web clients).
        let _ = self.live.feed.send(env);
    }

    fn publish_drop_total(&mut self) {
        let total = self.queue_dropped.load(Ordering::Relaxed) + self.io_lost;
        if total != self.published_drops {
            self.published_drops = total;
            self.live.update(|s| s.dropped_records = total);
        }
    }

    /// Writes one DroppedRecords event for drops not yet reported.
    fn emit_pending_drops(&mut self) {
        let total = self.queue_dropped.load(Ordering::Relaxed) + self.io_lost;
        let pending = total.saturating_sub(self.reported_drops);
        if pending == 0 {
            return;
        }
        if self
            .retry
            .get(&Stream::Events)
            .is_some_and(|r| Instant::now() < r.at)
        {
            return; // the event would be lost too; report when the events file works again
        }
        self.reported_drops = total;
        tracing::warn!(count = pending, "store: records dropped");
        self.write_record(Record::Event(EventKind::DroppedRecords { count: pending }));
    }

    /// Day of the file a record goes to. Never moves backwards (clock jumps).
    fn effective_day(&mut self, ts: DateTime<Utc>) -> NaiveDate {
        let d = ts.date_naive();
        let d = match self.last_day {
            Some(l) if l > d => l,
            _ => d,
        };
        self.last_day = Some(d);
        d
    }

    fn append(&mut self, stream: Stream, env: &Envelope) -> Result<(), ()> {
        let mut line = match serde_json::to_vec(env) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "store: cannot serialize record");
                return Err(());
            }
        };
        line.push(b'\n');
        let day = self.effective_day(env.ts);
        if self.files.get(&stream).is_some_and(|f| f.day != day) {
            self.close_file(stream, true);
        }
        if !self.files.contains_key(&stream) {
            self.open_file(stream, day)?;
        }
        let res = match self.files.get_mut(&stream) {
            Some(f) => f.w.write_all(&line).map(|()| {
                f.unflushed += 1;
                f.unsynced = true;
            }),
            None => return Err(()),
        };
        res.map_err(|e| self.fail_file(stream, &e))
    }

    fn open_file(&mut self, stream: Stream, day: NaiveDate) -> Result<(), ()> {
        if self
            .retry
            .get(&stream)
            .is_some_and(|r| Instant::now() < r.at)
        {
            return Err(());
        }
        let path = self.dir.join(stream_file_name(stream, day));
        match open_append(&path) {
            Ok(file) => {
                self.files.insert(
                    stream,
                    OpenFile {
                        day,
                        path,
                        w: BufWriter::with_capacity(64 * 1024, file),
                        unflushed: 0,
                        unsynced: false,
                    },
                );
                Ok(())
            }
            Err(e) => {
                self.schedule_retry(stream, &e, &path);
                Err(())
            }
        }
    }

    fn schedule_retry(&mut self, stream: Stream, e: &io::Error, path: &Path) {
        let delay = self
            .retry
            .get(&stream)
            .map_or(BACKOFF_MIN, |r| (r.delay * 2).min(BACKOFF_MAX));
        tracing::warn!(
            path = %path.display(),
            error = %e,
            retry_in_s = delay.as_secs(),
            "store: write failed, will reopen"
        );
        self.retry.insert(
            stream,
            Retry {
                at: Instant::now() + delay,
                delay,
            },
        );
    }

    /// Drops a broken file without flushing its buffer and schedules a reopen.
    fn fail_file(&mut self, stream: Stream, e: &io::Error) {
        let path = match self.files.remove(&stream) {
            Some(f) => {
                self.io_lost += f.unflushed;
                drop(f.w.into_parts());
                f.path
            }
            None => self.dir.join(stream.name()),
        };
        self.schedule_retry(stream, e, &path);
    }

    /// Flushes, fsyncs and closes the file of `stream`; optionally compresses it.
    fn close_file(&mut self, stream: Stream, compress: bool) {
        let Some(mut f) = self.files.remove(&stream) else {
            return;
        };
        let res = f.w.flush().and_then(|()| f.w.get_ref().sync_data());
        if let Err(e) = res {
            self.io_lost += f.unflushed;
            drop(f.w.into_parts());
            self.schedule_retry(stream, &e, &f.path);
            return;
        }
        drop(f.w);
        if compress && self.cfg.compress_old {
            self.spawn_compress(f.path);
        }
    }

    /// Closes files of past days even when their stream is idle.
    fn rotate_idle(&mut self) {
        let today = self.now().date_naive();
        let old: Vec<Stream> = self
            .files
            .iter()
            .filter(|(_, f)| f.day < today)
            .map(|(s, _)| *s)
            .collect();
        for s in old {
            self.close_file(s, true);
        }
    }

    fn spawn_compress(&mut self, path: PathBuf) {
        let h = self.rt.spawn_blocking(move || match compress::compress_file(&path) {
            Ok(gz) => tracing::info!(path = %gz.display(), "store: compressed day file"),
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "store: compression failed, keeping original"),
        });
        self.compressions.push(h);
    }

    fn flush_all(&mut self) {
        let streams: Vec<Stream> = self.files.keys().copied().collect();
        for s in streams {
            let Some(f) = self.files.get_mut(&s) else {
                continue;
            };
            match f.w.flush() {
                Ok(()) => {
                    f.unflushed = 0;
                    if self.retry.remove(&s).is_some() {
                        tracing::info!(stream = s.name(), "store: writes recovered");
                    }
                }
                Err(e) => self.fail_file(s, &e),
            }
        }
    }

    fn maybe_fsync(&mut self, force: bool) {
        let every = Duration::from_secs(self.cfg.fsync_s);
        if !force && self.last_fsync.elapsed() < every {
            return;
        }
        self.last_fsync = Instant::now();
        let streams: Vec<Stream> = self.files.keys().copied().collect();
        for s in streams {
            let Some(f) = self.files.get_mut(&s) else {
                continue;
            };
            if !f.unsynced {
                continue;
            }
            match f.w.get_ref().sync_data() {
                Ok(()) => f.unsynced = false,
                Err(e) => self.fail_file(s, &e),
            }
        }
    }

    fn check_disk(&mut self) {
        if self
            .last_disk_check
            .is_some_and(|t| t.elapsed() < self.hooks.disk_check_every)
        {
            return;
        }
        self.last_disk_check = Some(Instant::now());
        let Some(free) = (self.hooks.free_space)(&self.data_dir) else {
            return;
        };
        let mode = DiskMode::classify(free, &self.cfg);
        if mode == self.mode {
            return;
        }
        self.mode = mode;
        match mode {
            DiskMode::Stopped => {
                tracing::error!(
                    free_bytes = free,
                    "store: disk almost full, writing stopped"
                );
            }
            DiskMode::EventsOnly => {
                tracing::warn!(
                    free_bytes = free,
                    "store: low disk space, writing events only"
                );
            }
            DiskMode::Normal => {
                tracing::info!(
                    free_bytes = free,
                    skipped = self.disk_skipped,
                    "store: disk space ok, writing all records"
                );
            }
        }
        self.write_record(Record::Event(EventKind::DiskPressure {
            free_bytes: free,
            mode: mode.name().into(),
        }));
    }

    fn write_heartbeat(&mut self, env: &Envelope) {
        let hb = Heartbeat {
            ts: env.ts,
            boot_id: self.boot_id.clone(),
            mono_ns: env.mono_ns,
        };
        let res = serde_json::to_vec(&hb)
            .map_err(io::Error::other)
            .and_then(|b| write_atomic(&self.dir.join(HEARTBEAT_FILE), &b));
        match res {
            Ok(()) => self.heartbeat_failing = false,
            Err(e) => {
                if !self.heartbeat_failing {
                    tracing::warn!(error = %e, "store: cannot write heartbeat file");
                }
                self.heartbeat_failing = true;
            }
        }
    }
}

/// Opens a stream file for appending; an existing file first gets its tail repaired
/// (a failed write may have left a partial line).
fn open_append(path: &Path) -> io::Result<File> {
    if path.exists() {
        let rep = recover::repair_tail(path)?;
        if rep.truncated_bytes > 0 {
            tracing::warn!(path = %path.display(), bytes = rep.truncated_bytes, "store: truncated partial tail");
        }
    }
    OpenOptions::new().create(true).append(true).open(path)
}
