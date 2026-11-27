//! Store tests: seq continuity, crash recovery, rotation, compression, locking, drops.

use super::*;
use crate::model::{Envelope, EventKind, IfaceRole, LinkState, MultiResult, PathState, Sample};
use chrono::TimeZone;
use std::sync::Mutex;
use tokio::sync::broadcast;

struct TestClock(Mutex<DateTime<Utc>>);

impl TestClock {
    fn at(t: DateTime<Utc>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(t)))
    }
    fn set(&self, t: DateTime<Utc>) {
        *self.0.lock().unwrap() = t;
    }
}

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

fn hooks(clock: Arc<TestClock>) -> Hooks {
    Hooks {
        clock,
        free_space: Arc::new(|_| Some(u64::MAX)),
        disk_check_every: Duration::ZERO,
    }
}

fn t(y: i32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, h, mi, s).unwrap()
}

fn meta(session: &str) -> SessionMeta {
    SessionMeta {
        v: 1,
        session: session.into(),
        started: Utc::now(),
        host: "test".into(),
        version: "0.0.0".into(),
        point: Some("B1/F1/R1".into()),
        label: None,
        note: None,
        config: serde_json::json!({}),
        host_id: None,
        tz_offset_s: None,
        clock_synced: None,
        network: None,
    }
}

fn cfg() -> Storage {
    Storage {
        queue: 64,
        fsync_s: 0,
        ..Storage::default()
    }
}

fn note(s: &str) -> Record {
    Record::Event(EventKind::Note { text: s.into() })
}

fn sample() -> Record {
    Record::Sample(Sample {
        iface: "eth0".into(),
        role: IfaceRole::Ethernet,
        link: LinkState::default(),
        gw: None,
        isp: None,
        net: MultiResult {
            ok: 1,
            of: 1,
            rtt_ms: Some(10.0),
        },
        tcp: None,
        dns: None,
        rx_delta: 0,
        tx_delta: 0,
        state: PathState::Ok,
        speedtest_active: false,
        overrun: false,
        scan_active: false,
        t: None,
        freq_mhz: None,
    })
}

async fn wait_feed(rx: &mut broadcast::Receiver<Arc<Envelope>>, n: usize) -> Vec<Arc<Envelope>> {
    let mut out = Vec::new();
    while out.len() < n {
        let e = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("feed timeout")
            .expect("feed closed");
        out.push(e);
    }
    out
}

fn all_seqs(dir: &Path) -> Vec<u64> {
    let mut v: Vec<u64> = Stream::ALL
        .iter()
        .flat_map(|s| read::iter(dir, *s).map(|e| e.seq))
        .collect();
    v.sort_unstable();
    v
}

#[tokio::test]
async fn seq_continues_across_reopen() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 3, 1, 12, 0, 0));
    let (h, info) = open_with(
        d.path(),
        meta("s1"),
        &cfg(),
        Live::new(),
        hooks(clock.clone()),
    )
    .await
    .unwrap();
    assert_eq!(info.next_seq, 0);
    assert!(info.gap_s.is_none());
    for i in 0..5 {
        h.send(note(&format!("n{i}")));
        h.send(sample());
    }
    h.close(serde_json::json!({"ok": true})).await.unwrap();

    let (h, info) = open_with(d.path(), meta("s1"), &cfg(), Live::new(), hooks(clock))
        .await
        .unwrap();
    assert_eq!(info.next_seq, 10);
    h.send(note("again"));
    h.close(serde_json::json!({})).await.unwrap();

    let dir = d.path().join("s1");
    assert_eq!(all_seqs(&dir), (0..11).collect::<Vec<_>>());
    assert!(dir.join(META_FILE).exists());
    assert_eq!(read::summary(&dir), Some(serde_json::json!({})));
    let s = read::sessions(d.path());
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].1.session, "s1");
}

#[tokio::test]
async fn truncated_line_is_recovered() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 3, 1, 12, 0, 0));
    let (h, _) = open_with(
        d.path(),
        meta("s"),
        &cfg(),
        Live::new(),
        hooks(clock.clone()),
    )
    .await
    .unwrap();
    for i in 0..3 {
        h.send(note(&i.to_string()));
    }
    h.close(serde_json::json!({})).await.unwrap();

    let file = d.path().join("s").join("events-20260301.jsonl");
    let good = fs::read(&file).unwrap();
    let mut torn = good.clone();
    torn.extend_from_slice(b"{\"v\":1,\"run\":\"x\",\"seq\":3,\"ts\":\"2026-03");
    fs::write(&file, &torn).unwrap();

    let (h, info) = open_with(d.path(), meta("s"), &cfg(), Live::new(), hooks(clock))
        .await
        .unwrap();
    assert_eq!(info.next_seq, 3);
    assert_eq!(fs::read(&file).unwrap(), good);
    h.send(note("after"));
    h.close(serde_json::json!({})).await.unwrap();

    let mut it = read::iter(&d.path().join("s"), Stream::Events);
    let seqs: Vec<u64> = it.by_ref().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![0, 1, 2, 3]);
    assert_eq!(it.skipped(), 0);
}

#[tokio::test]
async fn rotation_and_gzip_across_day_boundary() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 1, 1, 23, 59, 58));
    let live = Live::new();
    let mut feed = live.feed.subscribe();
    let (h, _) = open_with(
        d.path(),
        meta("s"),
        &cfg(),
        live.clone(),
        hooks(clock.clone()),
    )
    .await
    .unwrap();
    h.send(note("day1"));
    h.send(sample());
    wait_feed(&mut feed, 2).await;

    clock.set(t(2026, 1, 2, 0, 0, 1));
    h.send(note("day2"));
    h.send(sample());
    wait_feed(&mut feed, 2).await;
    h.close(serde_json::json!({})).await.unwrap();

    let dir = d.path().join("s");
    for s in ["events", "samples"] {
        assert!(
            dir.join(format!("{s}-20260101.jsonl.gz")).exists(),
            "{s} day1 gz"
        );
        assert!(
            !dir.join(format!("{s}-20260101.jsonl")).exists(),
            "{s} day1 plain removed"
        );
        assert!(
            dir.join(format!("{s}-20260102.jsonl")).exists(),
            "{s} day2 plain"
        );
    }
    let texts: Vec<String> = read::iter(&dir, Stream::Events)
        .filter_map(|e| match e.rec {
            Record::Event(EventKind::Note { text }) => Some(text),
            _ => None,
        })
        .collect();
    assert_eq!(texts, vec!["day1", "day2"]);
    let samples: Vec<Envelope> = read::iter(&dir, Stream::Samples).collect();
    assert_eq!(samples.len(), 2);
    assert_eq!(
        samples[0].ts.date_naive(),
        t(2026, 1, 1, 0, 0, 0).date_naive()
    );
    assert_eq!(live.snapshot().events.len(), 2);
}

#[tokio::test]
async fn reader_merges_gz_and_plain_without_duplicates() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 2, 1, 10, 0, 0));
    let (h, _) = open_with(
        d.path(),
        meta("s"),
        &cfg(),
        Live::new(),
        hooks(clock.clone()),
    )
    .await
    .unwrap();
    for i in 0..3 {
        h.send(note(&i.to_string()));
    }
    h.close(serde_json::json!({})).await.unwrap();
    let dir = d.path().join("s");
    let plain = dir.join("events-20260201.jsonl");
    let copy = fs::read(&plain).unwrap();
    // Simulate a crash after the .gz rename but before removal of the .jsonl.
    compress::compress_file(&plain).unwrap();
    fs::write(&plain, &copy).unwrap();
    // A malformed line inside the plain file is skipped and counted.
    let mut extra = copy.clone();
    extra.extend_from_slice(b"not json\n");
    fs::write(&plain, &extra).unwrap();

    let mut it = read::iter(&dir, Stream::Events);
    let seqs: Vec<u64> = it.by_ref().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![0, 1, 2]);
    assert_eq!(it.skipped(), 1);

    // Reopen next day: the duplicate is removed by recovery, seq continues.
    clock.set(t(2026, 2, 2, 10, 0, 0));
    let (h, info) = open_with(d.path(), meta("s"), &cfg(), Live::new(), hooks(clock))
        .await
        .unwrap();
    assert_eq!(info.next_seq, 3);
    assert!(!plain.exists());
    h.send(note("3"));
    h.close(serde_json::json!({})).await.unwrap();
    assert_eq!(all_seqs(&dir), vec![0, 1, 2, 3]);
}

#[tokio::test]
async fn second_instance_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 3, 1, 12, 0, 0));
    let (h, _) = open_with(
        d.path(),
        meta("a"),
        &cfg(),
        Live::new(),
        hooks(clock.clone()),
    )
    .await
    .unwrap();
    let err = match open_with(
        d.path(),
        meta("b"),
        &cfg(),
        Live::new(),
        hooks(clock.clone()),
    )
    .await
    {
        Ok(_) => panic!("second open must fail"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("another linkwatch instance"), "{err}");
    h.close(serde_json::json!({})).await.unwrap();
    let (h, _) = open_with(d.path(), meta("b"), &cfg(), Live::new(), hooks(clock))
        .await
        .unwrap();
    h.close(serde_json::json!({})).await.unwrap();
}

#[tokio::test]
async fn full_queue_counts_drops_and_reports_once() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 3, 1, 12, 0, 0));
    let live = Live::new();
    let c = Storage { queue: 2, ..cfg() };
    let (h, _) = open_with(d.path(), meta("s"), &c, live.clone(), hooks(clock))
        .await
        .unwrap();
    // The writer task cannot run between these calls (current-thread runtime, no await).
    for i in 0..10 {
        h.send(note(&i.to_string()));
    }
    assert_eq!(h.dropped(), 8);
    h.close(serde_json::json!({})).await.unwrap();

    let evs: Vec<Envelope> = read::iter(&d.path().join("s"), Stream::Events).collect();
    let drops: Vec<u64> = evs
        .iter()
        .filter_map(|e| match e.rec {
            Record::Event(EventKind::DroppedRecords { count }) => Some(count),
            _ => None,
        })
        .collect();
    assert_eq!(drops, vec![8]);
    assert_eq!(evs.len(), 3);
    assert_eq!(live.snapshot().dropped_records, 8);
}

#[tokio::test]
async fn disk_pressure_drops_samples_keeps_events() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 3, 1, 12, 0, 0));
    let free = Arc::new(AtomicU64::new(u64::MAX));
    let f2 = free.clone();
    let hk = Hooks {
        free_space: Arc::new(move |_| Some(f2.load(Ordering::Relaxed))),
        ..hooks(clock)
    };
    let live = Live::new();
    let mut feed = live.feed.subscribe();
    let (h, _) = open_with(d.path(), meta("s"), &cfg(), live, hk)
        .await
        .unwrap();
    h.send(sample());
    wait_feed(&mut feed, 1).await;
    free.store(cfg().min_free_bytes - 1, Ordering::Relaxed);
    h.send(sample());
    h.send(note("kept"));
    // DiskPressure + sample + note
    wait_feed(&mut feed, 3).await;
    h.close(serde_json::json!({})).await.unwrap();

    let dir = d.path().join("s");
    assert_eq!(read::iter(&dir, Stream::Samples).count(), 1);
    let modes: Vec<String> = read::iter(&dir, Stream::Events)
        .filter_map(|e| match e.rec {
            Record::Event(EventKind::DiskPressure { mode, .. }) => Some(mode),
            _ => None,
        })
        .collect();
    assert_eq!(modes, vec!["events_only"]);
    assert_eq!(read::iter(&dir, Stream::Events).count(), 2);
}

#[tokio::test]
async fn heartbeat_gives_gap_on_next_open() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 3, 1, 12, 0, 0));
    let (h, _) = open_with(
        d.path(),
        meta("s1"),
        &cfg(),
        Live::new(),
        hooks(clock.clone()),
    )
    .await
    .unwrap();
    h.send(Record::Heartbeat { uptime_s: 1.0 });
    h.close(serde_json::json!({})).await.unwrap();
    assert!(d.path().join("s1").join(HEARTBEAT_FILE).exists());

    clock.set(t(2026, 3, 1, 12, 1, 40));
    // A new session must not report another session's downtime as its own gap.
    let (h, info) = open_with(d.path(), meta("s2"), &cfg(), Live::new(), hooks(clock.clone()))
        .await
        .unwrap();
    assert_eq!(info.gap_s, None);
    h.close(serde_json::json!({})).await.unwrap();
    // The same session reopened sees its own heartbeat.
    let (h, info) = open_with(d.path(), meta("s1"), &cfg(), Live::new(), hooks(clock))
        .await
        .unwrap();
    assert_eq!(info.gap_s, Some(100.0));
    assert_eq!(info.prev_boot_id, Some(boot_id()));
    h.close(serde_json::json!({})).await.unwrap();
}

#[tokio::test]
async fn bad_session_name_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    let r = open(d.path(), meta("../x"), &cfg(), Live::new()).await;
    assert!(r.is_err());
}

#[test]
fn stream_file_names_roundtrip() {
    let day = NaiveDate::from_ymd_opt(2026, 5, 7).unwrap();
    let n = stream_file_name(Stream::Wifi, day);
    assert_eq!(n, "wifi-20260507.jsonl");
    let f = parse_stream_file(Path::new(&format!("/x/{n}.gz"))).unwrap();
    assert_eq!((f.stream, f.day, f.gz), (Stream::Wifi, day, true));
    assert!(parse_stream_file(Path::new("/x/other-20260507.jsonl")).is_none());
    assert!(parse_stream_file(Path::new("/x/wifi-2026057.jsonl")).is_none());
}

#[tokio::test]
async fn host_stream_writes_recovers_and_reads() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 4, 1, 10, 0, 0));
    let (h, _) = open_with(d.path(), meta("sh"), &cfg(), Live::new(), hooks(clock.clone()))
        .await
        .unwrap();
    h.send(Record::Host(crate::model::HostSample {
        cpu_pct: Some(22.5),
        mem_used_pct: Some(45.0),
        temp_c: Some(42.0),
        clock_synced: Some(true),
        ..Default::default()
    }));
    h.close(serde_json::json!({})).await.unwrap();

    let dir = d.path().join("sh");
    let host_file = dir.join("host-20260401.jsonl");
    assert!(host_file.exists());
    let mut extra = fs::read(&host_file).unwrap();
    extra.extend_from_slice(b"{\"v\":1,\"run\":\"x\",\"seq\":99,\"broken");
    fs::write(&host_file, &extra).unwrap();

    let (h2, info) = open_with(d.path(), meta("sh"), &cfg(), Live::new(), hooks(clock))
        .await
        .unwrap();
    assert_eq!(info.next_seq, 1);
    h2.send(Record::Host(crate::model::HostSample {
        cpu_pct: Some(30.0),
        ..Default::default()
    }));
    h2.close(serde_json::json!({})).await.unwrap();

    let recs: Vec<Envelope> = read::iter(&dir, Stream::Host).collect();
    assert_eq!(recs.len(), 2);
    assert!(matches!(recs[0].rec, Record::Host(ref hs) if hs.cpu_pct == Some(22.5)));
    assert!(matches!(recs[1].rec, Record::Host(ref hs) if hs.cpu_pct == Some(30.0)));
}

#[tokio::test]
async fn disk_pressure_stops_below_critical_and_recovers() {
    let d = tempfile::tempdir().unwrap();
    let clock = TestClock::at(t(2026, 4, 2, 10, 0, 0));
    let free = Arc::new(AtomicU64::new(u64::MAX));
    let f2 = free.clone();
    let hk = Hooks {
        free_space: Arc::new(move |_| Some(f2.load(Ordering::Relaxed))),
        ..hooks(clock)
    };
    let live = Live::new();
    let mut feed = live.feed.subscribe();
    let (h, _) = open_with(d.path(), meta("dp"), &cfg(), live, hk).await.unwrap();
    h.send(sample());
    wait_feed(&mut feed, 1).await;

    free.store(cfg().critical_free_bytes - 1, Ordering::Relaxed);
    h.send(sample());
    h.send(note("dropped below critical"));
    wait_feed(&mut feed, 2).await;

    free.store(u64::MAX, Ordering::Relaxed);
    h.send(sample());
    h.send(note("recovered"));
    wait_feed(&mut feed, 3).await;
    h.close(serde_json::json!({})).await.unwrap();

    let dir = d.path().join("dp");
    assert_eq!(read::iter(&dir, Stream::Samples).count(), 2);
    let modes: Vec<String> = read::iter(&dir, Stream::Events)
        .filter_map(|e| match e.rec {
            Record::Event(EventKind::DiskPressure { mode, .. }) => Some(mode),
            _ => None,
        })
        .collect();
    assert_eq!(modes, vec!["normal"]);
}
