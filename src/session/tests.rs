//! Loader tests on small hand-written session folders. Whole-report parity with
//! `linkwatch analyze` is covered by the golden tests (`analyze::golden_tests`), which load
//! their fixtures through [`load`].

use super::*;
use std::path::Path;

const META: &str = r#"{"v":1,"session":"S1","started":"2026-01-15T10:00:00.000Z","host":"h1","version":"0","point":"R1","config":{}}"#;

fn line(seq: u64, sec: u32, kind: &str) -> String {
    format!(r#"{{"v":1,"run":"r","seq":{seq},"ts":"2026-01-15T10:00:{sec:02}.000Z","mono_ns":0,"type":"event",{kind}}}"#)
}

fn write_session(dir: &Path, events: &[String]) {
    std::fs::write(dir.join("meta.json"), META).unwrap();
    std::fs::write(dir.join("events-20260115.jsonl"), events.join("\n") + "\n").unwrap();
}

fn suspend(seq: u64) -> String {
    line(seq, seq as u32, r#""kind":"suspend_gap","secs":10.0"#)
}

#[test]
fn missing_directory_is_an_error() {
    let d = tempfile::tempdir().unwrap();
    let err = load(&d.path().join("nope"), &LoadOpts::default()).unwrap_err();
    assert!(err.to_string().contains("session directory not found"), "{err}");
}

#[test]
fn id_and_label_come_from_meta() {
    let d = tempfile::tempdir().unwrap();
    write_session(d.path(), &[suspend(1)]);
    let r = load(d.path(), &LoadOpts::default()).unwrap();
    assert_eq!(r.id, "S1");
    assert_eq!(r.label, "R1");
    assert!(r.meta.is_some());
}

#[test]
fn id_falls_back_to_folder_name_without_meta() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("20260115T100000Z_x");
    std::fs::create_dir(&dir).unwrap();
    let r = load(&dir, &LoadOpts::default()).unwrap();
    assert_eq!(r.id, "20260115T100000Z_x");
    assert_eq!(r.label, "20260115T100000Z_x");
    assert!(r.meta.is_none());
}

#[test]
fn events_fill_gaps_and_clock_jumps() {
    let d = tempfile::tempdir().unwrap();
    write_session(
        d.path(),
        &[
            suspend(1),
            line(2, 2, r#""kind":"clock_jump","wall_delta_s":5.0,"mono_delta_s":1.0"#),
            line(3, 3, r#""kind":"start","version":"0","gap_s":60.0,"boot_id":"b""#),
        ],
    );
    let r = load(d.path(), &LoadOpts::default()).unwrap();
    assert_eq!(r.clock_jumps, 1);
    assert_eq!(r.gaps.len(), 2, "one suspend gap and one monitor gap: {:?}", r.gaps);
}

#[test]
fn malformed_lines_are_counted_in_monitor_gaps() {
    let d = tempfile::tempdir().unwrap();
    write_session(d.path(), &[suspend(1), "{not json".into(), suspend(3)]);
    let r = load(d.path(), &LoadOpts::default()).unwrap();
    assert!(r.report.monitor_gaps.iter().any(|g| g == "1 malformed lines skipped while reading"), "{:?}", r.report.monitor_gaps);
}

#[test]
fn max_lines_cuts_each_stream() {
    let d = tempfile::tempdir().unwrap();
    write_session(d.path(), &[suspend(1), suspend(2), suspend(3)]);
    let all = load(d.path(), &LoadOpts::default()).unwrap();
    assert_eq!(all.gaps.len(), 3);
    let cut = load(d.path(), &LoadOpts { max_lines: Some(2), ..Default::default() }).unwrap();
    assert_eq!(cut.gaps.len(), 2);
    let exact = load(d.path(), &LoadOpts { max_lines: Some(3), ..Default::default() }).unwrap();
    assert_eq!(exact.gaps.len(), 3);
}
