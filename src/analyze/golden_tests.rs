//! Golden tests: run the real analyzer on recorded sessions in `testdata/golden/<name>/` and
//! compare a small summary with the committed `expect.json`.
//! Set `LINKWATCH_UPDATE_GOLDEN=1` to rewrite the expectation files.

use super::*;
use crate::store;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn golden_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata").join("golden")
}

/// Runs the analyzer on a session directory the same way `linkwatch analyze` does.
fn analyze_dir(dir: &Path) -> Report {
    let meta: Option<SessionMeta> = std::fs::read(dir.join("meta.json")).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let mut a = Analyzer::new(Opts::for_session(meta.as_ref()));
    for st in Stream::ALL {
        for e in store::read::iter(dir, st) {
            a.push(&e);
        }
    }
    a.finish(&[])
}

fn to_json<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

fn summarize(r: &Report) -> Value {
    let mut per_iface: BTreeMap<String, u32> = BTreeMap::new();
    for e in &r.episodes {
        *per_iface.entry(e.iface.clone()).or_default() += 1;
    }
    let episodes: Vec<Value> = r
        .episodes
        .iter()
        .map(|e| {
            json!({
                "iface": e.iface,
                "start": e.start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "duration_s": e.duration_s.round() as i64,
                "cause": to_json(&e.cause),
                "origin": to_json(&e.origin),
                "attribution": to_json(&e.finding.attribution),
            })
        })
        .collect();
    json!({
        "episodes_per_iface": per_iface,
        "network_incidents": r.network_incidents,
        "observer_incidents": r.observer_incidents,
        "load_incidents": r.load_incidents,
        "episodes": episodes,
    })
}

/// Line diff of two pretty-printed JSON documents (`-` expected, `+` actual).
fn diff(expected: &str, actual: &str) -> String {
    let e: Vec<&str> = expected.lines().collect();
    let a: Vec<&str> = actual.lines().collect();
    let mut out = String::new();
    for i in 0..e.len().max(a.len()) {
        let (le, la) = (e.get(i).copied(), a.get(i).copied());
        if le != la {
            if let Some(l) = le {
                out.push_str(&format!("line {:>3} - {l}\n", i + 1));
            }
            if let Some(l) = la {
                out.push_str(&format!("line {:>3} + {l}\n", i + 1));
            }
        }
    }
    out
}

#[test]
fn golden_sessions_match_expectations() {
    let update = std::env::var("LINKWATCH_UPDATE_GOLDEN").is_ok_and(|v| v == "1");
    let Ok(rd) = std::fs::read_dir(golden_root()) else { return };
    let mut dirs: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    let mut failures = Vec::new();
    let mut checked = 0;
    for dir in dirs {
        let expect_path = dir.join("expect.json");
        // Update mode also adopts a new fixture; otherwise a directory without expect.json is skipped.
        if !expect_path.exists() && !(update && dir.join("meta.json").exists()) {
            continue;
        }
        checked += 1;
        let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut actual = serde_json::to_string_pretty(&summarize(&analyze_dir(&dir))).unwrap_or_default();
        actual.push('\n');
        if update {
            std::fs::write(&expect_path, &actual).expect("write expect.json");
            eprintln!("golden: updated {}", expect_path.display());
            continue;
        }
        let expected = std::fs::read_to_string(&expect_path).unwrap_or_default();
        let same = match (serde_json::from_str::<Value>(&expected), serde_json::from_str::<Value>(&actual)) {
            (Ok(x), Ok(y)) => x == y,
            _ => false,
        };
        if !same {
            failures.push(format!("golden session `{name}` differs from expect.json:\n{}", diff(&expected, &actual)));
        }
    }
    eprintln!("golden: {checked} session(s) checked");
    assert!(
        failures.is_empty(),
        "{}\nIf the change is intended, run with LINKWATCH_UPDATE_GOLDEN=1 and review the diff of expect.json.",
        failures.join("\n")
    );
}
