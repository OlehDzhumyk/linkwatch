# linkwatch target architecture

Status: design, 2026-11-28 (after 0.11.1). This document sets the target structure and the
refactor order. Module rules for each file stay in [CONTRACTS.md](CONTRACTS.md). Product goals
stay in [ROADMAP.md](ROADMAP.md).

## 1. Goal

`linkwatch` has one job: give a correct, explained verdict about where a connection fails.
The architecture must serve three properties, in this order:

1. **Accuracy.** One analysis pipeline. Every user surface (CLI, web, compare, support pack)
   shows the same result for the same session. Every rule can be tested on recorded data.
2. **Clarity.** Pure decision code is separate from IO. A reader can find a rule in one place.
3. **Cost.** The live report on a Raspberry Pi stays inside `MemoryMax=256M` for a 7-day
   session.

Everything that does not serve the verdict is an extension. Extensions must not make the
core harder to change.

## 2. Problems in the current structure (0.11.1)

Measured from the code, not from the docs.

| # | Problem | Where | Effect |
|---|---|---|---|
| P1 | Three session loaders | `main.rs::analyze_cmd`, `compare.rs::SessionView::load_with`, `web/api.rs::analyze_session_raw` | The web report has no `--reclassify` and has a line limit (`MAX_SCAN_LINES`). The same session can give a different result in the web and in the CLI. |
| P2 | Verdict text and headline live in the web layer | `web/api.rs::dominant_cause`, `explain_verdict`, `with_live_verdict` | The Markdown report, the support pack and the web can word the same verdict differently. The rules cannot be tested without HTTP types. |
| P3 | `Analyzer::finish()` is about 600 lines | `analyze/engine.rs` | Episodes, cross-path cause, context, router log, incidents, attribution, masking and totals are one function. A change in one stage can break another without a clear test. |
| P4 | Two verdict systems without a written relation | `classify::verdict` (layer) and `analyze::attribution` (cause, confidence) | It is not clear which one wins in a headline. `dominant_cause` uses only the first. |
| P5 | Golden tests check counts only | `testdata/golden/*/expect.json` | A wrong episode state or cause does not fail a test. Refactoring is not safe yet. |
| P6 | Flat top-level modules | 33 modules in `main.rs`; check code in 4 files, router code in 5 files | The core and the extensions look the same. Freezing extensions is hard. |
| P7 | The live report rebuilds the full session | `web/api.rs::report` | Cost grows with session length. No checkpoint. |
| P8 | Magic numbers outside named limits | `classify.rs` (half weight, minimum evidence, lost-probe count) | A threshold change has no single place and no reason text. |
| P9 | IPv4 only, in types | `Ipv4Addr` in `model.rs`, `probe/*` | IPv6 needs changes in many files. |

## 3. Target structure

Four layers. A layer may use only the layers below it.

```
            +-------------------------------------------------+
  surfaces  |  cli (main.rs)   web/   support_report/          |  formatting, HTTP, files
            +-------------------------------------------------+
  services  |  session/ (load, reclassify, checkpoint, cache)   |  one entry point to results
            |  run/ (live measurement)   check/ (preflight)    |
            +-------------------------------------------------+
  core      |  model   classify   analyze/   compare   verdict/ |  pure: no IO, no clock
            +-------------------------------------------------+
  adapters  |  probe/  link  wifi/  host  lan  store/          |  sockets, netlink, disk
            +-------------------------------------------------+
  extensions (cargo features): router/ (audit, adapters, snmp), cve, security, site, notify, speed
```

### 3.1 Core (pure)

Rules: no sockets, no files, no `Utc::now()`. Time comes in the data. Every threshold is a
named constant with a reason, in one `limits` module per area, or a `config` field.

- `model`: shared types. Addresses become `IpAddr` when IPv6 work starts (P9).
- `classify`: per-tick path state (`instant_state`, `PathClassifier`) and the instant layer
  verdict (`verdict`). Magic numbers move to `classify::limits` (P8).
- `analyze/`: the session pipeline, as explicit stages (P3):

  | Stage | Input | Output | Today in |
  |---|---|---|---|
  | `ingest` | envelopes | per-interface timelines, time-sorted event index | `push`, `sample` |
  | `episodes` | timelines | episodes with onset, dominant state, flags | `sample`, `close_episode` |
  | `cross_path` | episodes | episode layer verdict (`cause`) | `finish` lines ~600–660 |
  | `context` | episodes, events | nearby events, router log matches | `finish` |
  | `incidents` | episodes | merged real-world incidents | `finish` |
  | `facts` | incidents, host data | `IncidentFacts` | `finish` |
  | `attribution` | facts | `Finding` (already pure) | `attribution.rs` |
  | `masking` | findings, session data | blinded findings, `session_blinds` | `attribution.rs`, `session_blinds` |
  | `summary` | all above | `Report` | `finish` |

  Each stage is a function with a typed input and output. `Analyzer::finish` only calls the
  stages in order. Each stage has its own unit tests.

- `verdict/` (new): the one place that turns a `Report` (plus an optional live layer verdict)
  into what a person reads (P2, P4):
  - `headline(report, live) -> Headline` (code, args, severity). It replaces
    `dominant_cause`, `explain_verdict` and `with_live_verdict`.
  - The rule between the two systems is written here: the **layer verdict** says *where* the
    path broke; the **attribution** says *whether the network is to blame* and *how sure we
    are*. The headline uses the layer verdict of the incidents that the attribution keeps as
    network incidents. An observer or inconclusive incident never sets the headline layer.
  - Text comes from message codes (`Msg`), so the CLI, Markdown, web and support pack use the
    same words in every language.

- `compare`: multi-session logic on `Report` values only. Session loading moves out (P1).

### 3.2 Services

- `session/` (new, P1, P7): the only code that turns a session folder into results.
  ```rust
  pub struct LoadOpts { pub reclassify: bool, pub router_log: Vec<RouterLine> }
  pub fn load(dir: &Path, opts: &LoadOpts) -> Result<SessionResult>;  // meta, report, gaps, fingerprint
  ```
  The CLI, `compare`, the web and the support pack call it. Later it gets a checkpoint:
  the analyzer state at a file offset, so a live report reads only new lines (ROADMAP §9).
  The web cache (`REPORT_FRESH`) moves here.
- `run/`: live measurement. It already separates tick logic (`run/tick.rs`) from tasks. No
  large change. It uses `classify` and writes through `store`.
- `check/` (merge of `check.rs`, `hostcheck.rs`, `deepcheck.rs`, `readiness.rs`, P6):
  `check/mod.rs` (items and output), `check/host.rs`, `check/deep.rs`, `check/calibrate.rs`,
  `check/readiness.rs`.

### 3.3 Surfaces

Surfaces format and transport. They hold no rules.

- `main.rs`: argument parsing and calls into services. `analyze_cmd` and the other
  `*_cmd` functions move to `cli/` if `main.rs` grows.
- `web/`: `api.rs` (1991 lines) splits by tab: `web/api/{live,report,sessions,site,router,
  control}.rs`, plus `web/api/mod.rs` for errors and shared helpers. Handlers call
  `session::load` and `verdict::headline`.
- `support_report/`: consumes `SessionResult` and `Headline`. Keeps redaction and rendering.

### 3.4 Adapters

`probe/`, `link`, `wifi/`, `host`, `lan`, `store/`. They stay as they are. Two changes:
- `store::read` gives one time-merged iterator over all streams. Today the loaders read stream
  by stream, and the analyzer must sort later.
- Addresses become `IpAddr` in the IPv6 phase.

### 3.5 Extensions (frozen until the verdict is validated)

ROADMAP "Before 1.0" freezes the RF wall model, CVE/KEV, SNMP/MikroTik and rogue DHCP. The
architecture makes the freeze real:

- Move `router.rs`, `router_audit.rs`, `advice.rs` into `router/`. Move `cve.rs` under it.
- Put each extension behind a cargo feature: `router-audit` (with `snmp2`), `cve` and `alerts`
  (both with the TLS stack), `site`, `security`, `speedtest`.
- In 0.x all features stay on by default, so no user loses a function. Before 1.0, decide
  which features the release files have. The core build must not need `rustls-rustcrypto`.
- Rule: the core never imports an extension. An extension may read core types.

## 4. Accuracy work that the structure enables

These are behaviour changes. Each one comes **after** the refactor step that it needs, with a
golden diff that a person reviews.

1. **Full golden snapshots (P5).** `expect.json` holds every episode (start, end, state,
   cause), every incident with its `Finding`, the headline and the session blinds, not only
   counts. Keep the files small: drop fields that only repeat input data.
2. **Public real-pattern fixtures.** Use `scripts/make-fixture.py` to make two or three
   redacted fixtures from real nights. A person reviews each one before commit. CI runs them.
3. **Labelled nights.** Each real fixture gets `labels.json`: the cause known from outside
   (router log, ISP ticket, a planned cable pull). A test prints a confusion table of
   headline layer against label. It does not fail on a miss at first; it shows the error rate.
4. **Mixed and degraded layer verdicts.** `classify::verdict` returns `Mixed` when paths fail
   at different layers, not `LineProblem` by default. A path that stays `Degraded` for a long
   time becomes a finding (quality problem), not `AllOk`. Table-driven tests for all state
   pairs.
5. **Episode onset.** Keep the 0.11.1 rule (nearest failure with 25 % share). Also store the
   onset state in the episode, so the report can say "started as X".
6. **Masking frequency.** Count how often masking makes a finding inconclusive on real
   fixtures. If it is the common answer for single-path users, the report must say what to
   add (a cable, a second probe), not only "inconclusive".

## 5. Refactor order

Rules for every step:
- One step is one commit (or one pull request). Each step keeps behaviour, except where the
  step says "behaviour change".
- Before and after each step: `cargo test --locked` passes, clippy passes in CI, and the
  golden snapshots do not change. A refactor step that changes a snapshot is wrong.
- No new features during the refactor.

| Step | Work | Size | Needs |
|---|---|---|---|
| R0 | Full golden snapshots (§4.1). Add one public real-pattern fixture (§4.2). | M | — |
| R1 | `session/` loader. CLI, compare, web and support pack use it. Web gets `reclassify` parity; the line limit becomes a documented `LoadOpts` field. | M | R0 |
| R2 | `verdict/` module: `headline()` with message codes. Web, Markdown and support pack use it. | M | R1 |
| R3 | Split `Analyzer::finish` into the stages of §3.1. Key episode states by `PathState`. | L | R0 |
| R4 | `classify::limits`; named constants for every threshold in `classify.rs`. | S | R0 |
| R5 | `check/` module merge. | S | — |
| R6 | `router/` module and cargo features for extensions (§3.5). | M | — |
| R7 | Split `web/api.rs` by tab. | M | R1, R2 |
| R8 | Behaviour change: mixed and degraded verdicts (§4.4), onset in episodes (§4.5). | M | R3, R4 |
| R9 | Analyzer checkpoint and incremental live report; measure a 7-day session on a Pi. | L | R1, R3 |
| R10 | Behaviour change: IPv6 probes (`IpAddr` in model and probes; per-family paths). | L | R3 |
| R11 | Replace `chrono` with `jiff` (ROADMAP §5). | M | R3 |

R0 first: without full snapshots, no refactor step is safe. R5 and R6 do not touch the
analyzer, so they can run in parallel with R1–R3.

## 6. What does not change

- Pure Rust, `#![forbid(unsafe_code)]`, no subprocesses, explicit timeouts (CONTRACTS.md).
- The on-disk session format. Old sessions must stay readable; `--reclassify` stays.
- The web API shape for the UI, except new fields. TypeScript bindings stay generated.
