# Changelog

All notable changes to `linkwatch` are documented in this file.

## [Unreleased]

Behaviour changes for accuracy (docs/ARCHITECTURE.md, step R8). Golden snapshots change; see
each item.

### Changed
- **Mixed layer verdict:** new verdict `mixed` (Mixed problem). `classify::verdict` returns it
  when paths fail at different layers at the same time (for example Wi-Fi cannot reach the
  router while the cable reaches it but not the internet), and when both Wi-Fi and a cable
  fail next to a good path. Before, the first case gave `line_problem` and the second gave
  `unknown`. Wi-Fi `LanDown` with a cable `IspDown` now gives `mixed`, not `line_problem`.
  The verdict has English and Ukrainian text in the web UI, the advisor, the incident counts
  line and the support pack. The headline ties go to the concrete layer, never to `mixed`.
- **Long Degraded is a finding:** a path that stays `Degraded` (loss or high latency, not
  down) for one unbroken run of 5 min or more, or for 5 % of its ticks (and at least 1 min in
  total), now gets a quality finding `f_degraded` in the findings list. It is not an episode,
  so incident counts and availability do not change. Ticks during the monitor's own speed
  tests, scans, overruns and heavy own traffic do not count. The limits are in
  `analyze/limits.rs`. `IfaceReport` has the new fields `degraded_ticks` and
  `degraded_longest_s` (omitted when zero).
- **Headline counts only network-caused incidents:** the dominant cause in `verdict::headline`
  now counts an episode only when its attribution is `network`, `network_despite_host` or
  `mixed`. Episodes with `observer_likely`, `observer_confirmed` or `inconclusive` never set the
  headline layer (before, only origin `observer` and load-provoked episodes were skipped).
  `expect.json` of the golden sessions now also holds the headline.
- **Onset state:** `Episode` has the new field `onset_state`, the first bad state of the
  episode. It differs from `state` (the state that names the episode) when the failure moved,
  for example `WanDown` first and then `LanDown`. The Markdown outage table shows
  `LanDown (started as WanDown)` and the web incident row shows a "started as …" badge, only
  when the two differ. The web report API has the same field. `expect.json` of the golden
  sessions holds it too.

## [0.12.0] - 2026-11-28

Refactor to the target structure in `docs/ARCHITECTURE.md` (steps R0–R7). Reports, verdicts
and the web API are the same as in 0.11.1; the golden snapshots did not change.

### Changed
- **Golden tests (R0):** `expect.json` also checks episode state, end, confidence and blinds,
  causes, Observer Trust and session-wide blinds. New `snapshot.json` holds the whole report.
- **One session loader (R1):** `session::load` serves `analyze`, `compare`, `support-report`
  and the web. The web line limit is a documented load option.
- **One verdict headline (R2):** `verdict::headline` replaces the web-only verdict text code.
- **Analyzer stages (R3):** `Analyzer::finish` calls named stages in `analyze/stages/`
  (episodes, cross-path cause, context, facts, incidents, masking, observer, summary).
- **Classifier limits (R4):** every classifier threshold is a named constant with a reason in
  `classify/limits.rs`.
- **Modules (R5–R7):** check code in `check/`; router, audit, advice and CVE code in `router/`;
  the web API split by tab in `web/api/`.

### Added
- Cargo features `router-audit`, `cve`, `alerts` (all on by default). Without `cve` and
  `alerts` the build has no TLS stack. CI builds `--no-default-features`.

## [0.11.1] - 2026-11-28

### Fixed
- Episode state: the failure nearest to the user names the episode when it holds at least
  25 % of the bad ticks (a router reboot: gateway down, then a long WAN reconnect, is a
  router problem). Before, the most frequent state won, and a tie went by the alphabetical
  order of state names (`lan_down` vs `wan_down` gave `internet_problem`).
- The golden test fails when no fixture runs, instead of a silent pass.

### Changed
- `docs/INSTALL.md`, README: install from the release files (`.deb`, `.tar.gz`, checksums).
- `scripts/ci.sh`: own cache volume (`TARGET_VOLUME`), not shared with other containers.

## [0.11.0] - 2026-11-28

### Added
- `analyze`, `compare`, `support-report --reclassify`: replays the current classifier over the
  recorded probe results, so classifier fixes reach old sessions. On a real DOCSIS night a
  dual-path drop recorded as `line_problem` (ISP hop never answered echo) becomes
  `internet_problem`. Golden tests check both ways (`expect-reclassified.json`).
- **Masking phase 2 (session-wide limits):** power-save share (M4), monitor gaps (M9), a
  polluted observer caps every network confidence at `medium` (M10), own heavy traffic in the
  evening (M13) and frequent own evening speed tests (M6) are listed once in "Session-wide
  limits" (Markdown) and under the KPI tiles (web).

### Changed
- Observer Trust: Wi-Fi power-save under 5 % of the session is `caution`, not `polluted`
  (same tolerance as the session-wide limit).

## [0.10.1] - 2026-11-28

### Fixed
- A package upgrade no longer starts a new session when only settings that do not change the
  measurement differ (speed tests, web, alerts, advisor, new default sections). The session
  continues and records a `config changed: …` note. A new probe interval, target, interface or
  classifier setting still starts a new session.

## [0.10.0] - 2026-11-28

### Added
- **Readiness advisor** ([docs/ADVISOR.md](docs/ADVISOR.md)): `linkwatch check` ends with
  GO / GO WITH CAVEATS / NO-GO, one top action, and for every caveat the conclusion it spoils,
  its evidence and threshold. `[advisor] accept = [...]` silences an accepted risk (blocking
  items cannot be accepted). During a run, Wi-Fi power-save turning on and the clock losing
  NTP sync are reported once per session (`HostAlertKind::ClockUnsynced` is new).

### Changed
- The analyzer indexes events and time series by time: a session with 54 000 events and
  2 000 episodes analyzes in 0.18 s instead of 1.9 s.
- axum 0.8 (route syntax `/{id}`), md-5 0.11.
- `scripts/make-fixture.py` also redacts host names in free text, session ids (they carry the
  point id) and device make/model.

## [0.9.0] - 2026-11-28

### Added
- **Masking (phase 1):** an incident that only one Wi-Fi path saw, with a very busy channel or a
  weak signal and nothing independent, is `inconclusive` for the router and the line
  (`Finding.blinded`); an unsynchronized clock stops router-log matches from counting as
  evidence. See docs/INCIDENT-ATTRIBUTION.md section 10 (M1, M2, M3, M5, M11).
- **Golden tests:** `testdata/golden/<session>/expect.json` is compared with a fresh analysis;
  `scripts/make-fixture.py` slices and redacts a real session (self-check for MACs, private
  IPs, SSIDs, ids); real fixtures stay local in `testdata/golden/local-*`.
- `[classify] debounce_s` / `window_s`: the classifier is time-based, so profiles with other
  probe intervals keep the same meaning. The tick keys still work and are deprecated.
- A week-long synthetic session benchmark (`perf_tests`, ignored by default).

### Fixed
- A cable unplugged long ago no longer turns a later Wi-Fi drop into `router_problem`
  (a wired path counts only within 15 s of losing link).
- The ISP hop search backs off to 10 min while no hop answers.

### Changed
- The live web report is rebuilt at most every 5 min; its verdict headline always follows the
  live verdict.

## [0.8.0] - 2026-11-28

Fixes from an independent review. Verdicts first, no new features.

### Fixed
- Live verdict: an interface that never had link (an unused Ethernet port) no longer turns a
  Wi-Fi drop into `router_problem`; single-path outages now send alerts.
- A gateway that never answers ICMP no longer makes every internet outage a `lan_down`
  (router) incident.
- `degraded` needs at least two lost gateway probes in the window (one lost ping is noise).
- The ISP first hop is used only when it answers echo. Many ISP access routers (seen on a
  real DOCSIS line) never do, and every internet outage was then blamed on the line. A private
  hop that answers within 1 ms of the gateway is a second home router and is skipped; CGNAT
  hops count as ISP equipment.
- Detective: `host_s` ignores contradicted suspects (no more `mixed` with 0 s of network);
  observer results get a real confidence; all thresholds are named with reasons.
- Docs and packaging: the sysctl file now really sets `ping_group_range`; host-wide ARP and
  `rp_filter` effects are explained; the TLS comment lists webhooks; `calibrate` says its
  file is informational; a "Before 1.0" roadmap.

### Changed
- Speed tests are light by default: every 6 h, at most 50 MiB per test (about 200 MiB per
  interface per day instead of several GB). The evening speed-up stays as an option.
- Host alerts are typed (`HostAlertKind`, optional `iface`); old session files still parse.
  Router WAN status uses one helper; engine time windows are named constants.

## [0.7.0] - 2026-11-28

### Added
- **Incident detective** (`src/analyze/attribution.rs`, [docs/INCIDENT-ATTRIBUTION.md](docs/INCIDENT-ATTRIBUTION.md)):
  each incident gets a graded attribution (`network`, `network_despite_host`, `mixed`,
  `observer_likely`, `observer_confirmed`) from the scope, dose, timing and counter-evidence of
  ten host effects, the seconds explained by the host and by the network, an evidence list,
  what would change the result, and likely network causes (router reboot, WAN down, router
  log, AP disconnect, channel switch, carrier loss, roam, DHCP, weak signal, busy channel).
  Shown in the web report incident rows and the Markdown outage table; 34 scenario tests and
  5 end-to-end tests.
- `linkwatch check --deep`: timer jitter, loopback RTT, CPU/IO pressure (PSI) and a per-interface
  path proof (replies must arrive on the interface that sent the probe).
- `linkwatch calibrate [--seconds N]`: idle baseline of every path (gateway RTT p50/p95/p99,
  loss, NIC errors) and timer jitter, written to `<data_dir>/calibration.json`.

### Changed
- `scripts/ci.sh` runs the CI checks locally or in Docker; clippy is clean with `-D warnings`.
- Release archives include `docs/INSTALL.md`.

### Fixed
- A small host effect no longer hides a long network outage, and a host effect that
  cannot cause the symptom (a Wi-Fi scan beside a cable outage, a driver reset after the
  outage began) no longer excludes it. Removed checks for host alerts that were never emitted.
- Clock sync with chrony: the daemon is asked for its real state (stratum, offset, max error)
  over its read-only UDP command port, so a running but unsynchronized `chronyd` is reported.

## [0.6.0] - 2026-11-28

### Added
- Step-by-step install guide: [docs/INSTALL.md](docs/INSTALL.md).
- `linkwatch check` reads host settings that can imitate network faults (no root needed):
  per-interface `rp_filter`, cable speed/duplex and NIC CRC errors, USB/PCIe power control,
  active VPN/tunnel interfaces, conntrack fill and container bridges, two network managers,
  blocked Wi-Fi radio, Bluetooth on 2.4 GHz, random MAC address, MTU < 1500, equal
  default-route metrics, local-only DNS resolver, Wi-Fi country `00` (nl80211 `GET_REG`)
  ([docs/HOST-ISOLATION-SCENARIOS.md](docs/HOST-ISOLATION-SCENARIOS.md) `H13`–`H24`).
- Analyzer: the host's own traffic above 10 Mbit/s or 2000 packets/s (new `Sample.pkt_delta`) outside the speed test is not counted as
  stalls, and short unconfirmed drops in that time are observer incidents
  (`self_traffic_s`, `self_traffic_stalls`, finding `o_self_traffic`).

- **Observer Trust Score** per session (`clean | caution | polluted` with reasons) in the
  analyzer report, the Markdown report and a KPI tile of the web report; a polluted observer
  lowers support-pack readiness (`warn_observer_polluted`).

## [0.5.0] - 2026-11-28

### Added
- **New web UI** with four views: Now (verdict hero, path strip, path rows), Sessions (session list,
  report, timeline, incidents, compare of 2–8 sessions), Map (measurement dialog, RF ray through
  walls), Diagnostics (recommendations, Wi-Fi, router, observer, audit). Phone layout with bottom
  navigation. See [docs/UI-DESIGN.md](docs/UI-DESIGN.md).
- **Translatable server messages:** verdict sentence, advisor items, analyzer findings, patterns,
  incident context and compare notes carry a stable `code` + `args` (`Msg`); the UI shows them in
  English or Ukrainian.
- `[web] view = "token" | "open"`: open read-only viewing while changes still need the token.

### Fixed
- `GET /api/router/audit` no longer probes the network; probes need `POST` with the token.
- Live session report is reused for 30 s and built once for parallel viewers.
- CVE query sanitizer keeps word breaks and `+`; analyzer reports roam/channel context.
- The advisor never says "no issues" while the live verdict shows a failing path.

## [0.4.0] - 2026-11-27

### Added
- **Multi-language Web UI (`i18n`):** Extensible translation registry (`en`, `uk`) with automatic browser language detection, `localStorage` persistence, and zero external dependencies ([docs/I18N.md](docs/I18N.md)).
- **Router Diagnostics Module:** Read-only local adapters (`upnp`, `snmp`, `tr064`, `openwrt`, `mikrotik`, `http`), SNMP interface error counters (`IF-MIB`), gateway LAN port risk inspection, and RFC1918/loopback SSRF guards.
- **Vulnerability & Advisory Checks:** Manual on-demand CVE + CISA KEV lookup (CIRCL + NIST NVD 2.0 + offline `cve-bundle.json[.gz]` fallback), CPE query normalization, version comparison, and rule-based Wi-Fi/security/router advisor (`/api/advice`).
- **Passive Wi-Fi Security IEs:** Parses RSN (`WPA2`, `WPA2/WPA3`, `WPA3`, `TKIP`, `WPA`, `WEP`, `Open`), `WPS` beacon presence, and `PMF` flags in `nl80211` scans.
- **Session Report Preview, Export & Multi-Session Compare:** Live/historical `/api/report`, downloadable `/api/report/export?format=md|json`, and `/api/compare?sessions=...`.
- **Site Layout Walls, Doors & RF Loss:** Wall materials (`concrete`, `brick`, `drywall`, `glass`, `wood`), door swings/kinds, vertical neighbor overlays (`above`/`below`), and 5 GHz RF obstacle loss estimation (`RfPathEstimate`).
- **Alert Notifier & Preflight Extensions:** Optional `[alerts]` webhook / `ntfy` notifications on sustained outages and security events; `linkwatch check` gateway port & UPnP readiness checks.
- **Multi-Arch Releases & CI:** Automated CI + tagged release workflow producing static musl `.tar.gz` binaries and `.deb` packages for `amd64` and `arm64`.

### Changed
- License migrated to **PolyForm Shield 1.0.0**.
- Dependency stack switched to pure Rust TLS/crypto (`rustls` + `rustls-rustcrypto` + `snmp2` crypto-rust) for zero-C cross-compilation.
