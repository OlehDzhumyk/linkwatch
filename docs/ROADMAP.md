# linkwatch Roadmap & Planned Features

Design specifications for upcoming capabilities and how each should work safely within `linkwatch`'s architecture (pure Rust, `#![forbid(unsafe_code)]`, strict offline CSP, RAM-only secrets).

> **Shipped in `v0.4.0`:** MikroTik RouterOS REST adapter, SNMP `IF-MIB` interface error/discard counters, CVE query normalization + firmware comparison + offline `cve-bundle.json[.gz]` support, RF wall/floor obstacle loss calculation (`RfPathEstimate`), Web UI Markdown/JSON export (`/api/report/export` & `/api/compare`), `[alerts]` webhook/`ntfy` notifications, gateway port & UPnP checks in `linkwatch check`, extensible UI `i18n` (`EN`/`UA`), and multi-arch CI/CD releases.

---

## 1. Visual Site Layout Editor (Web UI)

**Goal:** Create and edit building/unit floor plans directly in the browser without hand-writing TOML coordinates, while keeping `site.toml` as the single clean source of truth.

### Intended Workflow
1. Add an optional **Edit layout** mode behind `[web] token` authentication on the **Map & Plan** tab.
2. Provide interactive grid snapping (0.25 m / 0.5 m step) to:
   - Draw or resize rectangular/polygonal rooms with `id` and `name`.
   - Mark `fixed` non-testable blocks (bathrooms, lift shafts, stairwells).
   - Draw `walls` along grid edges or point-to-point with selectable material (`drywall`, `glass`, `wood`, `brick`, `concrete`) and optional `thickness_cm`.
   - Snap `doors` (`interior`, `exit`, `fire`, `balcony`) onto walls with hinge swing (`left`, `right`, `double`, `sliding`).
   - Place `router`, `ap`, `booster`, and `probe` markers on the floor plan.
3. **Export / Apply:**
   - Generate valid deterministic TOML preview (`Export site.toml`) usable with zero server disk writes.
   - Optionally persist via a token-guarded `POST /api/site` endpoint (validating the full schema through `Site::parse_str()` and performing atomic write + live reload).

---

## 2. Interactive SVG RF Ray Overlay

**Goal:** Highlight on the SVG floor plan *which specific walls* a signal crosses from the router placement to the selected room (extending the numeric `RfPathEstimate` already computed by `Site::estimate_rf()`).

### Intended Behaviour
- Draw the dashed line-of-sight ray between the nearest `router`/`ap` marker and the hovered/selected room center on the SVG canvas.
- Emphasize intersected wall segments alongside measured room RSSI for side-by-side comparison.

---

## 3. Additional Router Diagnostics Adapters

**Goal:** Expand `src/router_audit.rs` cleanly behind the existing `RouterAdapterKind` dispatch while staying read-only and credential-safe.

| Planned Adapter | Transport & Auth | Data Collected |
|---|---|---|
| **`ssh_readonly`** | Pure-Rust SSH (`russh` when vetted with zero C deps) running allowlisted read-only info commands | `uname`, wireless config summary (`uci show wireless` on OpenWrt, read-only system info) |
| **`router_log_pull`** | Adapter-specific log endpoint (where supported without screen-scraping arbitrary HTML) | Auto-correlate router/modem disconnects inside `/api/report` without manual copy-paste |

All new adapters must enforce `validate_local_host()` (private/loopback IPv4 only), strict timeouts (`<= 3 s`), bounded response sizes, and RAM-only credentials.

---

## 4. End-of-Life Tracking & UI Session Compare

- **Router EOL Warnings:** Flag hardware/firmware families in `src/advice.rs` when vendor security support is older than a configurable threshold (e.g. 3 years).
- ~~**Web UI Multi-Session Compare View**~~ — done in 0.5.0 (Sessions view).
- **Additional UI Languages:** Community locale files following [docs/I18N.md](I18N.md) (Spanish, Polish, German, French, etc.).

---

## 5. Dependency hygiene

- **Replace `chrono`** (RUSTSEC-2026-0543, unmaintained) with `jiff`; until then the advisory is
  ignored in `.cargo/audit.toml`.
- **`paste`** (RUSTSEC-2024-0436) comes in through `rustls-rustcrypto`; it goes away when that
  provider is replaced or updated.
- **Major updates proposed by Dependabot** (axum 0.8, md-5 0.11, netlink-sys 0.9) need code
  changes; they are done as separate pull requests, never merged blind.
- **UI interaction and motion** (stage 3): see [docs/UI-DESIGN.md](UI-DESIGN.md) §11.

---

## 6. Support & Escalation Report Pack (`src/support_report.rs`)

> **Full design & 12 branching scenarios (load on demand when implementing):** [docs/SUPPORT-REPORT-DESIGN.md](SUPPORT-REPORT-DESIGN.md).

**Goal & Module Boundary:** Turn raw diagnostics into an actionable, redacted, audience-specific escalation package without duplicating any detection logic.
- Implement a dedicated pure-Rust synthesis and redaction module `src/support_report.rs` (`#![forbid(unsafe_code)]`, offline-first, CSP-safe).
- Keep `src/analyze/` and `src/compare.rs` strictly as forensic detection engines, and `src/advice.rs`, `src/router_audit.rs`, and `src/cve.rs` strictly as diagnostic producers. `support_report` consumes their typed outputs (`Report`, `CompareReport`, `AdviceResponse`, `RouterAudit`, `CveLookupResponse`, `RfPathEstimate`) and formats them for external recipients.

### Audience Profiles (`SupportAudience`)
1. **`isp` — ISP Support Ticket** (built to skip tier-1 reboot scripts):
   - Wired-vs-Wi-Fi isolation proof (Ethernet baseline vs wireless hop over overlapping windows).
   - Exact outage/micro-drop timestamps in both **UTC and local time**, duration, and path state.
   - Router telemetry proof (`uptime_s`, `0` reboots vs WAN resets, `wan_status`, `isp_hop` reachability).
   - Throughput & latency-under-load (bufferbloat) summary distinguishing idle drops from load saturation.
   - **"Already ruled out"** checklist: Ethernet cable tested, NTP clock synced, Wi-Fi power-save disabled, local observer faults excluded.
   - Concrete tier-2 asks (e.g., check CMTS/ONT/line logs at exact timestamps).
2. **`landlord` — Property Owner / Manager Brief:**
   - Plain-language verdict separating ISP line reliability from building/unit Wi-Fi coverage.
   - Room-by-room availability, signal, retry rate, and `RfPathEstimate` wall/material obstacle summary table.
   - Practical fix comparison backed by data (e.g. why adding a wired hallway AP resolves multi-wall attenuation, whereas cheap wireless repeaters increase co-channel contention).
3. **`admin` — Local Admin / Hardware Vendor Escalation:**
   - Router hardware/firmware inventory, open LAN management ports (`Telnet`/`HTTP`/`HTTPS`/DNS), and CVE + CISA KEV summary.
   - Radio and security configuration findings (2.4 GHz channel overlap/40 MHz, 5 GHz co-channel sharing, `WPA2-TKIP`/WEP/WPS/PMF flags, bufferbloat under load).
   - Step-by-step hardening checklist and firmware upgrade or EOL hardware replacement asks.

### Evidence-Gated "Requests to Support" (`SupportAsk`)
Deterministic rules emit support requests **only** when backed by measured evidence and cite exact timestamps/metrics. Include **negative gating** to prevent misdirected tickets:
- `WifiProblem` / `LocalOnly` while Ethernet stays ~100% online → explicitly instructs **not** to file an ISP line fault ticket and routes asks to `landlord` / `admin`.
- `LineProblem` / `SharedOutage` (cable failed while gateway answered) → requests upstream CMTS/ONT/access-line log check at the exact UTC + local timestamps.
- `RouterProblem` or `uptime_resets > 0` → requests router hardware/power/firmware check or unit replacement.
- Speedtest/load-provoked timeouts & elevated loaded RTT (`loaded_net_rtt_med`) → separates saturation bufferbloat from unprovoked line outages; recommends router SQM/AQM or bridge mode + dedicated router.
- `Dns` failures while IP probes succeed → requests ISP resolver check or alternate DNS configuration.
- Matched CVEs / EOL firmware / insecure open ports or legacy Wi-Fi ciphers → emits firmware upgrade, port lockdown, or cipher migration asks.

### Privacy & Redaction (`RedactionLevel`)
- **`none`:** Internal operator view; preserves full IDs, local IPs, BSSIDs, and hostnames.
- **`standard` (default for `isp` / `landlord`):** Masks BSSID/MAC addresses to the last 3 octets, omits LAN client scan details, and strips `[web] token` values and local filesystem paths.
- **`strict` (for public forums / bug reports):** Applies `standard` redaction plus replaces private LAN and ISP hop IPs with RFC 5737 documentation placeholders and generalizes point/unit identifiers.

### Output Formats & Independent Export Language
- **Ticket Text (`.txt`, `<= 2000` chars):** Concise copy-paste summary sized for live chat and ISP web ticket forms.
- **Full Markdown (`.md`):** Structured report with evidence tables, timeline highlights, and asks.
- **Printable HTML (`.html`):** Self-contained offline document with `@media print` styling so browsers can Save-as-PDF without adding external PDF crates.
- **JSON (`SupportPack`):** Typed output using translatable `Msg` codes + args, exported for TS bindings.
- **Independent language choice:** `--lang en|uk` (and future community locales per [docs/I18N.md](I18N.md); no Russian) works independently of the Web UI language, allowing diagnostics in one language and ticket export in another.

### Prerequisites & Interfaces
1. **Report model additions:** Expose `loaded_gw_rtt_med` / `loaded_net_rtt_med` in `/api/report` (`ReportIface`), distinguish load/speedtest-provoked episodes from unprovoked idle outages in `ReportResponse`, and attach per-point `RfPathEstimate` data into multi-session summaries.
2. **CLI:** `linkwatch support-report --audience isp|landlord|admin --lang en|uk --redact standard|strict|none --format text|md|html|json [sessions...]`
3. **Web API & UI:** `GET /api/support-report` plus a **Support report** trigger on the **Sessions** tab opening a CSP-safe `<dialog>` with audience/language/redaction toggles, live preview, copy-to-clipboard button, and `<a download>` links for `.md` and printable `.html`.

---

## 7. Deployment, Discovery & Onboarding

Current pain points (`:8080` collisions, DHCP IP drift, mobile token entry friction, firewall/AP-isolation blindness, Docker `bridge` pitfalls, and manual `scp` between probes) plus ten branching deployment scenarios (`D1`–`D10`) and a prioritized P0–P3 implementation backlog are documented in [DEPLOYMENT-SCENARIOS.md](DEPLOYMENT-SCENARIOS.md).

---

## 8. Host Isolation, Calibration & Self-Check

Twelve branching host/observer artefact scenarios (`H1`–`H12`), active deep preflight verification (`check --deep`), co-located two-probe hardware calibration (`calibrate`), continuous zero-overhead sentinels, and a structured **Observer Trust Score** (`Clean | Caution | Polluted`) are scoped in [HOST-ISOLATION-SCENARIOS.md](HOST-ISOLATION-SCENARIOS.md).

