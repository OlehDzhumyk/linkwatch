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
