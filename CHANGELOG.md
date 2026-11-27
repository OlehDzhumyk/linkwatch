# Changelog

All notable changes to `linkwatch` are documented in this file.

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
