# linkwatch Features & Architecture

Detailed technical reference of what `linkwatch` currently implements and how each subsystem works.

---

## 1. Design Guarantees

- **Pure Rust, zero `unsafe`, zero subprocesses:** `#![forbid(unsafe_code)]` across the crate. All probes, netlink Wi-Fi queries, sysfs/procfs reads, UPnP/SOAP, HTTP Digest, OpenWrt `ubus`, SNMP v1/v2c, and HTTPS CVE lookups run through typed sockets and pure-Rust crates (`rustls` + `rustls-rustcrypto` for TLS). Never invokes `ping`, `iw`, `ip`, `curl`, or `snmpwalk`.
- **Explicit timeouts & bounded memory:** Every socket read, connect, discovery, and channel queue is bounded. Slow web clients or full storage channels never stall the per-second monitor loop.
- **Privacy by design:**
  - LAN device sweeps (`lan_s`) store and transmit only integer counts (`probed`, `ping_alive`, `arp_alive`, `unique_seen`). MAC deduplication hashes addresses in memory using a per-run salted hasher (`DeviceCounter`, capped at 4096 entries); IP/MAC lists are never persisted.
  - Router probe credentials (`username`, `password`, `community`) live only in RAM during a single `POST /api/router/probe` call, are redacted from `Debug` formatting (`[redacted]`), and are never written to disk or returned in HTTP responses.
- **Offline-first Web UI:** HTML, ES modules, and CSS are compiled in (`include_str!`), require no CDN or Node at runtime, and enforce strict Content Security Policy (`default-src 'self'`, `form-action 'none'`, no inline scripts/styles). External HTTPS connections occur **only** when the user explicitly triggers a manual CVE check.

---

## 2. Multi-Layer Probing & Cross-Path Verdict Attribution

For every configured or auto-detected physical interface (bound with `SO_BINDTODEVICE`), each tick probes multiple layers in parallel:

| Layer | Mechanism | What failure isolates |
|---|---|---|
| **Link** | `sysfs` / `getifaddrs` (`src/link.rs`) | Unplugged cable, interface down, disassociated Wi-Fi |
| **Wi-Fi** | `nl80211` generic netlink (`src/wifi/`) | Weak RSSI, busy channel airtime, high TX retries, disconnects, roaming |
| **Router (GW)** | Unprivileged `SOCK_DGRAM` ICMP + optional UPnP IGD | Local Wi-Fi hop or gateway hang/reboot |
| **ISP hop** | TTL-limited probe (`IP_TTL 2..=4` via `IP_RECVERR`) to first non-private IPv4 hop | Access modem / DOCSIS / DSL / FTTH line fault |
| **Internet** | Multiple public IPs (ICMP + TCP connect to `:443`) | Upstream transit outage (only `WanDown` when **all** internet targets fail) |
| **DNS** | Hand-built UDP DNS A-record query to system or configured resolvers | DNS resolution fault independent of IP connectivity |
| **Speed** | Periodic plain HTTP/1.1 download (`src/speed.rs`, one interface at a time, skipping TCP warmup window) | Evening / peak bandwidth throttling or bufferbloat under load |

### Debouncing & Cross-Path Verdicts
- Raw per-tick probes are recorded unconditionally (`samples-YYYYMMDD.jsonl`).
- State transitions (`Ok`, `Degraded`, `LinkDown`, `NoIp`, `LanDown`, `IspDown`, `WanDown`, `DnsDown`) require `classify.debounce` consecutive equal ticks (default `3`), eliminating single-packet jitter false alarms while preserving 1–2 s glitches as **micro-drops** in analysis.
- Comparing active interfaces at the same timestamp produces a cross-path verdict (`AllOk`, `WifiProblem`, `WiredProblem`, `RouterProblem`, `LineProblem`, `InternetProblem`, `Dns`, `SinglePath`).

### Measurement Profiles
- `light`: 5 s tick interval for constrained boards.
- `standard`: 1 s tick interval (default).
- `detailed`: 0.5 s tick interval with per-second Wi-Fi stats.
- All sessions store their complete configuration in `meta.json` and normalize metrics by time/rate so sessions with different profiles remain comparable.

---

## 3. Wi-Fi Diagnostics & Passive Security IEs (`src/wifi/`)

Implemented over hand-parsed `nl80211` generic netlink attributes and TLVs:
- **Station stats:** RSSI (instant + signal average), TX/RX bitrates, cumulative TX retries and failures, connected BSSID, frequency/channel, channel width (20/40/80/160 MHz), and `power_save` state.
- **Channel survey:** Airtime busy/noise ratios (`ChannelLoad`) handling driver counter resets.
- **MLME kernel events:** Disconnections (`wifi_disconnect`) capture reason codes and whether initiated by the AP (`by_ap`) or locally, plus roaming across BSSIDs (`roam`) and AP channel switches (`channel_change`).
- **Passive beacon / probe-response Security IEs (`ScanBss`):**
  - Parses RSN (`IE 48`), WPA1 (`IE 221` MS OUI `00:50:F2:01`), WPS (`IE 221` MS OUI `00:50:F2:04`), and `BSS_CAPABILITY` privacy bit (`IE` + NL80211 capability).
  - Extracts `security` (`Open`, `WEP`, `WPA`, `WPA2`, `WPA2-TKIP`, `WPA2/WPA3`, `WPA3`), `wps` (`bool` when WPS IE is present), and Protected Management Frames (`pmf`: `required`, `optional`, or omitted).
  - Displayed in the **Wi-Fi** tab scan table with status pills and WPS badges.

---

## 4. Observer Health vs Network Incidents (`src/host.rs`)

Measures the monitoring box itself (`host-YYYYMMDD.jsonl`, default every 10 s):
- CPU %, 1-minute load average, RAM %, disk free bytes, CPU thermal zone temperature, NTP synchronization status, and Wi-Fi `power_save` flags.
- **Raspberry Pi hardware health:** reads undervoltage / throttling bitmask (`rpi_throttled`, `throttled`).
- **Anomaly protection:** detects `ifindex` changes (driver/firmware resets), monotonic-vs-wall clock jumps, and OS suspend gaps (`CLOCK_BOOTTIME` vs `CLOCK_MONOTONIC`).
- Outage episodes caused by off-channel Wi-Fi scans, monitor loop overruns, host throttling, or OS suspend are classified with `origin = "observer"` and excluded from network availability and incident totals.

---

## 5. Router UPnP IGD Telemetry & LAN Device Sweep

### UPnP IGD Poller (`src/router.rs`)
- Disabled by default (`[router] enabled = false`). When enabled, discovers the gateway's IGDv1/IGDv2 description XML via SSDP (`M-SEARCH` restricted to the gateway IP) or explicit `upnp_url`.
- Polls SOAP `GetStatusInfo`, `GetCommonLinkProperties`, `GetTotalBytesReceived`/`Sent` (and `GetTotalPacketsReceived`/`Sent`), computing WAN Mbit/s, packet/s rates, uptime, physical link status, and `bytes_saturated` (when 32-bit router counters clamp at `i32`/`u32::MAX`).

### Active LAN Device Count (`src/lan.rs`)
- Disabled by default (`[intervals] lan_s = 0`; valid `0` or `>= 60` s).
- On subnets `/22` through `/30` (`<= 1022` hosts), sends concurrent unprivileged ICMP echoes (`IN_FLIGHT = 32`), forcing kernel ARP resolution even for ICMP-silent devices, then inspects `/proc/net/arp` to count resolved neighbours (`arp_alive`) alongside `ping_alive` and `unique_seen`.
- Rendered on the timeline chart alongside outages and RTT to reveal whether evening stalls correlate with device spikes.

---

## 6. Router Diagnostics Module (`src/router_audit.rs`)

Read-only router auditing accessible from the **System** tab and `/api/router/*`:

### Modular Adapters
1. **`upnp`** (no credentials): fetches IGDv1/v2 device XML + status + link properties (`vendor`, `model`, `firmware_hint`, `admin_url`, `uptime_s`, WAN rates).
2. **`snmp`** (SNMP v1/v2c over UDP `:161`, default community `public`): queries standard MIB-II OIDs (`sysDescr`, `sysUpTime`, `sysName`, `ifNumber` under `1.3.6.1.2.1.*`) plus `ifDescr`, `ifInErrors`, `ifOutErrors`, and `ifOutDiscards` on interfaces `1..=8` to flag non-zero port errors.
3. **`tr064`** (HTTP SOAP on gateway port `49000`, `/upnp/control/deviceinfo`): queries `DeviceInfo:1#GetInfo` unauthenticated or with RFC 2617 HTTP Digest MD5 auth (`username`/`password`) for `NewManufacturerName`, `NewModelName`, `NewSoftwareVersion`, `NewUpTime`, `NewHardwareVersion`.
4. **`openwrt`** (LuCI `ubus` JSON-RPC over HTTP `/ubus`): authenticates `session.login`, queries `system.board` (`model`, release description/version, kernel) and `system.info` (`uptime`).
5. **`mikrotik`** (RouterOS REST over local HTTP `/rest/system/resource` and `/rest/system/routerboard`, optional Basic auth): reads board/model, RouterOS version, RouterBOARD firmware, uptime (`parse_mikrotik_uptime`), architecture, CPU load, and free memory.
6. **`http`** (HTTP `GET /` on port `80`, optional Basic auth): reads `Server` response header and HTML `<title>` banner.
7. **`auto`**: passively runs `upnp` -> `snmp` (when community given) -> `http` without credentials; with credentials, probes `tr064`, `openwrt`, and `mikrotik` (when firmware is still unknown).

### Gateway LAN Port Scan
Fast concurrent TCP connect check (650 ms timeout per port) on RFC1918/loopback gateway ports:
- `21 (FTP)`, `23 (Telnet)` -> risk **`high`** if open.
- `80 (HTTP)`, `8080 (HTTP-Alt)` -> risk **`warn`** if open while `443 (HTTPS)` is closed.
- `22 (SSH)`, `53 (DNS)`, `443 (HTTPS)`, `49000 (TR-064)` -> risk **`info`** if open.

### Security Boundaries
- `validate_local_host()` accepts **only** RFC1918 private, loopback, or link-local IPv4 addresses (rejecting public IPs like `8.8.8.8` with HTTP 400 to prevent SSRF).
- Active `POST /api/router/probe` requires `[web] token` configured + authenticated request + same-origin check + `application/json` + 5 s rate limit (`429 Too Many Requests` with `Retry-After`).

---

## 7. On-Demand CVE & CISA KEV Lookup (`src/cve.rs`)

Runs **only** when manually triggered via **Check CVEs** (`POST /api/router/cve`):
1. Requires `[web] token` configured, authenticated caller, same-origin header, JSON body, validated `model` (1–128 non-control chars), and 5 s rate limit.
2. Uses pure-Rust TLS (`rustls` + `rustls-rustcrypto` + `webpki-roots`), bounded response limits (`2 MiB` API / `6 MiB` KEV feed, gzip decoding).
3. Normalizes noisy device strings via `normalize_device_query` (strips generic phrases like `"wireless router"`, removes duplicate vendor prefixes, infers common vendors like `tp-link`, `asus`, `mikrotik`, `avm`, `ubiquiti`, `netgear`, `d-link`, `openwrt`) and compares dotted versions via `version_lt`.
4. Fetches and caches CISA Known Exploited Vulnerabilities (`<data_dir>/kev-cache.json`, 24 h TTL).
5. Queries `https://vulnerability.circl.lu/api/vulnerability/search/<vendor>/<model>` first (when vendor is given), falling back to NIST NVD 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=...`, optionally authenticating with `[router] nvd_api_key`).
6. If online APIs return no hits or are unreachable, falls back cleanly to an optional local offline bundle (`<data_dir>/cve-bundle.json.gz` or `cve-bundle.json`), skipping CVEs patched below the supplied `firmware` version (`affected_below`).
7. Caches normalized results per `(vendor, model, firmware)` for 24 hours in `<data_dir>/cve-cache.json` (up to 64 entries) and tags any matching CISA KEV entry.

---

## 8. Configuration & Security Advisor (`src/advice.rs`)

Pure rule engine combining `LiveSnapshot` and cached `RouterAudit` into prioritized recommendations (`critical`, `warn`, `info`, `ok`):

| ID prefix | Trigger condition | Category | Recommended action |
|---|---|---|---|
| `wifi_sec_<if>` | Connected BSS uses `Open` or `WEP` | `security` | Switch to WPA2-PSK (AES) or WPA3-SAE |
| `wifi_tkip_<if>` | Connected BSS advertises `WPA` or `WPA2-TKIP` | `security` | Disable TKIP / WPA1; require AES-CCMP |
| `wifi_wps_<if>` | Connected BSS advertises WPS IE | `security` | Disable WPS to prevent PIN brute-force attacks |
| `port_high_<port>` | Gateway port `21` (FTP) or `23` (Telnet) open | `security` | Disable insecure cleartext service in router admin |
| `port_http_<port>` | Gateway HTTP `80`/`8080` open while `443` closed | `security` | Enable HTTPS router management if supported |
| `wifi_weak_<if>` | Connected RSSI `< -75 dBm` | `wifi` | Move closer, reposition clear of concrete/bath walls, or wire an AP |
| `wifi_ps_<if>` | Interface `power_save == true` | `wifi` | Disable with `iw dev <if> set power_save off` |
| `wifi_24_overlap_<if>` | 2.4 GHz channel not in `{1, 6, 11}` | `wifi` | Switch to cleanest of `{1, 6, 11}` at 20 MHz |
| `wifi_24_40mhz_<if>` | 2.4 GHz channel width is 40 MHz | `wifi` | Narrow 2.4 GHz width to 20 MHz |
| `wifi_congestion_<if>` | Channel airtime busy `> 60%` & cleaner channel exists | `wifi` | Switch to least-crowded channel observed in scan |
| `router_wan_down` | UPnP `wan_status` != `Connected` | `router` | Inspect ISP cable/fibre/modem side |
| `router_bufferbloat` | UPnP WAN traffic `> 50 Mbit/s` and internet RTT `> 80 ms` | `router` | Enable SQM / Smart Queue Management / QoS shaping |
| `host_throttled` | Observer host reports active throttling/undervoltage | `observer` | Upgrade power supply for reliable telemetry |
| `host_ntp` | `clock_synced == false` | `observer` | Fix NTP so multi-session comparisons align |
| `host_temp` | Host CPU temperature `>= 75 °C` (`>= 85 °C` critical) | `observer` | Improve cooling/airflow around observer |

---

## 9. Passive Security Detectors (`src/security.rs`)

Continuous detectors emitting `EventKind::Security` events onto the event stream:
- **`gateway_mac_change`:** detects gateway MAC address changes on an interface or conflicting MACs for the same gateway IP across interfaces.
- **`rogue_gateway` / `rogue_dhcp`:** detects unexpected default gateway or DHCP server transitions within a session.
- **Evil-twin AP detection:** flags unknown OUI MAC prefixes broadcasting an already-known local SSID.
- **DNS anomaly detection:** alerts when a public hostname resolves to RFC1918/private IP space or when resolvers return disjoint `/16` address prefixes consecutively.

---

## 10. Site Layout Model & Measurement Plan (`src/site.rs`)

Describes physical spaces cleanly in TOML without hard-coded buildings:
- **`[[unit_type]]`**: explicit reusable unit definitions (left/right layouts as separate types in metres, `x` right, `y` down):
  - `rooms`: `{ id, name, rect | poly }` — each room acts as a clickable map region and an observation point `<building>/<unit>/<room>`.
  - `fixed`: non-testable regions such as bathrooms or stairwells.
  - `walls`: line segments `{ from, to, material, thickness_cm? }` where `material` is `concrete`, `brick`, `drywall`, `glass`, or `wood` (rendered with distinct wall weights/styles).
  - `doors`: `{ from, to, swing, kind, label? }` (`interior`, `exit`, `fire`, `balcony`; `left`, `right`, `double`, `sliding`).
  - `points`: named markers (`router`, `ap`, `booster`, `probe`, `other`).
- **`[[building]]`**: stacks units by `floor` and maps unit types; computes vertical floor neighbors (`above`, `below`) for floor-to-floor RF context overlays.
- **RF Obstacle Estimate (`RfPathEstimate`):** `Site::estimate_rf()` finds the nearest `router`/`ap` marker in the building, counts wall crossings along the straight path (`glass` ~2.5 dB, `drywall` ~3 dB, `wood` ~4 dB, `brick` ~9 dB, `concrete` ~14 dB, scaled by `thickness_cm`), adds `15 dB` per floor slab crossed, and surfaces the estimate on room cards in the UI.
- **`[[plan]]`**: target hours (`0 < hours <= 168`) per point; tracks recorded duration (`>= 60 s` sessions count) with statuses `todo`, `partial`, `done`, `active`.

---

## 11. Web UI, Multi-Language Support & HTTP/SSE API (`src/web/`)

### 4 Dashboard Tabs & i18n
1. **Live:** Session selector (live or historical), network path topology SVG, per-interface live sparkline cards, `15 m` / `1 h` / `3 h` / `6 h` / `24 h` / `72 h` canvas timeline (losses, GW/Net RTT, RSSI, channel busy, LAN device count), **Session summary & incidents** preview (plain-English verdict, KPIs, 24 h hourly loss profile, clickable incident cards, **Export MD / Export JSON** links), event filter feed, and speed test log.
2. **Map & Plan:** Building selector, vertical floor cross-section grid, detailed unit floor plan with walls/doors/rooms/RF obstacle estimates (`RfPathEstimate`) and optional `above`/`below` floor overlay, active session switcher with confirmation, plan progress checklist, and **Points comparison** table.
3. **Wi-Fi:** Connected interface radio details + RSN/WPS context, scan filters (`All`, `Our network`, `Interfering`, `2.4 GHz`, `5 GHz`), overlapping-channel spectrum SVG arches, and scan table with **Security** & **WPS** badges.
4. **System:** Alert bar summary dot, **Recommendations** (`#advice-panel`), Observer health, UPnP Router telemetry, LAN Sweep counters, **Router audit & firmware CVEs** panel (with `mikrotik` support), and Observer/Security filtered event feed.

- **Extensible i18n (`EN` / `UA`):** Header language selector (`#lang-sel`) switches static labels, tooltips, verdicts, path states, advisor chrome, and RF notes dynamically (`localStorage` key `lw-lang`, auto-detects `navigator.languages` on first visit; see [docs/I18N.md](I18N.md)).
- Interactive `ⓘ` tooltips explain thresholds and causes on hover (desktop), tap (mobile), and `Esc` (close).

### HTTP & SSE API Summary

| Method | Endpoint | Auth / Guard | Purpose |
|---|---|---|---|
| `GET` | `/api/status` | Token (if set) / Host | Live snapshot: verdict, interfaces, host, UPnP router, LAN |
| `GET` | `/api/minutes` | Token (if set) / Host | Time-series minute buckets (`?session=&iface=&hours=\|minutes=`) |
| `GET` | `/api/events` | Token (if set) / Host | Recent live events (`?limit=`) |
| `GET` | `/api/speed` | Token (if set) / Host | Recent speed test runs |
| `GET` | `/api/scan` | Token (if set) / Host | Last Wi-Fi scan report per interface (`security`, `wps`, `pmf`) |
| `GET` | `/api/site` | Token (if set) / Host | Resolved site geometry, walls, doors, points, floor links, RF loss |
| `GET` | `/api/plan` | Token (if set) / Host | Measurement plan progress across all recorded sessions |
| `GET` | `/api/sessions` | Token (if set) / Host | Recorded session index (sessions >= 60 s or current) |
| `GET` | `/api/report` | Token (if set) / Host | Structured analyzer report + incidents (`?session=`) |
| `GET` | `/api/report/export` | Token (if set) / Host | Download full report as Markdown or JSON (`?session=&format=md\|json`) |
| `GET` | `/api/compare` | Token (if set) / Host | Compare 2..=8 sessions (`?sessions=a,b&tolerance_s=2.0&format=json\|md`) |
| `GET` | `/api/sessions/:id/summary` | Token (if set) / Host | Stored or computed session summary |
| `GET` | `/api/sessions/:id/events` | Token (if set) / Host | Historical session events (`?limit=`) |
| `GET` | `/api/live` | Token (if set) / Host | SSE stream of real-time `Envelope` records |
| `GET` | `/api/control` | Token (if set) / Host | Check if UI control is enabled + known points |
| `POST` | `/api/control/session` | Token required + SameOrigin + JSON + 10 s limit | Switch measurement session `{point?, label?, note?}` |
| `GET` | `/api/router/audit` | Token (if set) / Host | Cached or passive UPnP/SNMP/HTTP audit + gateway ports |
| `POST` | `/api/router/probe` | Token required + SameOrigin + JSON + 5 s limit | Active adapter probe `{adapter?, host?, username?, password?, community?}` |
| `POST` | `/api/router/cve` | Token required + SameOrigin + JSON + 5 s limit | Manual CVE/KEV lookup `{vendor?, model, firmware?}` |
| `GET` | `/api/advice` | Token (if set) / Host | Evaluated config & security recommendations |

---

## 12. CLI, Offline Analysis & Storage Format

### Subcommands
- `linkwatch check` — preflight checks: `CAP_NET_ADMIN`/scan capability, physical interfaces, ARP sysctls (`arp_ignore`, `arp_announce`, `rp_filter`), Wi-Fi `power_save`, NTP sync, disk space, web bind port, gateway LAN admin ports, and UPnP IGD responsiveness (when enabled).
- `linkwatch run [--point ID] [--label TXT] [--new-session] [--no-web]` — continuous monitor loop (systemd `Type=notify` watchdog; auto-resumes unfinished sessions `< 12 h` unless `--new-session`).
- **Optional Webhook / `ntfy` Alerts (`[alerts]`):** Non-blocking pure-Rust HTTP/HTTPS POST notifications on sustained outage verdicts (`>= min_outage_s`), recovery back to `all_ok`, and security detector events (`security_events = true`), bounded by per-key cooldown (`cooldown_s`).
- `linkwatch config` — print effective configuration as TOML.
- `linkwatch sessions` — list recorded session directories with timestamps, point IDs, and completion state.
- `linkwatch analyze [SESSION] [--router-log FILE] [--json]` — single-session report with DOCSIS modem T3/T4 log correlation, per-band breakdown, bufferbloat vs idle RTT, median/MAD anomalies, and repeating hourly/period patterns.
- `linkwatch compare S1 S2 [S3...] [--tolerance-s 2.0] [--json]` — multi-session comparison verifying network fingerprint overlap and isolating shared upstream outages (`±2 s` aligned) from room-local Wi-Fi defects.

### Session Files (`<data_dir>/<session>/`)
- `meta.json` — session ID, timestamps, observer hostname/`host_id`, point, label, note, full config, initial `NetworkFingerprint`.
- `samples-YYYYMMDD.jsonl` — per-tick interface link + probe states.
- `events-YYYYMMDD.jsonl` — state changes, verdicts, roaming, MLME disconnects, security events, heartbeats.
- `wifi-YYYYMMDD.jsonl` — `WifiStation`, `Survey`, `ChannelLoad`, and `ScanReport` records.
- `speed-YYYYMMDD.jsonl` — download throughput test results.
- `host-YYYYMMDD.jsonl` — `HostSample`, `RouterSample` (UPnP), and `LanSample` records.
- `heartbeat` — atomically updated Unix-day sentinel for crash-gap measurement.
- `summary.json` — generated on graceful stop.
- Old day `.jsonl` files are background-compressed to `.jsonl.gz` (`[storage] compress_old = true`), with disk-pressure degradation below `min_free_bytes` and `critical_free_bytes`.

---

## 13. License

Distributed under **[PolyForm Shield 1.0.0](../LICENSE.md)** (`Required Notice: Copyright (c) 2026 OlehDzhumyk`). Free to use, modify, and share for personal or internal business purposes, prohibiting competing products/services.
