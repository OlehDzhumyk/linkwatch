# linkwatch

[![CI](https://github.com/OlehDzhumyk/linkwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/OlehDzhumyk/linkwatch/actions/workflows/ci.yml)
[![Release](https://github.com/OlehDzhumyk/linkwatch/actions/workflows/release.yml/badge.svg)](https://github.com/OlehDzhumyk/linkwatch/releases)
[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm%20Shield%201.0.0-blue.svg)](LICENSE.md)
![Linux amd64 / arm64](https://img.shields.io/badge/Platform-Linux%20amd64%20%7C%20arm64-informational)
![Pure Rust](https://img.shields.io/badge/Rust-Pure%20%23!%5Bforbid(unsafe_code)%5D-orange)

**Continuous network path monitor & router security diagnostics for Linux.**  
Find out definitively where your connection breaks: **Wi-Fi**, the **router**, the **ISP line**, **DNS**, or the **monitoring host itself**.

`linkwatch` runs continuously on a Raspberry Pi, mini PC, or Linux box next to your router — probing Wi-Fi and wired Ethernet concurrently every second, isolating ISP vs wireless faults, auditing your gateway, and turning raw telemetry into crisp incident reports.

> **Project origin.** This is a personal tool, written with heavy help from AI coding agents ("vibe-coded") to diagnose Wi-Fi drops in a shared flat. It is pure Rust (`#![forbid(unsafe_code)]`) with no C toolchain dependencies and no external shell calls (`ping`/`iw`/`curl`). Read the code and check it against your own needs before you rely on it.

---

## How it tells causes apart

Every configured interface (`SO_BINDTODEVICE`) is probed across 7 layers simultaneously. Comparing layers and comparing Wi-Fi against Ethernet at the exact same second pinpoints where packets are lost:

| Layer | Target & Method | Failure Means |
|---|---|---|
| **Link** | Kernel state via `sysfs` / `getifaddrs` | Unplugged cable, interface down, Wi-Fi disassociated |
| **Wi-Fi** | `nl80211` netlink stats, airtime survey, beacon IEs | Weak RSSI, congested channel, retries, RSN/WPS posture |
| **Router (GW)** | Unprivileged `SOCK_DGRAM` ICMP + optional UPnP IGD | Local Wi-Fi hop or gateway hang / reboot |
| **ISP hop** | TTL-limited hop discovery (`IP_TTL 2..=4`, `IP_RECVERR`) | Access line / modem / DOCSIS / fibre fault |
| **Internet** | Multiple public IPs (ICMP + TCP `:443`) | Upstream transit outage (only when all fail) |
| **DNS** | Direct UDP A-record query to resolvers | Name resolution only |
| **Speed** | Scheduled plain HTTP/1.1 download tests | Peak congestion / household bufferbloat under load |

| Wi-Fi Path | Cable Path | Verdict |
|---|---|---|
| Fails at router | Healthy | **Wi-Fi problem** |
| Fails | Fails at ISP hop | **ISP line problem** |
| Fails | Fails at router | **Router problem** |
| Works | Works | **All OK** |

---

## Feature Matrix

- **Zero-subprocesses & pure Rust:** Unprivileged ICMP, TCP connect, DNS queries, `nl80211`, UPnP SOAP, SNMP v1/v2c, TR-064 HTTP Digest, OpenWrt `ubus`, MikroTik REST, and `rustls-rustcrypto` HTTPS all in memory with explicit timeouts.
- **Observer vs network attribution (`host` stream):** Monitors CPU, RAM, disk, thermal throttling / Raspberry Pi undervoltage, NTP sync, Wi-Fi `power_save`, `ifindex` driver resets, clock jumps, and OS suspend. Observer-caused glitches are tagged `observer` and excluded from ISP outage totals.
- **Privacy-preserving LAN sweep & UPnP telemetry (`host` stream):** Optional active LAN client counts (`[intervals] lan_s >= 60`, counts only — MACs hashed in RAM and never stored) plus UPnP IGD WAN throughput, link rate, and saturation alerts (`[router] enabled = true`).
- **Router Diagnostics & Advisor (`System` tab):**
  - Read-only protocol adapters: **`auto`**, **`upnp`**, **`snmp`** (including IF-MIB interface error/discard counters), **`tr064`** (HTTP Digest), **`openwrt`** (`/ubus`), **`mikrotik`** (`/rest/system/*`), and **`http`**.
  - Gateway LAN port risk check (`21/FTP`, `23/Telnet`, `80/HTTP`, `443/HTTPS`, `22/SSH`, `53/DNS`, `49000/TR-064`), RFC1918/loopback SSRF enforcement, and RAM-only credentials.
  - Manual on-demand CVE + CISA KEV lookup (CIRCL + NIST NVD 2.0 + offline `cve-bundle.json[.gz]`, CPE query normalization, firmware version matching, 24 h cache).
  - Rule-based Wi-Fi, security, router, and host recommendations (`/api/advice`) + passive Wi-Fi security IEs (`WPA2`, `WPA3`, `TKIP`, `Open`, `WPS`, `PMF`).
- **4-Tab Web UI with multi-language support (`EN` / `UA`):**
  - **Live:** Topology SVG, real-time sparklines, `15 m`–`72 h` canvas timeline, session summary & incidents preview (`/api/report`), hourly loss profile, one-click Markdown/JSON export (`/api/report/export`), events, speed tests.
  - **Map & Plan:** TOML floor plans (`examples/site.toml`) with wall materials (`concrete`/`brick`/`drywall`/`glass`/`wood`), doors, vertical floor neighbors (`above`/`below`), 5 GHz RF obstacle attenuation estimation, measurement point switching, and points comparison.
  - **Wi-Fi:** Overlapping channel spectrum arches, connected radio telemetry, and scan table with RSN/WPS security badges.
  - **System:** Advisor findings, host/UPnP/LAN status, router audit + CVE lookup, observer/security event stream.
  - Extensible static i18n registry (`src/web/ui/src/i18n.ts`; see [docs/I18N.md](docs/I18N.md) — strict offline CSP, zero CDNs).
- **Offline CLI Analysis & Alerts:**
  - `linkwatch analyze` (with `--router-log` DOCSIS matching) and `linkwatch compare` (cross-room fingerprint matching & `±2 s` alignment, plus `/api/compare`).
  - Optional `[alerts]` webhook / `ntfy` notifications on sustained outages and passive security alerts (`gateway_mac_change`, `rogue_gateway`, `rogue_dhcp`, evil-twin OUI, DNS anomalies).
  - Crash-safe append-only JSON Lines storage with gap-free `seq`, torn-tail recovery, background `.jsonl.gz` compression, disk-pressure guards, and `systemd` watchdog integration.

---

## Quick Install

Step-by-step guide for a first measurement: [**docs/INSTALL.md**](docs/INSTALL.md).

### 1. `.deb` package

Prebuilt `.deb` files may be attached to a release: see [Releases](https://github.com/OlehDzhumyk/linkwatch/releases). To build the package yourself, build the binary (section 2), then:

```sh
packaging/build-deb.sh target/release/linkwatch     # -> target/deb/linkwatch_<version>_<arch>.deb
sudo dpkg -i target/deb/linkwatch_<version>_amd64.deb   # or _arm64.deb
sudo -u linkwatch linkwatch --config /etc/linkwatch/linkwatch.toml check
sudo systemctl start linkwatch
```

### 2. Build from source (static musl or native release)

```sh
cargo build --release --locked
# or static cross-compile without a C toolchain (uses pure-Rust crypto/TLS + rust-lld):
cargo build --release --locked --target aarch64-unknown-linux-musl
```

To develop the Web UI (Node 20+):

```sh
npm ci --ignore-scripts
npm run check     # strict TypeScript typecheck
npm run build     # emits ES modules to src/web/ui/dist/ (committed)
```

Run the same checks as CI (clippy, tests, bindings, UI) on a Linux host or in Docker:

```sh
scripts/ci.sh             # needs Rust with clippy and Node
scripts/ci.sh --docker    # IMAGE=<image with Rust + Node>
```

For manual service install (without `.deb`):

```sh
cp target/release/linkwatch deploy/
cp examples/linkwatch.toml deploy/linkwatch.toml
sudo deploy/install.sh
sudo systemctl start linkwatch
```

> **Dual-interface routing on one subnet:** Running Wi-Fi and Ethernet in the same LAN subnet requires `arp_ignore=1`, `arp_announce=2`, and loose `rp_filter` (configured by `deploy/90-linkwatch.conf` and verified by `linkwatch check`). These ARP and `rp_filter` values apply to all interfaces of the host. See "Kernel settings" in [docs/INSTALL.md](docs/INSTALL.md) for what they change and how to remove them.

---

## CLI Usage

```sh
linkwatch check [--deep]                               # preflight; --deep adds ~6 s of active self-tests
linkwatch calibrate --seconds 60                       # idle baseline of every path -> calibration.json (informational; not yet used by analyze/compare)
linkwatch run --point B1/F2/R3                         # start monitoring loop + Web UI
linkwatch sessions                                     # list recorded sessions
linkwatch analyze /var/lib/linkwatch/<id> --router-log docsis.txt > report.md
linkwatch compare /var/lib/linkwatch/<s1> /var/lib/linkwatch/<s2> > compare.md
```

Default Web UI: `http://127.0.0.1:8080/` (set `[web] listen = "0.0.0.0:8080"` and `token` for LAN access and active probes).

---

## Session Data Layout

`<data_dir>/<session>/`:

```text
meta.json                 session ID, start time, host/host_id, point, fingerprint, full config
samples-YYYYMMDD.jsonl    per-second interface probes & path state
events-YYYYMMDD.jsonl     state/verdict changes, roaming, disconnects, security alerts, heartbeats
wifi-YYYYMMDD.jsonl       station telemetry, channel survey, scans (with security/WPS/PMF IEs)
speed-YYYYMMDD.jsonl      periodic download speed tests
host-YYYYMMDD.jsonl       observer health, UPnP router telemetry, LAN device counts
heartbeat                 atomic crash-recovery timestamp
summary.json              clean shutdown summary
```

Old daily files compress automatically to `.jsonl.gz`.

---

## Documentation

- [**Install and first measurement**](docs/INSTALL.md) — step-by-step guide for a new user.
- [**Features & Architecture**](docs/FEATURES.md) — deep reference for probing, router adapters, advisor rules, CVE engine, site geometry, and every API endpoint.
- [**Adding a UI Language (i18n)**](docs/I18N.md) — 3-step guide to adding new interface languages cleanly.
- [**Roadmap & Planned Features**](docs/ROADMAP.md) — upcoming layout editor, extra adapters, and multi-observer UI compare.
- [**Module Contracts**](docs/CONTRACTS.md) — internal Rust boundaries and invariants.
- [**Failure Scenarios Matrix**](docs/FAILURE-SCENARIOS.md) — covered network, observer, storage, and security edge cases.
- [**Changelog**](CHANGELOG.md) — release history.

See [examples/linkwatch.toml](examples/linkwatch.toml) and [examples/site.toml](examples/site.toml) for fully commented configuration templates.

---

## License

**[PolyForm Shield 1.0.0](LICENSE.md)** (`Required Notice: Copyright (c) 2026 OlehDzhumyk`). Free to use, modify, and share for personal or internal business purposes (preserving notice), excluding competing products or services. Source-available (not OSI open-source).
