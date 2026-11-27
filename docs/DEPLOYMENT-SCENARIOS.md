# Linkwatch Deployment, Discovery & Onboarding Scenarios

> Status: design reference (scoping future `doctor`, discovery, QR pairing, and multi-probe sync work)
> Audience: future engineering agents, maintainers, operators

This document captures how **linkwatch** is installed, discovered, secured, and operated across real home/apartment/field environments, where the current "random DHCP IP + port `:8080` + pasted bearer token + manual `scp`" workflow breaks down, and ten concrete branching scenarios (`D1`–`D10`) to guide implementation without re-inventing the analysis.

---

## 1. Current Baseline & Root Pain Points

What happens today:
1. `linkwatch web` / `linkwatch monitor --web` binds a static host/port (commonly `:8080` on loopback or `0.0.0.0`).
2. Operators SSH into a probe host, look up its transient DHCP IP, copy an auto-generated bearer token, and manually type `http://<ip>:8080/#token=...` or paste the token into a phone/laptop browser.
3. Firewall rules (`ufw`, `firewalld`, macOS firewall), port `8080` collisions, Docker `bridge` isolation, laptop sleep, or `host_allowed()` DNS-rebinding checks fail silently or with opaque browser errors.
4. Multi-probe runs (Ethernet anchor + roaming Wi-Fi laptop) require manual `scp` of `sessions/<id>` folders before running `linkwatch compare`.

Design goals:
- **Zero-guesswork startup:** Never silently collide on `8080`; print an actionable banner (URL, QR code in TTY, mDNS name, firewall hint) and persist the runtime endpoint in a state file.
- **No manual 32-char token typing on phones:** QR pairing with `#token=` hash-fragment auto-consumption + short-lived bootstrap or read-only share tokens where appropriate.
- **Preflight diagnostics (`linkwatch doctor`):** Check capabilities, Wi-Fi power save, firewall, port availability, clock sync, and container network mode *before* a 24-hour soak fails.
- **Safe remote & multi-probe ergonomics:** Explicit proxy/Tailscale host allowlist, SSE unbuffering, and clean session bundle export/pull.

---

## 2. Target Architecture Building Blocks

### 2.1 Port & Bind Strategy
- **Dedicated default port:** Prefer an unregistered high port (e.g. `17840` or `8742`) over `8080` (heavily contested by proxies, dev servers, Torrent WebUIs, and Syncthing/Arr stacks), while still honoring `--port` / `web.port`.
- **Automatic fallback (opt-in / interactive):** When configured port is busy (`EADDRINUSE`), fail cleanly in systemd/daemon mode with the owning process name if inspectable, or optionally bind the next free port (`port + 1..port + 10`) when `--port-auto` is set, writing the bound address to `<data_dir>/runtime.json` (`pid`, `urls`, `mdns`, `started_at`).
- **Bind scope clarity:** Distinguish `127.0.0.1` (local-only, no LAN access), `<lan-ip>` / `0.0.0.0` (LAN UI), and explicit allowed `Host` headers (`web.allowed_hosts`) for reverse proxies / `.local` / Tailscale MagicDNS.

### 2.2 LAN Discovery (mDNS / DNS-SD)
- Advertise `_http._tcp` (and/or `_linkwatch._tcp`) with hostname `<host>.local` or `linkwatch-<short-id>.local` including TXT records (`ver`, `mode=lan|ro`, `path=/`).
- **Fallback always required:** mDNS fails on Android (older OS / OEM ROMs), corporate VPNs, VLAN splits, and routers with Client/AP Isolation enabled. Every mDNS announcement must remain secondary to direct LAN IP + QR + explicit static URL.

### 2.3 QR Pairing & Authentication Flow
- Generate an ASCII/UTF-8 terminal QR code on startup (when attached to a TTY or via `linkwatch web qr`) encoding `http://<lan-ip-or-mdns>:<port>/#token=<bearer>`.
- **Why `#token=` instead of `?token=`:** URL fragments stay client-side; they are not written to HTTP proxy access logs or `Referer` headers. The Web UI reads `location.hash`, stores the token in `localStorage`/`sessionStorage`, and immediately calls `history.replaceState` to strip the fragment from the address bar.
- **Two-tier tokens (future):**
  - `operator`: full live control, speedtests, settings, deletion, raw export.
  - `viewer` / read-only: view `Now`, `Sessions`, `Compare`, and download pre-redacted `support-report` packs without triggering speedtests or reading unredacted MACs/logs.

### 2.4 Preflight (`linkwatch doctor`)
Before multi-hour captures or daemon setup, check:
1. Port bindability + firewall hints (`ufw status`, `firewalld`, macOS PF/ALF).
2. Container network isolation check (`/.dockerenv` or `/proc/1/cgroup` with non-host netns -> warn that Wi-Fi `nl80211`, ARP, and UPnP/SSDP discovery require `--network=host`).
3. Power / sleep inhibition availability (`systemd-inhibit` / `caffeinate`) and Wi-Fi power-save state (`iw dev <iface> get power_save`).
4. Time sync (`timedatectl` / NTP active) so multi-probe `compare` alignment is trustworthy.
5. `CAP_NET_RAW` / `CAP_NET_ADMIN` or ICMP ping `ping_group_range` permissions.

---

## 3. Branching Deployment Scenarios (`D1`–`D10`)

Each scenario defines **Trigger**, **Branching Outcomes**, **Observed Signals**, and **Recommended Behavior**.

### D1. Port Conflict on Startup (`EADDRINUSE`)
- **Trigger:** Host already runs another service on the configured Web UI port (especially `:8080`).
- **Branches:**
  - *D1a (Daemon / systemd unit):* Exit non-zero immediately with clear log (`port 8080 busy; set --port or web.port in config`) so systemd doesn't mask a silent wrong-port bind behind an old bookmark.
  - *D1b (Interactive CLI / ad-hoc probe with `--port-auto`):* Scan `+1..+16`, bind first free port, write `runtime.json`, re-advertise via mDNS TXT/port, and print the actual URL + QR.
  - *D1c (Stale linkwatch instance still bound):* Detect our own `runtime.json` PID before starting; offer/report "linkwatch already running at `<url>`" instead of failing generically.

### D2. Dynamic DHCP IP Drift on Headless Probe
- **Trigger:** Headless mini-PC/SBC reboots or router lease expires; LAN IP changes (`192.168.0.x -> 192.168.0.y`), breaking saved phone bookmarks.
- **Branches:**
  - *D2a (Home router supports mDNS across LAN):* `http://linkwatch.local:<port>/` resolves seamlessly despite IP change; `host_allowed()` must accept `.local` hostnames matching configured name.
  - *D2b (Phone/OS ignores mDNS or IPv6 link-local chosen first):* Operator runs `linkwatch status` over SSH or checks DHCP lease; `status` prints current clickable LAN URLs + regenerated QR.
  - *D2c (Dual-homed Ethernet + Wi-Fi probe):* Probe has two LAN IPs; advertise/prefer the primary wired management IP in QR/banner rather than the temporary Wi-Fi test interface IP.

### D3. Phone Cannot Reach Probe on Same SSID
- **Trigger:** Local `curl http://127.0.0.1:<port>` works on the probe, but the phone browser times out (`ERR_CONNECTION_TIMED_OUT`).
- **Branches:**
  - *D3a (Host firewall blocks inbound TCP):* `ufw` / `firewalld` drops packets silently. *Signal:* packets never reach linkwatch HTTP handler. *Fix:* `linkwatch doctor` detects active firewall without rule for configured port and prints exact allow command (`sudo ufw allow <port>/tcp`).
  - *D3b (Bound to `127.0.0.1` instead of LAN IP / `0.0.0.0`):* Listening socket only bound loopback. *Fix:* startup banner prominently labels `LOCAL ONLY` vs `LAN ACCESSIBLE`.
  - *D3c (Router AP / Client Isolation or Guest VLAN):* Wi-Fi isolates wireless stations from wired/other wireless hosts. *Signal:* probe cannot ARP/ping phone IP even on same subnet. *Fix:* surface diagnostic hint; suggest wired Ethernet subnet or temporary hotspot / reverse SSH / Tailscale.
  - *D3d (Phone active VPN without LAN bypass):* Corporate/commercial VPN tunnels RFC1918 traffic away from local router. *Fix:* documented troubleshooting note on Web UI / CLI connect sheet.

### D4. Friction & Risk During Token Onboarding on Mobile
- **Trigger:** First-time connection from a phone or tablet without SSH access.
- **Branches:**
  - *D4a (QR code scan with `#token=`):* Camera opens URL, Web UI consumes fragment via `history.replaceState`, persists token, connects SSE cleanly.
  - *D4b (LAN has no HTTPS, browser treats IP origin as insecure context):* Clipboard API (`navigator.clipboard.writeText`) or WebCrypto/Notifications behave differently on `http://<lan-ip>`. *Fix:* UI always provides a fallback selectable `<textarea>` / dialog when `navigator.clipboard` rejects in non-secure HTTP contexts (note: `127.0.0.1` / `localhost` is exempt, LAN IP is not).
  - *D4c (User scans QR on shared/guest device):* Full operator token grants router reboot/speedtest triggers. *Fix:* future split between `qr --role viewer` (read-only) and `qr --role operator`.

### D5. Reverse Proxy, Custom Hostname, or Tailscale Access
- **Trigger:** Operator puts linkwatch behind `caddy`, `nginx`, or `tailscale serve` for HTTPS or remote apartment monitoring.
- **Branches:**
  - *D5a (`Host` header rejected by DNS-rebinding guard):* `host_allowed()` sees `monitor.home.arpa` or `node.tailnet.ts.net` and returns `403`. *Fix:* configurable `web.allowed_hosts` plus automatic recognition of `.local` / Tailscale hosts when explicitly enabled.
  - *D5b (Proxy buffers Server-Sent Events):* `/api/stream` appears frozen for 30–60s then bursts or drops. *Fix:* always send `X-Accel-Buffering: no`, `Cache-Control: no-cache`, and document proxy websocket/SSE timeouts.
  - *D5c (TLS terminated upstream while backend checks origin/CSRF):* Keep `Origin` checks compatible with `X-Forwarded-Proto` + configured external origin.

### D6. Docker Container Deployment (`bridge` vs `host`)
- **Trigger:** User installs via Docker to avoid host dependency setup.
- **Branches:**
  - *D6a (Default `bridge` network `-p 8080:8080`):* Container sees only virtual `eth0` (`172.17.0.x`). *Failure:* Wi-Fi `nl80211` scan returns nothing, router gateway looks like `172.17.0.1`, UPnP/SSDP multicast does not traverse bridge, and `127.0.0.1` bind inside container is unreachable even with `-p`.
  - *D6b (`--network=host --cap-add=NET_ADMIN --cap-add=NET_RAW`):* Full visibility of host Wi-Fi, Ethernet, ARP, and UPnP.
  - *Mitigation:* Startup detects virtual container bridge gateway + missing `nl80211` and emits a clear warning banner instead of misleadingly blaming the user's ISP/router.

### D7. Roaming Laptop Probe Enters Sleep or Wi-Fi Power-Save
- **Trigger:** Operator runs a 4-hour capture on a portable laptop, closes the lid or leaves it on battery.
- **Branches:**
  - *D7a (OS suspends host):* Sampling pauses for minutes/hours; wake causes burst of stale socket errors and NTP jump. *Signal:* `clock_jumps` + `gaps` in `SessionView`. *Fix:* invoke `systemd-inhibit --what=sleep:idle` / `caffeinate -dims` under an opt-in flag (`--keep-awake`) and mark sleep gaps explicitly as observer gaps, never network outages.
  - *D7b (NIC enters aggressive power-save on battery):* Gateway ping jitter jumps `2ms -> 150ms` periodically while idle. *Fix:* `linkwatch doctor` checks `iw ... get power_save` and warns that battery mode skews RF latency baselines.

### D8. Two-Node Lab Collection (`anchor` + `roaming laptop`)
- **Trigger:** Stationary Ethernet node runs continuously while a Wi-Fi laptop moves across rooms (`K`, `R1..R6`, `H`), followed by `compare` and `support-report`.
- **Branches:**
  - *D8a (Unaligned wall clocks):* Roaming laptop clock drifts 8s ahead of anchor; simultaneous drops fail correlation inside `compare` default tolerance. *Fix:* record NTP sync boolean in `SessionMeta` (`clock_synced`), show clear warning in Compare + Support Pack readiness gate.
  - *D8b (Manual `scp` version/path mistakes):* Copying wrong subdirectory or overwriting live session. *Fix:* HTTP `GET /api/sessions/<id>/bundle.tar.gz` (or CLI `linkwatch bundle pull <url> <session>`) fetches validated immutable/snapshot bundles cleanly.
  - *D8c (Missing point/room metadata):* Operator forgets which session was run in which room. *Fix:* interactive `linkwatch monitor --point R2` prompt or Web UI session note/point tagger written to `meta.json`.

### D9. Sharing Findings with Untrusted / External Stakeholders (Landlord, ISP, Support Forum)
- **Trigger:** Operator sends evidence outside the household (`Support`, landlord, neighbor, GitHub issue).
- **Branches:**
  - *D9a (Raw Web UI screenshot or unfiltered `scp` folder):* Leaks LAN topology, device MACs, hostnames, SSIDs, or tokens.
  - *D9b (`support-report` redaction pipeline):* `Standard` (default for ISP/Landlord/external) strips MACs, BSSIDs, hostnames, local RFC1918 IPs -> placeholders, keeping RF/RTT/packet-loss proof intact (`Strict` strips SSID/ISP name/timestamps too).

### D10. In-Place Upgrade & Config Schema Evolution
- **Trigger:** User upgrades binary/`.deb` on a running probe after schema or Web UI changes.
- **Branches:**
  - *D10a (Stale browser tab caches old ES module with new API response):* Browser fails or renders old layout. *Fix:* serve static assets with explicit `Cache-Control: no-cache` + ETag/content hash or version query on module imports.
  - *D10b (Old `linkwatch.toml` lacks newly introduced optional fields):* Must deserialize cleanly via `#[serde(default)]` and never crash service startup after `.deb` upgrade.

---

## 4. Phased Implementation Backlog (Prioritized)

| Priority | Item | Addresses Scenarios |
|---|---|---|
| **P0** | Keep Web UI HTTP-context clipboard fallback (`textarea` select) + `#token=` fragment stripping (never `?token=`) | D4a, D4b |
| **P0** | Strict `#[serde(default)]` backwards compatibility on `linkwatch.toml` & session JSON + `Cache-Control: no-cache` on ES modules | D10a, D10b |
| **P1** | Non-conflicting default port (e.g. `17840`) + clear `EADDRINUSE` / owning-PID error + `<data_dir>/runtime.json` | D1a, D1c |
| **P1** | `linkwatch doctor` preflight (Docker netns check, firewall rules, NTP sync, Wi-Fi power_save, `CAP_NET_RAW`) | D3a, D6, D7b, D8a |
| **P1** | Startup TTY QR code (`#token=`) + multi-interface URL banner (`LOCAL` vs `LAN`) | D2b, D2c, D4a |
| **P2** | Built-in mDNS/DNS-SD announcer (`_linkwatch._tcp` / `.local`) + `web.allowed_hosts` proxy config | D2a, D5a, D5b |
| **P2** | `GET /api/sessions/<id>/bundle` + `linkwatch bundle pull` for zero-`scp` multi-probe workflows | D8b |
| **P3** | Read-only `viewer` token tier + `--keep-awake` sleep inhibitor | D4c, D7a, D9 |
