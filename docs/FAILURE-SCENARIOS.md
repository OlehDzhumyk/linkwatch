# Failure scenarios

What can go wrong during a multi-night measurement, what linkwatch should do, and where it
stands today. Status: **tested** (automated test exists), **handled** (code path exists, no
automated test), **partial**, **missing**. Updated as fixes land.

Two goals for every row:
1. the monitor keeps running and keeps writing usable data;
2. the report does not blame the network for something the observer did, and vice versa.

## A. The network under test (must be detected and attributed correctly)

| ID | Scenario | Expected behaviour | Status |
|---|---|---|---|
| A1 | Wi-Fi drops 1–2 s ("freezes for a moment") | each lost probe in samples; micro-drop in report; no state flapping | tested (classify, analyze) |
| A2 | Wi-Fi down for minutes, cable fine | `wifi_problem` verdict and episode cause | tested |
| A3 | Router reboots | both paths LinkDown/NoIp/LanDown, DHCP renew, `router_problem`; recovery recorded | tested (`verdict`) |
| A4 | DOCSIS line loss (T3/T4 timeouts, resync) | both paths fail beyond router, `line_problem`; router log matched | tested (cause), handled (log match) |
| A5 | ISP core/internet beyond first hop down | `internet_problem` | tested (verdict) |
| A6 | DNS only broken | `dns` verdict (2+ failed queries) | tested (verdict) |
| A7 | Router ignores or rate-limits ICMP | path counts as up when TCP/internet answer | tested |
| A8 | Evening congestion (high RTT, low speed, no loss) | Degraded state; hourly profile; evening speed finding | tested (degraded), handled (report) |
| A9 | Bufferbloat: latency rises only under load | RTT during speed test recorded, excluded from Degraded, reported; saturation by one host can induce RTT spikes/stalls on sibling observers and load-coincident micro-drops on the testing host, so episodes during `speedtest_active` must be distinguished from unprovoked idle line outages | partial (RTT under load tested; episode separation in `support_report` prerequisites) |
| A10 | Client roams to an extender/booster with the same SSID | `roam` event, context on episodes, roam count finding | tested (analyze) |
| A11 | Router changes channel (auto channel, DFS radar on 5 GHz) | `channel_change` event (polling + nl80211 multicast) | tested (analyze) |
| A12 | Co-channel interference from neighbours | scan shows same-channel networks; busy %; Wi-Fi retry rate delta | tested (retry rate in analyze) |
| A13 | AP deauthenticates the client (reason code) | `wifi_disconnect` event with reason and initiator (`by_ap`) | tested (parser + analyze) |
| A14 | DHCP lease change / IP change mid-run | `link_change` event, probes follow new address | handled |
| A15 | Gateway MAC changes (router swap, ARP spoofing) | `security` event (`gateway_mac_change`) | tested (security) |
| A16 | Second DHCP server / rogue gateway | `security` event (`rogue_gateway`) | tested (security) |
| A17 | 2.4 GHz vs 5 GHz behave differently | per-band statistics in `analyze`; multi-adapter context; `compare` | tested (analyze, compare) |
| A18 | Problem only in some rooms | `compare` with network fingerprint matching & ±tol time alignment | tested (compare) |

## B. The observer (must not be mistaken for the network)

| ID | Scenario | Expected behaviour | Status |
|---|---|---|---|
| B1 | Wi-Fi driver/firmware reset on the observer | `host` stream `driver_reset` alert (`ifindex` change), observer origin | tested (host) |
| B2 | Power-save of the observer's Wi-Fi adds latency | `power_save` read via nl80211, `HostAlert`, `check` & UI & report warning | tested (wifi, host, analyze) |
| B3 | Raspberry Pi undervoltage / thermal throttling | `host` stream + `HostAlert`, observer incident excluded from network totals | tested (host, analyze) |
| B4 | CPU starvation: tick loop late | `overrun` flag; observer origin when majority overrun; stalled loop stops watchdog | tested (analyze) |
| B5 | Out of memory | `host` `low_memory` alert + systemd `MemoryMax`, restart, gap recorded | tested (host) |
| B6 | Host suspends | `suspend_gap` event, episodes attributed to observer | tested (analyze) |
| B7 | Power cut / hard reboot | next start records `gap_s` from heartbeat and `prev_boot_id` | handled; store recovery tested |
| B8 | Observer's own speed test saturates the link | samples flagged `speedtest_active`, excluded from Degraded, context in episodes; speedtest-coincident timeouts must not inflate unprovoked idle line-outage counts | partial (`speedtest_active` flagged; episode separation in `support_report` prerequisites) |
| B9 | Wi-Fi scan by the observer pauses traffic (off-channel) | dedicated `wifi_scan` thread, `scan_active` flag, excluded from Degraded & attributed to observer | tested (analyze) |
| B10 | Observer moved or cable unplugged by someone | `link_change`; wired no-link time reported separately; Wi-Fi disassociation is outage | tested (analyze) |
| B11 | Both interfaces in one subnet: ARP flux mixes paths | sysctl set by package; `check` verifies; gateway MAC cross-iface check | handled (sysctl/check, security) |
| B12 | Observer clock not synced / steps | clock sync source (`timesyncd`/`chrony`/`ntpd`) in meta + `host` + `compare` warnings | handled (`clock_jump`, `compare` tested) |

## C. Measurement artefacts (false positives / false negatives)

| ID | Scenario | Expected behaviour | Status |
|---|---|---|---|
| C1 | One internet target down (e.g. a public DNS anycast node) | internet down only if all targets fail | tested |
| C2 | ICMP to the router deprioritised under load | not an outage when internet answers | tested |
| C3 | Late replies after timeout | counted as loss, never matched to the next probe | tested (icmp) |
| C4 | Probe interval longer than a drop (light profile) | report states time resolution per session (`tick_s` from meta) | tested (analyze) |
| C5 | Many probes per second disturb a weak link | probe rate per profile; bytes counted in rx/tx deltas | handled |
| C6 | ISP first hop changes (re-routing) | rediscovery, note event | handled |
| C7 | DNS cached by a local stub resolver | query servers directly, not 127.0.0.53 | handled |
| C8 | Speed test server slow or down | fallback URL, error recorded, not an outage | tested (speed) |

## D. Storage and data

| ID | Scenario | Expected behaviour | Status |
|---|---|---|---|
| D1 | Crash in the middle of a line | torn tail truncated on open, seq continues | tested |
| D2 | Crash during gzip of an old day | duplicate files resolved on open; reader skips duplicate seqs | tested |
| D3 | Disk nearly full | events only; then stop writing; event on mode change | tested (store) |
| D4 | Queue full (writer slow) | producers never block; drops counted and reported | tested |
| D5 | Second instance on the same data dir | lock refuses with a clear error | tested |
| D6 | SD card wear (Raspberry Pi) | batched writes, fsync interval | partial (no write-volume estimate in docs) |
| D7 | Day boundary, clock goes backwards | no backwards rotation | tested |
| D8 | Schema change in a later version | `v` field; reader keeps old versions readable | partial (only v1 exists) |

## E. Process and operations

| ID | Scenario | Expected behaviour | Status |
|---|---|---|---|
| E1 | Panic in a task | supervisor restarts the task, `task_restart` event | handled (no test) |
| E2 | Tick loop hangs | watchdog not fed → systemd restarts | handled (no test) |
| E3 | Web port in use | monitor continues without UI | handled |
| E4 | Bad config | refuse to start with the exact field | tested |
| E5 | Upgrade of the package during a session | same session continues after restart | handled |
| E6 | Interface renamed / USB adapter re-plugged | link reads `present=false`, recovers by name | handled |

## F. Web UI and security

| ID | Scenario | Expected behaviour | Status |
|---|---|---|---|
| F1 | UI reachable by everyone on the LAN | read-only; local-only default (127.0.0.1), optional `web.token`, Host check & CSP | tested (web) |
| F2 | Hostile SSID text (`<script>` etc.) | rendered as text only (`textContent`, never `innerHTML`) | handled (textContent rule) |
| F3 | Path traversal via session id | ids validated against `[A-Za-z0-9_.-]` and existing `meta.json` | tested (web) |
| F4 | Many SSE clients / slow clients | bounded, slow clients dropped | handled |
| F5 | SSE live stream disconnects or stalls | Header connection dot switches to reconnecting with exponential backoff; stale-data badge shown after 2× refresh interval (60 s) without fresh data | handled |
| F6 | Report / compare / history API fails (500 / 401 / 429) | Inline error banner with retry button or clear auth/rate-limit message; UI never stays stuck on loading | handled |
| F7 | Narrow phone screen (390 px) & live EN ↔ UK language switching | Zero horizontal overflow (`scrollWidth === innerWidth`), dynamic panels & open selections re-render in place without losing state | handled |

## How to test what is not tested yet

1. **Network faults without touching the real network:** network namespaces with veth pairs and
   `tc netem` (loss, delay, link down), a dnsmasq-like DHCP responder, and a fake "router" namespace.
   Ubuntu restricts unprivileged user namespaces by default, so this harness runs with sudo or in a
   VM/container in CI.
2. **Observer faults:** `kill -9`, `kill -STOP` (hang → watchdog), memory limit, a slow disk
   (`dm-delay` or a FUSE throttle), clock steps with `faketime`-style injection in unit tests
   (the store already accepts an injected clock).
3. **Long run:** a 72-hour soak on the lab box with the detailed profile, checking memory, file
   sizes, and that the report agrees with the router's own log.
4. **Fuzzing:** netlink TLV parser, HTTP response parser, DNS reply parser, JSONL reader.
