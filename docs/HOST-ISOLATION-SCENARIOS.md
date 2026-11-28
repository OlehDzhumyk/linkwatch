# Host Isolation, Calibration & Self-Check Scenarios (`H1`–`H24`)

> Status: design reference (scoping future `check --deep`, `calibrate`, passive sentinels, and Observer Trust Score)
> Audience: future engineering agents, maintainers, operators

This document extends the failure scenarios (`B1`–`B12` in [FAILURE-SCENARIOS.md](FAILURE-SCENARIOS.md)) to cover subtle host, adapter, OS, cable, and timing artefacts that cause an observer box or laptop to look like a Wi-Fi, router, or ISP failure — or that skew `compare`, `advice`, and `support_report`.

---

## 1. Goal & Core Principle

Every diagnostic verdict must prove two things before blaming the network:
1. **The fault is not inside the measuring host, its USB/PCIe NIC, OS scheduler, background traffic, VPN, or patch cable.**
2. **When comparing two rooms/devices, hardware bias (`ΔRSSI`, `ΔRTT`, clock drift) is bounded or calibrated.**

Instead of relying solely on coarse 10-second CPU averages or static boot-time checks, the monitor combines:
- Deep preflight verification (`linkwatch check --deep`)
- Optional baseline & paired co-located calibration (`linkwatch calibrate`)
- Zero-overhead per-second passive sentinels
- A per-session **Observer Trust Score** (`Clean | Caution | Polluted`) fed directly into `analyze`, `advice`, `compare`, and `support_report`.

---

## 2. Realistic Host & Observer Scenarios (`H1`–`H24`)

### H1. Micro-Stalls from Scheduler / IO Contention Hidden in 10 s Averages
- **What happens:** A 1.5-second freeze in host scheduling (log rotation, background `apt`, swap stall) misses a single 1 s probe deadline, yet 10 s `cpu_pct` stays under `20%`.
- **Signals:**
  - Wall-vs-`mono_ns` wakeup drift inside the probe tick loop (`tick_slip_ms`).
  - Linux PSI (`/proc/pressure/cpu`, `/proc/pressure/io` `some avg10`).
  - Optional loopback `127.0.0.1` ICMP/UDP echo sanity check during `--deep` self-test.
- **Mapping:** Elevated `tick_slip_ms` -> mark sample `overrun = true` -> `IncidentOrigin::Observer`.

### H2. Silent Wi-Fi Driver / Firmware Reset Keeping Same `ifindex`
- **What happens:** Modern Wi-Fi drivers (`iwlwifi`, `mt7921e`, `rtw89`) reset MAC/firmware without removing the netdev (`ifindex` stays identical, so current `ifindex`-change detector in `HostMonitor` misses it).
- **Signals:**
  - Sudden drop of `/sys/class/net/<if>/statistics/rx_packets` or nl80211 `inactive_ms` jump without an AP deauth frame (`by_ap = None`, `timed_out = false`).
  - `/sys/class/net/<if>/carrier_changes` increment without AP-initiated disconnect.
- **Mapping:** Emit `HostAlert { alert: "driver_reset_soft", detail }`; classify simultaneous wireless drop as `IncidentOrigin::Observer`.

### H3. USB Wi-Fi / Ethernet Adapter Autosuspend or Bus Reset
- **What happens:** USB-C dock or USB Wi-Fi dongle enters USB `auto` suspend or suffers transient brownout on a shared port, dropping carrier for 3–8 s.
- **Signals:**
  - `/sys/class/net/<if>/device/../power/control == "auto"` (check at startup + `check --deep`).
  - `carrier_changes` delta + USB `power/runtime_status`.
- **Mapping:** Preflight `Warn` + fix (`usbcore.autosuspend` / udev rule); attribute USB carrier bounce to `Observer`.

### H4. Host's Own Background Traffic Saturating the Link (`self_traffic_active`)
- **What happens:** OS updates, cloud backup, or large downloads run *on the monitor host itself* (outside `linkwatch`'s built-in speedtest), causing latency spikes or short drops that look like idle ISP bufferbloat or Wi-Fi failure.
- **Signals:**
  - Compare `rx_delta + tx_delta` (bytes/s on the probe interface) against sustained bulk thresholds (e.g., `> 10 Mbit/s` for `>= 3 s`), tagged `self_traffic_active = true` alongside existing `speedtest_active`.
- **Mapping:** Suppress unprovoked ISP/router outage claims during `self_traffic_active`; feed `advice.rs` ("heavy traffic on monitor host itself") and exclude from idle baseline RTT.

### H5. Cross-Device Antenna / Adapter Bias in Multi-Room `Compare`
- **What happens:** Stationary anchor (internal PCB antenna or USB dongle) reads `−58 dBm` at a spot while a laptop reads `−66 dBm` right beside it; comparing Bedroom 2 (`laptop`) vs Kitchen (`anchor`) conflates room attenuation with hardware sensitivity difference.
- **Signals:**
  - Co-located calibration session (`linkwatch calibrate --pair`): both devices sit at the **same point** for 2–5 minutes, recording `delta_signal_dbm`, `delta_gw_rtt_ms`, and `delta_clock_ms`.
- **Mapping:** `calibration.json` offsets shown explicitly in `compare` & `support_report` (*"hardware offset ±X dB compensated"*).

### H6. External OS / NetworkManager Background Scan While Internal Scan Is Off
- **What happens:** User disables `linkwatch` active scans (`scan_s = 0`) to avoid disruption, but `NetworkManager` / `wpa_supplicant` still runs off-channel scans every 2–5 minutes causing 1–3 s Wi-Fi spikes.
- **Signals:**
  - Listen continuously to `nl80211` `NL80211_MCGRP_SCAN` multicast events (`CMD_TRIGGER_SCAN` / `CMD_NEW_SCAN_RESULTS`) regardless of who triggered the scan.
- **Mapping:** Flag sample `scan_active = true` whenever *any* process triggers an off-channel scan on that radio.

### H7. Active VPN, Split Tunnel, or Policy Routing Distorting RTT / DNS / `isp_hop`
- **What happens:** Tailscale exit node, WireGuard, or corporate VPN is enabled on a roaming laptop probe; ICMP to `isp_hop` routes differently from TCP/DNS, inflating `net_rtt` and hiding real gateway drops.
- **Signals:**
  - Inspect routing tables / active virtual interfaces (`tun*`, `wg*`, `tailscale*`, `ppp*`, `utun*`) + check `SO_BINDTODEVICE` / source-IP egress vs `ip route get 1.1.1.1`.
- **Mapping:** `check --deep` flags active tunnel interfaces with clear warning; downgrade `ReadinessLevel` for `Isp` tickets if probes traverse a VPN.

### H8. Per-Interface `rp_filter` / ARP Flux Asymmetry on Dual-Path Probes
- **What happens:** `/proc/sys/net/ipv4/conf/all/rp_filter` is `2`, but `/proc/sys/net/ipv4/conf/wlo1/rp_filter` is `1` (Linux uses `max(all, dev)`!). Reverse-path filtering silently drops replies on the secondary Wi-Fi interface when both share a subnet.
- **Signals:**
  - Read **both** `all/*` and per-interface `<if>/{rp_filter,arp_ignore,arp_announce}` in `check`.
  - Cross-path self-test sends simultaneous probes out `eth0` and `wlo1` and verifies `/sys/class/net/<if>/statistics/rx_packets` increments on **each** matching interface (proving traffic did not silently route out only one interface).
- **Mapping:** Catch `B11` before running a 24 h dual-path test instead of discovering later that "Wi-Fi never saw traffic".

### H9. Faulty Ethernet Patch Cable, Negotiation Drop, or NIC CRC Errors
- **What happens:** The "reference Ethernet anchor" suffers micro-drops because of a loose RJ45 latch, corroded wall jack, or `1000 -> 100 Half-Duplex` renegotiation, falsely turning Wi-Fi-only issues or healthy lines into `RouterProblem` / `WiredProblem`.
- **Signals:**
  - `/sys/class/net/<if>/speed`, `/sys/class/net/<if>/duplex`.
  - Deltas of `rx_crc_errors`, `rx_frame_errors`, `tx_aborted_errors`, `rx_dropped` per minute.
- **Mapping:** If `rx_crc_errors > 0` or duplex != `full` or speed drops during outages -> emit `wired_cable_or_nic_error` in `advice.rs` and attribute to physical patch cable / NIC rather than router WAN or ISP.

### H10. Running NTP Daemon Directory Exists While Kernel Clock Is Unsynced (`STA_UNSYNC`)
- **What happens:** `host::clock_sync_source()` sees `/run/chrony` directory exists and reports `clock_synced = true`, even though `chronyd` lost upstream NTP reachability (e.g. during ISP outage or firewall block) and drifted 12 seconds.
- **Signals:**
  - Call safe `adjtimex` / `ntp_adjtime` equivalent (or parse `/run/chrony` + sysfs / `timedatectl` status) to check kernel `STA_UNSYNC` bit and `maxerror_us`.
  - Passive cross-check in `compare`: compute time offset `dt` across co-located shared outages when clock trust is `Uncertain`.
- **Mapping:** Accurate `clock_synced` truthfulness in `SessionMeta` + automatic offset warning in `compare` / `support_report`.

### H11. Slow Storage `fsync` Blocking or Memory Swap Thrashing
- **What happens:** Cheap/aging SD card on SBC stalls `fsync` for 2–4 s during heavy logs or memory swaps, delaying async tasks or dropping store queue records (`DroppedRecords`).
- **Signals:**
  - Writer `fsync` duration histogram (warn when `fsync_ms > 500 ms`), `/proc/vmstat` `pgmajfault` delta, `/proc/pressure/io`.
- **Mapping:** Distinct `host_io_stall` note vs network outage; recommend `storage.compress_old` / faster media.

### H12. Power Cable Unplugged / Laptop Switching Power Profiles Mid-Run
- **What happens:** Someone unplugs a laptop probe; GNOME/TLP/power-profiles-daemon immediately enables `wifi.powersave = 3`, ASPM PCIe sleep, and CPU frequency capping mid-session.
- **Signals:**
  - Poll `/sys/class/power_supply/{AC,ACAD,ADP*}/online` alongside `power_save` changes.
- **Mapping:** Emit `EventKind::HostAlert { alert: "ac_power_lost", ... }` correlated with `power_save` activation so sudden overnight latency jumps are explained cleanly.

### H13. Two Network Managers on One Interface
- **What happens:** `NetworkManager`, `systemd-networkd`, `dhcpcd` or `connman` run together. Each re-applies routes or renews DHCP on its own schedule and causes 2–5 s gaps.
- **Signals:** process names in `/proc/*/comm`.
- **Mapping:** `check` warns `network managers` when two or more managers run (`dhclient` started by NetworkManager is not a conflict). **Implemented.**

### H14. Local DNS Resolvers, Proxies and DNS Interception
- **What happens:** `systemd-resolved`, `dnsmasq`, `AdGuardHome`, `Pi-hole`, `dnscrypt-proxy` or a DoH/DoT client answer from a local cache or redirect port 53 with `nftables`. A slow or broken local resolver looks like `DnsDown`.
- **Signals:** `/etc/resolv.conf` points to `127.0.0.53` / `127.0.0.1`; listener on `:53` in `/proc/net/udp`; `nat` rules on port 53.
- **Mapping:** `check` item `dns resolver` warns when resolv.conf has only a local resolver and no upstream list (no systemd-resolved upstream file, no `[targets] dns_servers`). **Implemented.** Future: analyzer separates "local resolver failed" from "upstream DNS failed" when `[targets] dns_servers` are external.

### H15. Host Firewall, `nf_conntrack` and Container Networks
- **What happens:** `Docker`, `Podman`, `libvirt`, `ufw`/`nftables` or `fail2ban` add tables, policy routes (`ip rule`) and NAT. A full `nf_conntrack` table drops new flows silently inside the host kernel.
- **Signals:** `/proc/sys/net/netfilter/nf_conntrack_{count,max}`; bridges `docker*`, `br-*`, `virbr*`, `veth*` in `/sys/class/net`.
- **Mapping:** `check` item `conntrack`: Warn at ≥ 70 %, Fail at ≥ 90 %, lists container bridges. **Implemented.** Future: sample conntrack fill in `HostSample`.

### H16. Packet-Rate Storms from Background Programs
- **What happens:** torrent/DHT, `Syncthing`, `Nextcloud`, `unattended-upgrades`, `snapd` or CI runners send thousands of small packets per second. The byte rate stays at 2–3 Mbit/s (below the H4 limit), but Wi-Fi airtime and conntrack fill up.
- **Signals:** `rx_packets + tx_packets` delta per tick (PPS) next to the byte delta.
- **Mapping:** `Sample.pkt_delta` (rx+tx packets per tick); the analyzer treats ≥ 2000 packets/s (`Opts::self_traffic_pps`) like the H4 byte limit. **Implemented.**

### H17. Bluetooth on a Combo Wi-Fi + BT Card
- **What happens:** On 2.4 GHz, Wi-Fi and Bluetooth share one antenna. An active BT scan or headset adds 50–150 ms RTT spikes.
- **Signals:** `/sys/class/rfkill/*/{type,soft,hard}`; Wi-Fi frequency < 3000 MHz.
- **Mapping:** `check` warns `bluetooth` when BT is on and Wi-Fi uses 2.4 GHz. **Implemented.**

### H18. Wrong Regulatory Domain (`country 00`) and DFS Channels
- **What happens:** Without a country code, the driver limits TX power and forbids active transmission on some 5 GHz channels. The client cannot reach the router well even with a good RSSI.
- **Signals:** `NL80211_CMD_GET_REG` (`alpha2 == "00"`); TX power in the station info.
- **Mapping:** `check` item `wifi country <if>` (`CMD_GET_REG`, per wiphy for self-managed drivers) warns on `00`. **Implemented.**

### H19. MAC Address Randomization
- **What happens:** NetworkManager `cloned-mac-address = random/stable` changes the MAC. The router then resets DHCP/ARP state and counts extra devices.
- **Signals:** `/sys/class/net/<if>/addr_assign_type == 1`.
- **Mapping:** `check` warns `mac <if>`. **Implemented.**

### H20. PCIe ASPM, Runtime PM, Ethernet EEE
- **What happens:** Even with `iw power_save off`, PCIe link power states (`pcie_aspm`), runtime PM (`device/power/control = auto`), driver sleep states or Energy-Efficient Ethernet (802.3az) add jitter and micro-drops.
- **Signals:** `/sys/class/net/<if>/device/power/control`, `/sys/module/pcie_aspm/parameters/policy`; EEE needs the `ethtool` ioctl.
- **Mapping:** `check` item `bus power <if>` warns on `auto` (USB and PCIe) and shows the ASPM policy. **Implemented** (EEE: future).

### H21. Small MTU / Path-MTU Black Hole, Broken IPv6, Equal Route Metrics
- **What happens:** Small ICMP probes pass, but large TCP/DNS packets are lost. Two default routes with the same metric let the kernel move traffic between interfaces during a test.
- **Signals:** `/sys/class/net/<if>/mtu`; default routes with equal metric in `/proc/net/route`; optional DF ping with 1472 bytes in `check --deep`.
- **Mapping:** `check` warns `mtu <if>` when MTU < 1500 and `default routes` when two default routes have the same metric. **Implemented** (DF probe: future).

### H22. Client Background Scan / Aggressive Roaming
- **What happens:** `wpa_supplicant` `bgscan` or `iwd` roaming makes the client jump between 2.4 and 5 GHz below about −65 dBm. It looks like an unstable Wi-Fi.
- **Signals:** nl80211 roam events with the same SSID and no AP deauth; `bgscan` in the `wpa_supplicant` config.
- **Mapping:** already partly visible as roams; future: tag client-initiated roams as `Observer`.

### H23. Software `rfkill`, Power Tools and Memory Limits
- **What happens:** A soft `rfkill` (airplane mode, `tlp`) turns the radio off; `systemd-oomd` or a tight `MemoryMax` kills or stalls the monitor.
- **Signals:** `/sys/class/rfkill/*/soft`; `HostAlert low_memory`; cgroup `memory.events`.
- **Mapping:** `check` fails `rfkill wlan` when the Wi-Fi radio is blocked. **Implemented.**

### H24. USB 3.0 Radio Noise near the 2.4 GHz Antenna
- **What happens:** A USB 3.0 disk or hub next to the Wi-Fi antenna raises the 2.4 GHz noise floor by 10–20 dB.
- **Signals:** survey noise (`NL80211_SURVEY_INFO_NOISE`) higher than on other channels; USB 3 devices in `/sys/bus/usb/devices/*/speed == 5000`.
- **Mapping:** future: note in `check` when a USB 3 device is present and Wi-Fi uses 2.4 GHz.

---

## 3. Four Verification, Self-Test & Calibration Mechanisms

### 3.1 `linkwatch check --deep` (10 s Active Preflight Self-Test)
Runs existing `check` **plus** active sanity proofs:
1. **Loopback RTT baseline (5 s):** Ping/UDP `127.0.0.1` @ 10 Hz -> verify host scheduler p99 jitter `< 2 ms`.
2. **Per-interface independence proof:** Probe gateway simultaneously via `eth0` and `wlo1` and confirm *both* RX packet counters advance cleanly + check per-iface `max(all, dev).rp_filter`.
3. **Cable/NIC physical check:** Verify `duplex == full`, `speed >= 1000` (if gigabit capable), `0` `rx_crc_errors`.
4. **USB power check:** Warn if active NIC sits behind USB `power/control = auto`.
5. **VPN/Tunnel audit:** Detect active `tun`/`wg`/`tailscale` interfaces bypassing physical path binding.
6. **True kernel clock lock check:** Verify kernel `STA_UNSYNC == 0` (not merely process presence).

### 3.2 `linkwatch calibrate` (Baseline & Dual-Probe Bias Removal)
- **Single-node (`linkwatch calibrate`):** 60-second idle self-noise baseline + short controlled 5-second traffic burst -> records host wakeup jitter, idle NIC error rate, and confirms `speedtest_active` vs `idle` isolation works on that hardware.
- **Dual-probe co-located (`linkwatch calibrate --with <url-or-session>`):** Both monitors placed together at `K` for 3–5 minutes compute empirical `ΔRSSI` (dB antenna offset), `ΔRTT` (ms), and true clock skew -> written to `<data_dir>/calibration.json` and optionally factored into `compare` and `support_report`.

### 3.3 Passive Continuous Sentinels (Low-Overhead Inside `monitor` Loop)
| Sentinel | Cost | Feeds Into |
|---|---|---|
| `mono_ns` tick-slip (`actual_dt - tick_ms`) | ~0 CPU | `Sample.overrun` -> `Observer` attribution |
| External `nl80211` scan multicast listener (`CMD_TRIGGER_SCAN`) | event-driven | `Sample.scan_active` -> `Observer` attribution |
| Self background traffic (`rx_delta + tx_delta > 10 Mbps` w/o speedtest) | math on existing counters | `Sample.self_traffic_active` -> excludes from idle faults |
| NIC physical counters (`rx_crc_errors`, `carrier_changes`, `speed`/`duplex`) | 10 s sysfs read | `HostAlert` -> blames cable/NIC instead of router |
| `AC online` state + kernel `STA_UNSYNC` | 10 s proc/sys read | `HostSample` + session trustworthiness |

### 3.4 Structured Observer Trust Score
Each analyzed session produces an explicit **Observer Trust Score**:
- `Clean`: `0` thermal/undervolt alerts, `< 1%` tick-slip overrun, `power_save = off` (on Wi-Fi), kernel NTP locked, `0` NIC CRC/cable errors, `0` VPN hijack.
- `Caution`: short external scan or brief host traffic spikes (`self_traffic_active`), minor NTP gap, or single AC transition (incidents at those instants excluded/annotated, rest of run valid).
- `Polluted`: sustained `power_save = on`, frequent CPU/IO overruns, NIC CRC/half-duplex fault, or unsynced clocks throughout run -> downgrades `SupportPack` Readiness (`Low`), marks affected `AdviceItem` warnings prominent, and flags `compare` alignment.

---

## 4. Phased Implementation Backlog (Prioritized)

| Priority | Item | Mitigates |
|---|---|---|
| **P0** | Per-iface `rp_filter` check (`max(all, dev)`) + NIC CRC/duplex/carrier_changes reading + USB autosuspend check in `check` | H3, H8, H9 |
| **P0** | Passive `mono_ns` tick-slip detector -> auto `overrun`, plus kernel NTP `STA_UNSYNC` truthfulness | H1, H10 |
| **P1** | `nl80211` external `CMD_TRIGGER_SCAN` listener + `self_traffic_active` (`rx_delta + tx_delta`) flag in `Sample`/`analyze` | H4, H6 |
| **P1** | Observer Trust Score (`Clean | Caution | Polluted`) wired into `analyze::Report`, `advice.rs`, and `support_report` | H1–H12 |
| **P2** | `linkwatch check --deep` (5 s loopback jitter + simultaneous dual-path RX-counter proof + VPN check) | H1, H7, H8 |
| **P3** | `linkwatch calibrate` (single baseline + co-located two-probe `ΔRSSI` / `ΔRTT` / clock skew `calibration.json`) | H5, H10 |

### Status (2026-11-27)
- **Done:** per-interface `rp_filter` (`max(all, dev)`), cable speed/duplex and NIC CRC/frame errors, USB/PCIe power control, VPN/tunnel interfaces, conntrack fill, network managers, rfkill/Bluetooth, random MAC, MTU (`src/hostcheck.rs`, part of `linkwatch check`).
- **Done:** host's own traffic (H4): ticks with rx+tx above 10 Mbit/s outside the speed test (`Opts::self_traffic_bps`) do not count as stalls; short unconfirmed drops in that time are `Observer` incidents; `IfaceReport.self_traffic_s` / `self_traffic_stalls` and the `o_self_traffic` finding.
- **Done:** packet rate (H16): `Sample.pkt_delta`, limit 2000 packets/s.
- **Done:** Wi-Fi country (H18) in `check`; default-route metrics (H21) and local resolver (H14).
- **Done:** Observer Trust Score (3.4): `Report.observer_trust` (`clean | caution | polluted` + translatable reasons `t_*`), shown in the Markdown report and as a KPI tile in the web report; a `polluted` session (other than power-save, which has its own warning) sets support-pack readiness to `Low` with `warn_observer_polluted`.
  - `polluted`: Wi-Fi power-save on; ≥ 1 % late ticks; throttling in ≥ 10 % of host samples.
  - `caution`: ≥ 0.1 % late ticks; any throttling; NTP not synchronized; ≥ 60 s of own heavy traffic; any observer incident; CPU peak ≥ 85 %.
- **Open:** kernel `STA_UNSYNC` (needs `adjtimex`, the crate forbids `unsafe`), `check --deep`, `calibrate`.
