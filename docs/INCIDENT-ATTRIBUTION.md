# Incident Attribution ("Detective")

> Status: design for `src/analyze/attribution.rs` (replaces the boolean block in
> `Analyzer::finish`). Audience: maintainers and agents that change the analyzer.

## 1. Problem

Today every outage episode gets `origin = Observer` when **any** host flag is near it (scan,
speed test, own traffic, late ticks, suspend, throttling, low memory, driver reset), with a few
"unless another path or the router log confirms it" exceptions. That is:

- **too lenient** when a small host effect hides a real network fault: one late tick in a 40 s
  outage makes the whole outage "the observer's fault" and removes it from the network totals;
- **too aggressive** when a host effect could not have caused the symptom at all: a Wi-Fi scan
  next to an Ethernet-only outage, or a driver reset that came 20 s *after* the outage began;
- **opaque**: the report does not say *why* an incident was excluded, or what would change it.

Two alerts the old code waits for (`thermal_throttle`, `undervoltage`) are never emitted by
`host.rs`; throttling arrives only as `HostSample.throttled`. The new module uses the samples.

## 2. Principle

A host problem explains an incident only when it is **able** to produce this symptom on this
path (capability), is **strong enough** for this duration (dose), came **first** (timing), and
nothing independent **contradicts** it (counter-evidence). Each incident gets an explicit
evidence list and a graded result, never a silent exclusion.

## 3. Inputs per incident (`IncidentFacts`)

Built by the engine from data that every session already records. No new measurements.

| Field | Source |
|---|---|
| `iface`, `role`, `duration_s`, `ticks` (bad ticks), `tick_s` | episode |
| `scan_ticks`, `speedtest_ticks`, `self_traffic_ticks`, `overrun_ticks` | bad ticks of the episode with that `Sample` flag (own traffic includes the merge gap before) |
| `suspend_near` | `SuspendGap` event in `[start − 10 s, end + 10 s]` |
| `driver_reset_offset_s` | first `HostAlert driver_reset` for this iface in `[start − 30 s, end + 15 s]`, seconds from `start` (negative = before) |
| `throttled_near`, `low_memory_near` | `HostSample.throttled` / `HostAlert low_memory` in `[start − 30 s, end + 15 s]` |
| `power_save_on` | Wi-Fi power-save was on for this iface during the session |
| `other_failed` | other interfaces whose outage covers at least half (or 3 ticks) of this one, with their role and the host flags they had |
| `comparable_paths` | other interfaces that had link during the episode |
| `router_hit` | imported router (DOCSIS) log line within ±120 s |
| `ap_disconnect` | `WifiDisconnect` by the AP or by timeout within ±15 s (Wi-Fi only) |
| `host_samples` | the session has host samples at all |

## 4. Suspects: what each host effect can explain

`scope` = which paths it can break. `max` = the longest stretch of an outage it can explain.
`strength` = how sure we are when it fully covers the outage.

| Suspect | Scope | Explains (seconds) | Strength | Notes |
|---|---|---|---|---|
| `scan` (own off-channel scan) | this Wi-Fi iface only | `scan_ticks·tick + 2 s`, max 12 s | strong | cannot touch Ethernet |
| `speed_test` (own) | all paths (shares the WAN) | `speedtest_ticks·tick + 5 s`, max 30 s | strong | a provocation, not a fault: with other paths failing too it is a **load incident** (network weakness under load) |
| `self_traffic` (host's own load) | this iface only | `self_traffic_ticks·tick + 5 s`, max 30 s | strong | other path without own traffic failing = counter-evidence |
| `overrun` (late ticks) | all paths | `overrun_ticks·tick` | strong if ≥ 50 % of ticks, else weak | each late tick explains one tick, no more |
| `suspend` | all paths | whole outage | confirmed | the host was not running |
| `driver_reset` | this iface only | whole outage, **only if** offset ≤ +5 s | strong | later than +5 s = a consequence, not the cause (noted) |
| `throttling` | all paths | max 15 s | weak | throttling causes late ticks; alone it is a hint |
| `low_memory` | all paths | max 15 s | weak | |
| `power_save` | this Wi-Fi iface only | whole outage **only if** ≤ 2 ticks | weak | power-save adds latency and 1–2 missed beacons, not long full loss |
| `clock_jump` | all paths | max 5 s | strong | the wall clock was stepped (`ClockJump`); tick timing around it is not trustworthy |

`host_explained_s` = the largest explained value of the suspects that apply and are **not
contradicted** (capped at the duration); see section 6 for the exact rule. Ratio
`r = host_explained_s / duration_s`. All numbers are named constants in `mod limits` of
`attribution.rs`; section 6a lists them.

## 5. Counter-evidence (independent of the host)

A counter-evidence item applies to a suspect only when the suspect **could not** have caused
it:

- **Other path failed** (`other_failed` non-empty) — counts against suspects with scope "this
  iface only" (`scan`, `self_traffic` when the other path had no own traffic, `driver_reset`,
  `power_save`), against every **weak** suspect (`throttling`, `low_memory`, weak `overrun`: a
  hint does not outweigh an independent path), and against `speed_test` (→ load incident). It
  does **not** count against strong all-path suspects (`suspend`, strong `overrun`): those break
  every path at once.
- **Router log line** (`router_hit`) — counts against every suspect.
- **AP disconnect** (`ap_disconnect`, the AP sent deauth or the association timed out) —
  counts against `scan`, `power_save`, `self_traffic`.

## 5a. Network causes (hints)

When the network is (partly) at fault, the detective also names the most likely network
element. Several can apply; the list is ordered strongest first. The ones marked *independent*
are counter-evidence like the router log (section 5).

| Cause | Signal | Independent | Counts against |
|---|---|---|---|
| `router_log` | imported DOCSIS log line ±120 s | yes | every suspect |
| `router_reboot` | router uptime went back (UPnP/SNMP), boot time ±60 s | yes | every suspect |
| `router_wan_down` | router reports WAN/PHY down ±30 s | yes | every suspect |
| `ap_disconnect` | AP deauth or association timeout ±15 s | yes | `scan`, `power_save`, `self_traffic` |
| `channel_switch` | `ChannelChange` on this iface (−15 s … +5 s) | yes | `scan`, `power_save`, `self_traffic` |
| `carrier_loss` | `LinkChange` carrier 1 → 0 on this wired iface ±5 s | yes | iface-only and weak suspects |
| `roam` | `Roam` on this iface (−10 s … +5 s) | no (the client decides; H22) | — |
| `dhcp` | episode state `no_ip` | no | — |
| `weak_signal` | median signal ≤ −75 dBm ±60 s | no | — |
| `busy_channel` | median channel busy ≥ 70 % ±60 s | no | — |

Observer results carry no network causes.

## 6. Result

```text
Attribution = network | network_despite_host | mixed | observer_likely | observer_confirmed
Confidence  = high | medium | low          (network results: independence; observer results: see below)
```

Decision, in this order:

1. No suspect applies → `network`.
2. Strongest applicable suspect `S` (confirmed > strong > weak), ratio `r`, counter `C`
   (any counter-evidence that applies to `S`).
3. With `C`:
   - `S` is `speed_test` → `mixed` (the existing *load incident*: counted as network, flagged
     as load-provoked).
   - `S` strong or confirmed and `r ≥ 0.1` → `mixed`.
   - otherwise → `network_despite_host`.
4. Without `C`:
   - `r ≥ 0.8`: `observer_confirmed` when `S` is confirmed or strong, `observer_likely` when weak.
   - `0.1 ≤ r < 0.8` → `mixed`.
   - `r < 0.1` → `network_despite_host`.

**Rule for `host_s` (`host_explained_s`).**
- `host_s` is the maximum `explains_s` over the candidates that independent evidence does
  **not** contradict. A contradicted suspect never raises it.
- If the main suspect is contradicted, its own value still decides the grade (the ratio `r` is
  taken from `max(non-contradicted, main)`), because it is the strongest hint.
- `mixed` reports `network_s = duration − host_s`. When the main suspect is contradicted, the
  reported `host_s` is capped at `duration − tick`, so a `mixed` result never shows
  `network_s = 0`. If the cap leaves `host_s = 0` (a one-tick outage), the result is
  `network_despite_host`.
- Without contradiction `mixed` has `r < 0.8`, so `network_s > 0.2 · duration`.
- The only `mixed` with `network_s = duration` is the **load incident** (`speed_test`
  contradicted by another failing path): the host provoked it and the network really failed
  under that load, so `host_s` keeps the speed-test value and `network_s = duration` by design.
- `network_despite_host` reports `host_s` as what the host could have explained, and
  `network_s = duration`.

Confidence of `observer_likely` and `observer_confirmed` (the main suspect is not contradicted):
- `high`: the main suspect is `strong` or `confirmed`, it explains the whole outage
  (`explains_s ≥ duration`), and a comparable path had link and stayed fine
  (`comparable_paths > 0` and `other_failed` empty).
- `medium`: the main suspect is `strong` or `confirmed`, but it covers only part of the outage
  (for example 25 late ticks of 30), or no comparable path stayed fine (single path, or the
  other path failed with its own traffic or in a suspend).
- `low`: the main suspect is `weak` (`observer_likely`).

Confidence of `network`, `network_despite_host` and `mixed`:
- `high`: another path failed, a router log line, or an AP disconnect.
- `medium`: another path was comparable (had link) and stayed fine.
- `low`: single path, nothing independent.

### 6a. Thresholds and why

All values live in `mod limits` in `src/analyze/attribution.rs`. "Engineering estimate" means
there is no measured source: the value is a judgement and can be tuned.

| Constant | Value | Reason |
|---|---|---|
| `MIN_TICK_S` | 0.2 s | Guard against a zero or tiny tick length. Engineering estimate. |
| `SCAN_BASE_S` | 2 s | A scan keeps the radio off-channel for a few seconds in total. Engineering estimate. |
| `SCAN_MAX_S` | 12 s | A full multi-band scan rarely blocks the link longer. Engineering estimate. |
| `SPEEDTEST_BASE_S` | 5 s | The line stays loaded a while after the last bad tick. Engineering estimate. |
| `SPEEDTEST_MAX_S` | 30 s | Longest plausible disturbance by one speed test. Engineering estimate. |
| `SELF_TRAFFIC_BASE_S` | 5 s | Queues need seconds to drain after heavy own traffic. Engineering estimate. |
| `SELF_TRAFFIC_MAX_S` | 30 s | Longest plausible disturbance by own traffic. Engineering estimate. |
| `THROTTLE_MAX_S` | 15 s | Throttling is only a hint. Engineering estimate. |
| `LOW_MEMORY_MAX_S` | 15 s | Low memory is only a hint. Engineering estimate. |
| `CLOCK_JUMP_MAX_S` | 5 s | A clock step distorts about one short window. Engineering estimate. |
| `DRIVER_RESET_MAX_OFFSET_S` | 5 s | A reset later than this is a consequence of the outage. Engineering estimate. |
| `POWER_SAVE_MAX_TICKS` | 2 ticks | Power-save loses a few beacons (beacon interval about 102 ms, IEEE 802.11), not a long full loss; the 2-tick limit is an engineering estimate. |
| `OVERRUN_STRONG_SHARE` | 0.5 | Late ticks are strong when they are at least half of the bad ticks. Engineering estimate. |
| `WEAK_SIGNAL_DBM` | −75 dBm | Common rule of thumb for unreliable Wi-Fi. Engineering estimate. |
| `BUSY_CHANNEL_PCT` | 70 % | Little air time is left above this. Engineering estimate. |
| `OBSERVER_RATIO` | 0.8 | A host effect at 80 % or more of the outage counts as covering it. Engineering estimate. |
| `MIXED_RATIO` | 0.1 | Below 10 % a host effect is noise. Engineering estimate. |

### Mapping to the existing fields (backward compatible)

| Attribution | `Episode.origin` | Counted in |
|---|---|---|
| `observer_confirmed`, `observer_likely` | `observer` | observer incidents |
| `mixed`, `network_despite_host`, `network` | `network` (or `unknown` when `network` with `low` confidence and no host samples, as before) | network incidents (load incidents when `speed_test`) |

### Explanations

Every result carries translatable messages (`Msg`):
- `evidence`: one line per suspect and per counter-evidence (`a_scan`, `a_overrun`,
  `a_driver_reset_after`, `a_other_path`, `a_router_log`, ...), with the seconds it explains;
- `flip`: what would change the result (for example "if the Ethernet path had failed at the
  same time, this would be a network fault"), so a reader can check it.

## 7. Scenarios (tests)

`t` = tick (1 s). "Wi-Fi out 4 s" = 4 bad ticks. Ethernet "ok" = comparable path that stayed
fine. Each row is a unit test on `attribute()`; rows marked **E2E** are also tested through
`Analyzer` with samples and events.

| # | Situation | Expected | Why |
|---|---|---|---|
| A1 | Wi-Fi out 4 s, scan on 3 of 4 ticks, Ethernet ok | `observer_confirmed` | scan explains 5 s ≥ 4 s; scan cannot be contradicted by a healthy cable |
| A2 | Wi-Fi out 40 s, scan on 3 ticks, Ethernet ok | `mixed`, host 5 s, network 35 s | scan explains 5 s (r = 0.125) |
| A3 | Ethernet out 10 s, Wi-Fi scan at the same time, Wi-Fi ok | `network` | a Wi-Fi scan cannot break the cable (scope) |
| A4 | Both paths out 20 s, `SuspendGap` inside | `observer_confirmed` on both | all-path suspect; the other path failing is not counter-evidence |
| A5 | Wi-Fi out 20 s, throttling near, router log line | `network_despite_host`, confidence high | weak suspect + router log |
| A6 | Wi-Fi out 30 s, 2 of 30 ticks late, Ethernet ok | `network_despite_host` | late ticks explain 2 s (r < 0.1) |
| A7 | Wi-Fi out 30 s, 25 of 30 ticks late | `observer_confirmed` | strong overrun, r ≥ 0.8 |
| A8 | Wi-Fi out 10 s with own heavy traffic on Wi-Fi, Ethernet ok | `observer_confirmed` | own load on that path only |
| A9 | Wi-Fi out 10 s with own traffic on Wi-Fi, Ethernet (no own traffic) also out | `mixed`, high | the clean path failed too |
| A10 | Wi-Fi out 40 s, driver reset at +20 s | `network`; note "driver reset came after the outage began" | timing: consequence, not cause |
| A11 | Wi-Fi out 40 s, driver reset at −2 s, Ethernet ok | `observer_confirmed` | reset first, iface-scoped |
| A12 | Wi-Fi out 15 s, power-save on, Ethernet ok | `network_despite_host`, medium | power-save cannot cause 15 s of full loss |
| A13 | Wi-Fi out 2 s, power-save on, Ethernet ok | `observer_likely` | 1–2 missed beacons; weak |
| A14 | Wi-Fi out 8 s, own speed test on 7 ticks, Ethernet ok | `observer_confirmed` (**E2E**, existing test) | short, uncorroborated |
| A15 | Both out 6 s during own speed test | `mixed` → load incident, origin `network` (**E2E**, existing test) | the WAN gives up under load |
| A16 | Wi-Fi out 30 s, nothing on the host, single path | `network`, confidence low | nothing contradicts, nothing confirms |
| A17 | Wi-Fi out 12 s, scan on 3 ticks, AP sent deauth | `mixed`, high, host 5 s | the AP acted; a long off-channel scan can still have provoked it |
| A18 | Wi-Fi out 20 s, low memory near, Ethernet ok | `mixed`, host 15 s, network 5 s | weak suspects explain at most 15 s and never confirm |
| A19 | Wi-Fi out 4 s, throttling near, Ethernet ok | `observer_likely` | a weak suspect covers it all, nothing contradicts |
| A20 | Both paths out 6 s (gateway answers, internet does not), throttling near | `network_despite_host`, high (**E2E**, existing test) | a weak hint does not outweigh two failing paths |
| A21 | Both paths `lan_down` 90 s, router uptime reset inside | `network`, high, cause `router_reboot` | the router itself restarted |
| A22 | Wi-Fi out 6 s, `ChannelChange` 5180 → 5500 at +1 s, Ethernet ok | `network`, high, cause `channel_switch` | DFS / AP channel move |
| A23 | Wi-Fi out 3 s, `Roam` at the start, Ethernet ok | `network`, medium, cause `roam` | roaming gap; the client chose it, so it is only a hint |
| A24 | Wi-Fi out 3 s, `Roam` and own scan on 2 ticks, Ethernet ok | `observer_confirmed` | the scan explains 4 s; a roam does not contradict it |
| A25 | Wi-Fi out 20 s, signal −82 dBm, Ethernet ok | `network`, medium, cause `weak_signal` | |
| A26 | Wi-Fi out 10 s, channel 85 % busy, Ethernet ok | `network`, medium, cause `busy_channel` | |
| A27 | Wi-Fi `no_ip` 30 s, Ethernet ok | `network`, medium, cause `dhcp` | |
| A28 | Both paths out 4 s, `ClockJump` inside | `observer_confirmed` | the clock step explains 5 s |
| A29 | Both paths out 60 s, `ClockJump` inside | `network_despite_host` | a clock step explains 5 s of 60 (r < 0.1) |
| A30 | Wi-Fi out 8 s, own scan on 3 ticks, `ChannelChange` at the same time | `mixed`, high, host 5 s, cause `channel_switch` | the AP moved channel; the scan explains only part |
| A31 | Ethernet out 5 s, carrier lost, Wi-Fi ok | `network`, high, cause `carrier_loss` | cable, port or NIC |
| A32 | Wi-Fi out 30 s, 15 of 30 ticks late, router log line | `mixed`, high, host 15 s | strong overrun, but the router also logged an event |
| A33 | Both paths out 10 s, own heavy traffic on both | `observer_confirmed` on both | the other path had own traffic too, so it is not independent |
| A34 | Wi-Fi out 3 s, power-save on, `ChannelChange` | `network_despite_host`, high, cause `channel_switch` | weak suspect contradicted by the AP |

Clock trust (an unsynchronized clock when two observers are compared) belongs to `compare`,
not to the per-incident result: `compare` already refuses to match events when clocks are not
trusted.

## 8. Not in scope

- New measurements or sensors.
- Probabilities or machine learning: the rules stay deterministic and every number is shown.
- Changing the per-tick classifier (`classify.rs`) or the live verdict.

## 9. The 30 most common real causes and coverage

How often home users meet each cause is an estimate from support practice, not a measured
statistic. "Covered" = the detective names it today; "partial" = visible in the report but not
as a named cause; "no" = not detected.

| # | Cause | Side | Covered |
|---|---|---|---|
| 1 | Weak signal (distance, walls, floors) | Wi-Fi | yes (`weak_signal`) |
| 2 | Busy / overlapping channel (neighbours, co-channel) | Wi-Fi | yes (`busy_channel`) |
| 3 | Roaming gap between APs or mesh nodes | Wi-Fi | yes (`roam`) |
| 4 | AP deauth: band steering, load balancing, inactivity | Wi-Fi | yes (`ap_disconnect`) |
| 5 | DFS radar channel switch on 5 GHz | Wi-Fi | yes (`channel_switch`) |
| 6 | Router reboot / firmware crash | router | yes (`router_reboot`, needs `[router]`) |
| 7 | Router WAN / modem sync loss (DOCSIS T3/T4, DSL resync) | line | yes (`router_wan_down`, `router_log`) |
| 8 | ISP outage or maintenance | ISP | partial (cause `line_problem` / `internet_problem`) |
| 9 | DHCP lease failure | router | yes (`dhcp`) |
| 10 | Bufferbloat under load | line | yes (load incidents, loaded RTT) |
| 11 | Evening congestion | ISP | partial (peak/off-peak RTT, hourly profile) |
| 12 | ISP DNS outage | ISP | partial (cause `dns`) |
| 13 | Problems beyond the ISP (peering, a target down) | internet | partial (cause `internet_problem`) |
| 14 | Bad patch cable / port / NIC | local | yes (`carrier_loss`; `check` CRC/duplex) |
| 15 | Router overheating or CPU overload | router | no (needs router CPU/temperature telemetry) |
| 16 | Router NAT / conntrack table full | router | no |
| 17 | PPPoE session reconnect | line | partial (`router_wan_down` when the router reports it) |
| 18 | Mesh backhaul drop | Wi-Fi | partial (all clients of a node fail: visible with a second observer) |
| 19 | Powerline / MoCA adapter drop | local | partial (`carrier_loss` does not fire: the link stays up) |
| 20 | Rogue DHCP / IP conflict | LAN | partial (security events) |
| 21 | Client power-save | host | yes (`power_save`) |
| 22 | Own off-channel scan | host | yes (`scan`) |
| 23 | Own downloads, updates, backups | host | yes (`self_traffic`) |
| 24 | Own speed test | host | yes (`speed_test`, load incidents) |
| 25 | Host sleep / suspend | host | yes (`suspend`) |
| 26 | Driver / firmware reset, USB autosuspend | host | yes (`driver_reset`; `check` USB power) |
| 27 | Host CPU / disk stalls | host | yes (`overrun`; `check --deep` PSI) |
| 28 | Throttling / undervoltage / low memory | host | yes (`throttling`, `low_memory`) |
| 29 | Clock step | host | yes (`clock_jump`) |
| 30 | VPN carrying the probes | host | partial (`check` warns; not per incident) |

How many scenarios are enough: every suspect needs at least one case for each way it can go —
it covers the outage, it covers a part, it is out of scope, it comes too late, and it is
contradicted — and every named network cause needs one case. That is about 40 cases; A1–A34
plus the existing end-to-end tests cover the matrix except "too late" for suspects other than
the driver reset (they have no start time yet).

## 10. Masking: when a condition blocks a conclusion (implemented: M1, M2, M3, M5, M11 per incident; M4, M6, M9, M10, M13 per session; M7 not possible)

Status: rows marked **implemented** are in `attribution.rs` and tested (`m01_…` to `m11_…` in
`attribution_tests.rs`). The other rows are design only. Phase 1 is per incident; session-wide
rows (M4, M6, M7, M9, M10, M13, M15) need the session report. Phase 2 (below) does M4, M6, M9, M10, M13.

Phase 2: `Report.session_blinds: Vec<SessionBlind>` with `SessionBlind { element, by, share_pct, msg }`
(rule 3: reported once, in the Markdown section "Session-wide limits" and as a list under the KPI
tiles in the web report). `Element` also has `latency`, `isp`, `timing`, `network`; `BlindCause` also
has `power_save`, `vpn`, `monitor_gap`, `observer_polluted`, `self_traffic`, `own_speed_tests`.
Thresholds (rule 2: below them nothing is blinded):

| Row | Threshold |
|---|---|
| M4 | power-save on in at least 5 % of the power-save readings (host samples and Wi-Fi records) |
| M9 | any monitor gap above 5 s or host suspend; `share_pct` = gap share of the session |
| M10 | Observer Trust `polluted`; every non-observer finding gets confidence at most `medium` (applied in `finish()` after attribution and trust) |
| M13 | own heavy traffic in at least 10 % of the evening ticks (18-24 local) of the worst interface |
| M6 | at least 2 own speed tests in the evening and evening time / tests below 2 h; `share_pct` is 0 (no share applies) |

M7 (VPN) is **not implemented**: samples, host samples and events carry no VPN signal (no tunnel
interface or route is recorded). It needs a new collector field first. Existing patterns and
findings are not removed by a session blind; the blind states what they cannot prove.
Note: Observer Trust already counts any Wi-Fi power-save as `polluted`, so M10 also applies then.

Implemented in phase 1: `Finding.blinded: Vec<Blind>` with `Blind { element, by, msg }`;
`Element` = `router | line`; `BlindCause` = `busy_channel | weak_signal | clock_unsynced`;
`Attribution::Inconclusive`; the fact `IncidentFacts.clock_unsynced`. `Inconclusive` replaces
`network` / `network_despite_host` only for a Wi-Fi incident with a blinding condition at or
above its threshold (`BUSY_CHANNEL_PCT`, `WEAK_SIGNAL_DBM`) and nothing independent: no
comparable path, no other failed path, no trusted router log, router reboot or WAN-down, no AP
disconnect or channel switch. Confidence is `low`. The engine counts it as a network incident
(`IncidentOrigin::Network`), so totals do not change. Observer results never carry blinds.

Section 6 asks "who caused this incident". A second question is "what can this incident
prove at all". Some conditions do not cause the outage but **blind** the measurement for one
element: a 90 % busy Wi-Fi channel does not prove the router failed, but it also means a
Wi-Fi-only drop says nothing about the router. Other conditions are small and must be
**tolerated**: they lower confidence a little but do not block anything.

Each condition gets a `blinds` set (the elements it hides: `wifi`, `router`, `line`, `isp`,
`latency`, `timing`) and a strength. Per incident the detective then reports:

- `can_judge`: elements this incident can prove something about;
- `blinded`: elements it cannot judge, each with the condition that blinds it;
- `inconclusive` as an extra attribution when the condition blinds the element that the
  verdict would blame **and** no independent path or log can see past it.

Rules:
1. An **independent path unblinds**: a healthy Ethernet path proves the router and line were
   fine even while the Wi-Fi channel was saturated (the incident stays a Wi-Fi incident).
2. A **small condition never blinds** (same dose rule as section 6: r < 0.1, or a session
   share below 5 %); it only shows as a note.
3. A **session-wide condition** (power-save on all night, Observer Trust `polluted`) blinds the
   element for the whole session and is reported once, at the top, not on every incident.
4. **Nothing is invented**: when an element is blinded, the report says so and names the fix;
   it never falls back to a guess.

| # | Situation | Expected | Why |
|---|---|---|---|
| M1 | Wi-Fi-only drop 20 s, channel 90 % busy, no Ethernet | `inconclusive` for `router`, `line`; `can_judge: wifi` | the busy channel hides everything behind the AP **Implemented.** |
| M2 | The same, but Ethernet stays fine | `network`, Wi-Fi incident; router and line judged healthy | the cable path unblinds **Implemented.** |
| M3 | Wi-Fi-only drop, signal −86 dBm, no Ethernet | `inconclusive` for `router`, `line` | as M1 **Implemented.** |
| M4 | Power-save on all session | `blinded: latency` for the session (stall counts, bufferbloat, RTT medians); outages still judged | power-save adds latency, not long loss **Implemented** (session level). |
| M5 | Clock not synchronized, router log imported | `router_log` matches not used as counter-evidence; note | ±120 s matching needs a trusted clock **Implemented** (also: the router log does not raise confidence; note `blinded: line` by `clock_unsynced`). |
| M6 | Own speed test every 30 min in the evening | `blinded: isp` for the evening congestion pattern | own load is confounded with ISP peak load **Implemented** (session level). |
| M7 | VPN active during the session | `blinded: isp`, `line` for internet-path incidents | probes travel the tunnel **Not implemented:** no VPN signal in the data. |
| M8 | Router ignores ICMP (rate limit), internet fine | gateway loss does not blame the router | the router is busy answering, not down. Today only the Degraded check in `classify` allows for it; the other gateway-loss paths do not. Being fixed in the classifier (not done yet). |
| M9 | Monitor gap (service restart, disk full) | no conclusion inside the gap; gap listed | nothing was measured **Implemented** (session level, element `timing`). |
| M10 | Observer Trust `polluted` all night (late ticks) | every network result at most `medium`; no `observer_confirmed` needed per incident | session-wide; reported once **Implemented** (cap applied in the engine; one session blind). |
| M11 | 2 % of ticks late (Trust `caution`) | nothing blinded; one note | tolerated (rule 2) **Implemented** (conditions below their threshold, such as 2 of 30 late ticks, blind nothing). |
| M12 | Mesh / repeater between the observer and the main router | `router` means "the nearest Wi-Fi node"; note | the observer cannot see past the node |
| M13 | Host downloads heavily all evening | `blinded: isp` for evening RTT / speed patterns | own load **Implemented** (session level). |
| M14 | Repeated DFS channel switches all night | Wi-Fi incidents judged; cause `channel_switch`; advice: use a non-DFS channel | not blinding, a cause |
| M15 | Two observers, one `polluted` | `compare` uses the clean one for shared incidents | the polluted one cannot confirm or deny |
