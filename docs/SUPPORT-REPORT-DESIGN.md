# Support & Escalation Report Pack (`src/support_report.rs`)

> **Status:** implemented (`src/support_report/`, CLI `support-report`, `/api/support-report`, and Sessions Web UI dialog).  
> **For agents (progressive disclosure):** load this document on demand **only** when planning, implementing, reviewing, or testing `src/support_report.rs`, `/api/support-report`, `linkwatch support-report`, or its prerequisites in `analyze` / `/api/report`. Do not preload it during unrelated tasks.

---

## 1. Why Raw Technical Reports Fail (8 Core Problems)

1. **Unknown-tool credibility gap.** Neither ISP support staff nor a landlord knows what `linkwatch` is. A report titled `# linkwatch report` reads like output from an unverified custom script. Trust comes from a **3-line methodology summary** at the top (continuous 1 s direct ICMP/TCP/DNS probes over wired Ethernet and Wi-Fi, NTP-synchronized UTC + local timestamps, observer/load events separated, reproducible raw logs).
2. **Mismatched abstraction level.** Sending raw `dBm`, `p95 RTT`, or 802.11 reason codes to a landlord fails to explain why wireless repeaters won't help. Sending 4 pages of Markdown tables to a tier-1 ISP chat form (often capped around 1,500–2,000 characters) gets truncated or skipped.
3. **Misdirected escalation.** Users see failed probes and open an ISP line ticket even when drops happened only on Wi-Fi in one bedroom or strictly during a full-speed saturation test (bufferbloat). Unfounded tickets hurt credibility when real line faults occur later.
4. **Timezone ambiguity.** `linkwatch` stores UTC; router/modem logs and support dashboards often show local time (or ignore DST). A 1-hour shift causes support to reply *"no drops seen at that time"*. Reports for external teams must include **both UTC and local time**.
5. **Weak or premature evidence.** Exporting a 30-minute Wi-Fi-only run (especially with `power_save` enabled or unsynced clocks) invites instant dismissal by ISP engineering.
6. **Missing concrete asks.** Support teams respond slowly to open-ended complaints (*"internet is bad"*). Every report must translate findings into specific, answerable requests for that recipient.
7. **Privacy leaks and social friction.** Raw captures include MACs/BSSIDs, local IPs, LAN hostnames, and hourly active LAN device counts that reveal when residents are home. Overly adversarial wording makes recipients defensive.
8. **No verification loop ("Before / After").** After an ISP line tweak or router swap, users lack a side-by-side comparison proving whether the fault cleared or persists for formal escalation.

---

## 2. Knowledge Asymmetry Matrix

| Recipient | What they know | What they do NOT know | First 30 s questions | What the pack must provide |
|---|---|---|---|---|
| **ISP Tier 1 (L1 chat / phone / web form)** | Support scripts (reboot router, check cable, run speed test, live modem ping) | `linkwatch`, Linux metrics, `dBm`, `p95`, 802.11 reason 4 vs DOCSIS T3 timeout | *"Is this tested on Ethernet? Did you reboot? Could your laptop be sleeping? Exact times?"* | **Short layer (`<= 2000` chars):** **"Already ruled out"** checklist on line 1, 3–5 exact timestamps (UTC + local), one-line L2 escalation ask |
| **ISP Tier 2 / NOC engineer** | CMTS/ONT optics, T3/T4 timeouts, packet loss, bufferbloat, DNS, NTP, ICMP deprioritization | Custom app internals (but trusts standard network methodology) | *"Router ICMP rate-limit? NTP synced? First hop failed or only anycast? Loaded vs idle? Modem reboots?"* | **Full attachment (.md / printable .html):** 3-line method note, incident table (UTC+local, path state, `isp_hop`), router uptime & WAN status, loaded vs idle RTT, optional DOCSIS log correlation |
| **Landlord / Property manager** | Budget, tenant complaints, consumer terms ("Wi-Fi booster", "speed plan") | Networking jargon, `dBm`, ISP line vs indoor Wi-Fi, wall attenuation, co-channel contention | *"Is it the ISP's fault? Why not buy a cheap plug-in booster? Which rooms fail? What fix works best?"* | **1–2 page non-technical brief:** 2-sentence verdict, room table (good/degraded/poor) + wall geometry summary, clear comparison of fixes (wired AP vs wireless repeater) |
| **Local admin / Hardware vendor** | Channels, 20/40/80 MHz, WPA2/3, PMF, WPS, firmware versions, CVEs, SQM, bridge mode | Flat layout and measurement history | *"Exact model & firmware? Neighbour congestion? Open LAN ports? Client `power_save`?"* | Model/firmware/CVE + CISA KEV list, open LAN ports, Wi-Fi channel/width/security scan summary, retry rate, loaded RTT, actionable remediation checklist |
| **Sender (End user)** | Felt freezes/drops and who they want to contact | Whether evidence is ready yet, which recipient owns the fault, what is safe to share | *"Is this enough proof for an ISP? What do I paste? Did I leak housemates' data?"* | Pre-export **Readiness & Confidence Gate**, automatic audience warning, independent export language (`en`/`uk`), live preview + copy/download |

---

## 3. Six Core Design Principles

1. **Two-Layer Package from One Truth (`SupportPack`):**
   - **Layer 1 (`Ticket Text`, `<= 2000` chars):** copy-paste summary for web forms, live chat, or email body.
   - **Layer 2 (`Full Attachment`):** structured Markdown (`.md`) or self-contained offline **Printable HTML (`.html`)** styled with `@media print` so browsers can *Save as PDF* without adding external PDF crates.
2. **Self-Contained Methodology Footnote (Never Assume Tool Recognition):**
   - Neutral document titles (*"Network Connection Diagnostic Report"* instead of tool-centric headers).
   - A 3-line verifiable methods block stating probe frequency (`1 s`), protocol diversity (ICMP + TCP + direct DNS), interface binding (Ethernet vs Wi-Fi), NTP sync status, and observer/load separation.
3. **Pre-Export Readiness & Confidence Gate (`ReadinessLevel`):**
   - Evaluates evidence strength *before* generation:
     - `high`: dual-path (`ethernet` + `wifi`) or >= 2 NTP-synced overlapping observers, `>= 6 h` duration, clean observer state.
     - `medium`: `2–6 h`, or single-path where wired fault isolation is inferred or verified via router telemetry.
     - `low`: `< 2 h` (short sample), Wi-Fi-only when targeting `isp`, `power_save` enabled, unsynced clocks, or multiple monitor gaps.
   - Never hard-blocks emergency tickets (`S8`), but attaches concrete warnings and guidance on what is missing.
4. **"Already Ruled Out" L1 Script Killer:**
   - Generated strictly from observed session facts (never fabricated): wired Ethernet baseline tested, NTP clock synced (`clock_synced == true`), Wi-Fi power-save disabled (`power_save == false`), router continuous uptime with `0` reboots (`uptime_resets == 0`), observer faults and local speedtests excluded.
5. **Evidence-Gated Requests (`SupportAsk`) & Negative Gating:**
   - Emits asks **only** when backed by measured metrics or timestamped incidents.
   - **Negative gating rules** prevent counter-productive tickets:
     - `WifiProblem` / `LocalOnly` with Ethernet ~100% healthy -> explicitly warns user **not** to file an ISP line outage ticket; redirects asks to `landlord` / `admin`.
     - Incidents occurring strictly while `speedtest_active == true` -> labeled as load saturation / bufferbloat rather than unprovoked ISP line drops.
6. **Independent Export Language & Strict Privacy (`RedactionLevel`):**
   - Export language (`en`, `uk`, or any future locale registered per [docs/I18N.md](I18N.md); **no Russian**) is selectable independently of the Web UI language.
   - `RedactionLevel`:
     - `none`: internal view (full labels, local IPs, BSSIDs, hostnames).
     - `standard` (default for `isp` / `landlord`): masks BSSID/MAC addresses to last 3 octets (`...:aa:bb:cc`), **omits LAN active-device / occupancy timelines**, preserves UTC+local timestamps and `isp_hop` for ISP triage, strips `[web] token` and filesystem paths.
     - `strict` (for public forums / issue trackers): applies `standard` plus replaces private/ISP IPs with RFC 5737 documentation addresses (`192.0.2.x`, `198.51.100.x`), removes SSIDs, hostnames, and generalizes room identifiers.
   - Secrets (`[web] token`, router probe passwords/SNMP communities, local config paths) are structurally excluded from `SupportPack` at **all** redaction levels, including `none`.

---

## 4. Twelve Realistic Branching Scenarios (S1–S12)

### S1 — Real Overnight ISP Access-Line Outages (`LineProblem` / `SharedOutage`)
- **Stage 1 (Generation):**
  - *Branch A (Ideal):* `>= 8 h` dual-path run (Ethernet + Wi-Fi), NTP OK; both paths lose `isp_hop` + internet while router LAN answers in `< 5 ms`. Confidence = `high`; outputs Layer 1 chat text + Layer 2 printable HTML/MD with UTC+local table.
  - *Branch B (With Modem Log):* User supplies DOCSIS event log (`--router-log`). Matched `T3/T4` timeouts sit inline beside each outage timestamp, boosting escalation readiness for L2.
  - *Branch C (Wi-Fi-only):* Only wireless data exists. Readiness gate = `low` with warning: *"ISP will blame Wi-Fi; run one overnight test with Ethernet if possible, or send as preliminary."*
- **Stage 2 (Recipient Reaction):**
  - *Branch 1:* L1 tells user to reboot router -> **"Already Ruled Out"** checklist cites cable test, continuous router uptime, and asks for ticket reference + L2 handoff.
  - *Branch 2:* L1 replies *"line looks green right now"* -> report marks issue as **intermittent** and highlights exact UTC historical log windows for CMTS/ONT lookup.
  - *Branch 3:* ISP dispatches technician / reprovisions line -> user later runs **S12 (Before / After)** to confirm resolution.

### S2 — User Blames ISP, Real Cause Is Indoor Wi-Fi (Multi-Room)
- **Stage 1 (Generation):**
  - *Branch A:* User selects `isp`, but Ethernet has ~100% availability while bedroom Wi-Fi drops with `reason 4` / weak RSSI / high retries / co-channel AP -> **negative gate** warns *"ISP line is healthy; do not file an ISP line fault"* and offers one-click switch to `landlord` or `admin`.
  - *Branch B (Narrow ISP Router Ask):* Even with a healthy line, if ISP-supplied gateway shows bufferbloat or EOL/CVE issues, allows generating a narrow equipment-only ask explicitly noting the access line itself is stable.
- **Stage 2 (Landlord Negotiation):**
  - *Branch 1:* Landlord suggests cheap plug-in Wi-Fi repeaters -> `landlord` brief includes data-backed *"Why wireless repeaters worsen co-channel contention"* + side-by-side comparison (*wireless repeater* vs *single wired hallway AP*).
  - *Branch 2:* Landlord claims *"your old laptop is broken"* -> multi-session comparison (`kitchen` vs `bedroom A` vs `bedroom B`) plus `RfPathEstimate` wall/distance table isolates physical RF attenuation.
  - *Branch 3:* Landlord struggles with technical charts -> 2-sentence plain summary leads the PDF before any numbers.

### S3 — Drops and Lag Only Under Heavy Load (`Bufferbloat` / `speedtest_active`)
- **Stage 1 (Classification):**
  - *Branch A (Self-Test Artifact):* All cable/Wi-Fi timeouts occurred strictly during `linkwatch`'s hourly download test. Support pack excludes them from unprovoked outage totals and explains load-induced latency spikes cleanly.
  - *Branch B (Real Multi-User Saturation):* Evening downloads trigger 300+ ms RTT stalls for other residents (`loaded_net_rtt_med` spike). Report targets `admin` / `isp` with loaded-vs-idle RTT delta.
- **Stage 2 (Reaction):**
  - *Branch 1:* ISP replies *"speed test matches your tariff"* -> report contrasts **peak Mbps** against **latency under load** and requests bridge/modem mode (so a user SQM router can manage queues) or router AQM firmware.

### S4 — Router Freezes or Silently Reboots (`RouterProblem`)
- **Stage 1 (Evidence):**
  - *Branch A:* UPnP captures `uptime_resets > 0` right at a dual-path LAN failure -> direct hardware/power/firmware replacement ask.
  - *Branch B:* Router stops answering on `192.168.x.1` over both cable and Wi-Fi for 5–20 s without resetting UPnP `uptime_s` -> thermal/firmware hang evidence.
- **Stage 2 (Pushback Handling):**
  - *Branch 1:* ISP/landlord claims *"home power flickered"* -> report cites observer host's unchanged `boot_id` and uninterrupted host uptime on the same mains circuit.

### S5 — Peak-Hour Slowdowns Without Hard Drops (A8)
- **Stage 1 (Attribution):**
  - *Branch A (Upstream Saturation):* Wired throughput collapses from e.g. `380 Mbit/s` off-peak to `< 50 Mbit/s` in evenings (`18:00–23:00`) with elevated RTT while local LAN active count remains flat -> `isp` brief presents wired-only peak vs off-peak hourly profile (ready for regulator / minimum-speed guarantee escalation).
  - *Branch B (Household Saturation):* LAN sweep median doubles in evenings alongside high WAN packet/byte rates -> warns user that household sharing explains the slowdown; suppresses ISP oversubscription claim.

### S6 — Websites Fail While Direct IP Probes Succeed (`Dns`, A6)
- **Stage 1 (Branches):**
  - *Branch A:* Upstream ISP DNS servers time out while ICMP/TCP to public IPs is 100% -> `isp` ticket lists exact DNS server IP(s) and UTC failure windows.
  - *Branch B:* Managed apartment where user cannot touch router -> `admin` ask requests changing DHCP-distributed DNS, while giving user immediate safe client DoH/DoT steps.

### S7 — Vulnerable / EOL Firmware, Insecure Ports, or Rogue DHCP (`RouterAudit` / `CVE`)
- **Stage 1 (Branches):**
  - *Branch A (Audit + CVEs run):* Lists firmware age/EOL kernel, CISA KEV matches, open Telnet/FTP/HTTP-only admin, `WPA2-TKIP`, or `WPS` -> emits concrete `admin` / vendor upgrade or replacement ask.
  - *Branch B (`rogue_gateway` security event):* Immediately generates an urgent local-network notice (*"Do not escalate to ISP: a second DHCP server/router was connected inside the LAN"*).
  - *Branch C (No active probe run):* Explicitly prints scope boundary (*"Passive air/port visibility only; firmware login audit not performed"*).

### S8 — Emergency Outage Happening Right Now (Short Run)
- **Stage 1 (Branches):**
  - *Branch A (WAN down, Wi-Fi LAN still alive):* User opens offline Web UI on phone after 20–30 minutes of `LineProblem` -> generates an **Emergency Ticket** (confidence noted honestly as *ongoing 30 min outage*, router LAN answering `2 ms`, `0` reboots, `100%` loss at `isp_hop`).
  - *Branch B (Total router crash):* User generates Layer 1 ticket via CLI over Ethernet (`linkwatch support-report --audience isp --format text`).

### S9 — Cross-Language Diagnostics and Export
- **Stage 1 (Branches):**
  - *Branch A:* Operator inspects UI in Ukrainian (`uk`) and exports an English (`en`) ISP or landlord pack. All structured sections, verdicts, findings, and asks render via `Msg` keys in pure target language with zero mixed prose.
  - *Branch B:* User typed a custom free-text session `note` in another language -> preview highlights untranslated free-text fields before copying/sending.

### S10 — Privacy and Redaction Before Third-Party Sharing
- **Stage 1 (Branches):**
  - *Branch A (`standard`, ISP / Landlord):* Strips hourly LAN device occupancy series, masks client/router BSSIDs/MACs, strips local host paths and tokens, keeps UTC/local timestamps and `isp_hop` (for ISP) or room metrics (for landlord).
  - *Branch B (`strict`, Public Forum / Issue):* Masks private LAN and ISP IPs with RFC 5737 placeholders (`192.0.2.x`, `198.51.100.x`), hides SSIDs and hostnames, generalizes point IDs (`Room A`, `Room B`) while keeping distances/wall materials.
  - *Branch C (Structural Secret Guard):* `[web] token` and router probe credentials are never stored in `SupportPack` or any export under any mode.

### S11 — Polluted Measurement / Observer Fault (B1–B12)
- **Stage 1 (Branches):**
  - *Branch A (Observer Issue):* Session had `power_save = true`, `suspend_gap`, thermal throttling, or `clock_synced = false` -> readiness gate drops to `low`, observer incidents remain excluded from ISP/landlord claims, and user is advised to re-run clean.
  - *Branch B (Mismatched Networks):* User tries building a comparison pack across sessions with `NetworkMatch::Different` -> pack refuses mixed ISP attribution and explains the mismatch.

### S12 — Before / After Verification & Formal Escalation
- **Stage 1 (Branches):**
  - *Branch A (Fix Verified):* Comparing baseline vs post-change sessions shows quantifiable delta (e.g. room outages `3 -> 0`, retries `252/min -> 18/min`, signal `-67 -> -51 dBm`) -> clean verification note for landlord or ticket closure.
  - *Branch B (Intervention Failed):* Post-ISP-fix run still reproduces the exact fault pattern -> builds chronological escalation dossier (*Baseline -> Reported fault -> Post-intervention re-test showing recurrence*) ready for L2 management or telecom ombudsman.

---

## 5. Module Architecture, Prerequisites & Test Matrix

### Module Boundary (`src/support_report.rs`)
- Pure-Rust synthesis & formatting module (`#![forbid(unsafe_code)]`), zero duplicated fault-detection rules.
- Consumes outputs from `analyze::Analyzer`, `compare::compare`, `router::advice::evaluate`, `router::RouterAudit`, `router::CveLookupResponse`, and `site::Site` (`RfPathEstimate`).
- Core types (`ts_rs::TS` exported where needed by Web UI):
  - `SupportAudience`: `Isp | Landlord | Admin`
  - `RedactionLevel`: `None | Standard | Strict`
  - `ReadinessLevel`: `High | Medium | Low`
  - `SupportAsk`: `{ code, severity, target, evidence_timestamps, summary_msg }`
  - `SupportPack`: metadata, `ReadinessAssessment`, `AlreadyRuledOut`, localized sections via `Msg`, pre-formatted short text (`<= 2000` chars), Markdown, printable HTML, JSON.

### Prerequisites (Implement First)
1. **Report Model Enhancements (`src/analyze/`, `src/web/api.rs`):**
   - Expose `loaded_gw_rtt_med` and `loaded_net_rtt_med` (already computed in `IfaceReport`) on `/api/report` (`ReportIface`).
   - Flag or count `speedtest_active`-coincident episodes separately from unprovoked idle outages in `ReportResponse` so bufferbloat never masquerades as spontaneous line failure.
2. **Site RF Context in Multi-Session Summaries:**
   - Attach per-point `RfPathEstimate` (distance, walls crossed, obstacle loss dB) when building `landlord` / `admin` comparison packs.

### CLI, Web API & UI Surface
- **CLI:** `linkwatch support-report --audience isp|landlord|admin --lang en|uk --redact standard|strict|none --format text|md|html|json [sessions...]`
- **Web API:** `GET /api/support-report?sessions=...&audience=...&lang=...&redact=...&format=...` (available read-only respecting `[web] view` and host checks; redaction enforces zero secrets).
- **Web UI:** **Support report** trigger on the **Sessions** view opening a CSP-safe `<dialog>` with audience, language, and redaction controls, Readiness badge preview, copyable Layer-1 text (`<= 2000` chars), and `<a download>` for `.md` and printable `.html`.

### Unit & Contract Tests
- **Negative gating:** `WifiProblem` / `LocalOnly` under `audience = Isp` emits `do_not_file_isp_line_ticket` and zero line-fault asks; `speedtest_active`-only drops suppress unprovoked outage asks.
- **Redaction invariants:** `Standard` omits `lan` hourly occupancy & masks BSSID/MACs; `Strict` strips real SSIDs/private IPs/hostnames/room IDs; no `[web] token` or password can ever appear in any format.
- **Readiness gate:** short (< 2 h), Wi-Fi-only for ISP, `power_save = true`, or `clock_synced = false` downgrades readiness with explicit warning codes.
- **Length & charset limits:** Layer-1 ticket text stays `<= 2000` characters even with 100 episodes; Markdown tables escape `|`; printable HTML escapes `<`, `>`, `&`, `"` cleanly with zero external URLs or scripts.
- **Cross-language parity:** `en` and `uk` render without English leaks in `Msg` keys (verified via `t()` / `locale_*.ts`).
