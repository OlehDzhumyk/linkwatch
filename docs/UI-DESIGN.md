# linkwatch web UI: design specification

Status: **stage 2 complete + stage 3 interactions implemented** (27.11.2026). The owner accepted D1–D9 and §11.6a.

Remaining from §11.7: item 5 (visual site layout editor with snapping), deferred as its own module. Shared UI primitives (`kv`, `emptyState`, `errorState`, disclosure persistence, accessible `wireDialog`) live in `src/web/ui/src/ui.ts` because modules under `src/web/ui/src/` are kept flat so `/js/:name` serves them without a bundler.

Differences from the draft:

- The event log is in **Sessions** (under a disclosure), because it follows the selected session.
  Diagnostics keeps the observer and security events of the running session.
- Analyzer findings, patterns, compare findings and audit warnings stay English server text,
  shown only inside disclosures. The verdict sentence and the advisor are translated (D5 codes:
  `verdict_code` + `verdict_args`, advice `code` + `args`).
- `light-dark()` tokens: canvas code resolves them in `cssVar()` (custom properties are not
  computed by the browser).

Hard constraints (unchanged):

- No frameworks, bundlers or CDNs. Strict TypeScript in `src/web/ui/src/` compiled to `dist/`,
  embedded in the binary with `include_str!`.
- Strict CSP: no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`eval`/`new Function`, no inline
  `style=` and no `.style.*` writes, no inline scripts or handlers, `form-action 'none'`.
  Dynamic geometry goes into SVG attributes (`x`, `width`, `transform`) or canvas, never CSS.
- All visible text goes through `t()`; EN and UK ship, new locales are one file. No Russian.
- The repository holds no real addresses, SSIDs, BSSIDs, MACs, tokens or site files.

---

## 1. Audit of the current UI (v0.4.0 + commits 60e14a4..0e5cd6c)

Checked on the demo server (`demo_ui_server`) at 1440×900 dark and 390×844 light.

### 1.1 What works

- Solid base: typed API, `el()`/`sv()` helpers, no unsafe DOM, theme tokens, keyboard tabs,
  `prefers-reduced-motion`, tabular numbers.
- The data is rich and correct enough to answer the real question ("where do drops come from").

### 1.2 Problems, by severity

**Contradicting signals (worst UX issue).** One screen tells different stories at once:

| Place | Says |
|---|---|
| Header pill | "Wi-Fi problem" (amber) |
| Wi-Fi card | "Router not answering" (red) but Router RTT "3.2 ms" in green |
| Report | "Wi-Fi failed" sentence, then "Incidents 0 — no outage detected" |
| System › Recommendations | "No common configuration or security issues detected" (green) |
| Timeline | red failure ticks every ~1.5 h |

A user cannot tell which one is true. Cause: every panel derives its own status from a
different source (live state, last sample, analyzer, advisor), with different colours.

**No hierarchy.** Everything is a panel of the same weight. The first screen spends its space on a
topology drawing and two large interface cards; the answer ("is it fine, and if not, where") is a
small pill in the corner. The timeline, the report and the events all have the same visual rank.

**Session context is ambiguous.** The session selector on Live changes the timeline, events and
report, but not the topology, cards, header or speed table. After a switch, half the page is
history and half is live.

**Mobile (390 px) is broken.**
- The page is 506 px wide: the topology SVG has a fixed 860-unit viewBox with labels that do
  not scale, so the page scrolls sideways (`scrollWidth` 506 at `innerWidth` 390).
- The sticky header takes ~40 % of the first screen (brand, subtitle, three controls, verdict,
  tabs on five rows).
- Tooltips open past the right edge.
- The plan, the form and the points table stack into one very long page.

**Visual system drift.**
- 9 font sizes (9–16 px; most text is 11–12 px, too small for a dashboard read at a distance).
- 13 spacing values (1–18 px), 9 radii, 6 breakpoints (520/640/820/900/960/1020).
- Dark tokens are written twice (media query and `[data-theme=dark]`).
- Duplicate helpers (`kv()` exists in `cards.ts` and `system.ts`), per-module ad-hoc chips.
- Mono font is used for prose (timeline hint, topology labels).

**i18n is partial.**
- With UK selected, the Map tab still shows ~40 English strings: legend, plan states,
  "Floor 1", "Ground", form labels ("Point", "Label", "Note"), placeholders, the points table
  header, "Measure here next", "Sessions at this point", "not planned".
- Static HTML labels without `data-i18n`: the measurement form, the points table, many
  `aria-label`s.
- Units and composites are built by string concatenation (`"(+" + n + " micro)"`,
  `" · busy " + n + "%"`), so word order and plurals cannot be translated.
- **The server sends English prose**: `verdict_summary`, `findings`, `patterns`,
  `observer_findings`, advice `title/evidence/recommendation`, audit `warnings`, episode
  `context`, event text. The UI cannot translate these at all (see decision D5).

**Panels that are always visible but rarely needed.** Router audit form with six adapters and
credential fields, CVE lookup, port chips, 8-row BSSID table, the "details" checkbox on events,
Export MD/JSON buttons. They push the useful content down.

**Ready backend features with no or weak UI.**
- `/api/compare` (cross-session, cross-point correlation): not used at all.
- RF estimate through walls: shown only as one grey sentence in the point info.
- Report export: two equal buttons at the top of the report, also for the live session where
  the file changes every second.

---

## 2. Design goals

1. **Answer first.** The first screen answers: *Is the connection OK now? If not, which hop
   (Wi-Fi, router, line, internet, this device)? Since when?* Everything else is evidence.
2. **One status model.** Exactly one function maps data to `{tone, label, reason}`. Every badge,
   border, map colour and pill uses it. Conflicts are shown as conflicts ("live: OK · session:
   3 Wi-Fi incidents"), never as two colours side by side without a word.
3. **Progressive disclosure.** Level 1: verdict and key numbers. Level 2: timeline, incidents,
   map. Level 3 (behind a disclosure or a separate view): raw events, BSSID table, router audit,
   CVE lookup, exports.
4. **One time context per view.** Live views are always live. History has its own view with its
   own selector. No mixed pages.
5. **Phone is a first-class target** (the probe is in a bedroom; the user walks around with a
   phone). 390 px with no sideways scroll, 44 px touch targets, a header of one row.
6. **Calm.** Colour only for state. Neutral chrome. No decoration that competes with data.

---

## 3. Information architecture

Four top-level views (hash routes, as now). Names change to describe the task, not the data:

| Route | Name (EN / UK) | Question it answers | Main content |
|---|---|---|---|
| `#now` | Now / Зараз | Is it OK right now, and where does it break? | Verdict hero, path strip, path rows, last incidents, current measurement |
| `#sessions` | Sessions / Сеанси | What happened during a night / at a point? | Session list, report, timeline, incidents, compare, export |
| `#map` | Map / План | Which rooms are measured and how do they compare? | Building + flat map, plan checklist, point details, start a measurement |
| `#diag` | Diagnostics / Діагностика | Why? (expert evidence) | Wi-Fi link + environment, observer health, router, LAN, events, router audit + CVE |

Old hashes (`#live`, `#wifi`, `#system`) redirect to the new ones.

Wi-Fi and System merge into **Diagnostics** with an in-page section nav (Wi-Fi · Router ·
Observer · Events · Audit). Reason: both are evidence views for experts; the non-technical
user never needs them on the first screen.

### 3.1 Header (all views)

One row, 56 px, sticky:

```
[linkwatch] [● live · B1/F2/R2 · 3 h 12 min]           [Verdict pill]  [⋯]
```

- Context chip: connection dot + current point + session duration. Click → `#map` point.
- Verdict pill: from the one status model. Click → `#now`.
- `⋯` menu: language, theme (Auto/Light/Dark as a radio group, not a cycling button), token
  state ("control: on / read-only"), version.
- "Switch point" leaves the header; it lives on `#now` (current measurement card) and `#map`.
- Desktop: tabs under the header row (as now). Phone: **bottom tab bar** with four icons +
  labels (see D2).

---

## 4. Views

### 4.1 Now (`#now`)

Desktop grid (12 columns, max 1200 px):

```
┌───────────────────────────── Verdict hero (12) ─────────────────────────────┐
│ ● Wi-Fi problem                                                             │
│ Cable is fine, Wi-Fi lost the router 3× in the last hour. Since 21:04.      │
│ [path strip:  This device ─ Wi-Fi ✕ ─ Router ✓ ─ Line ✓ ─ Internet ✓ ]     │
└─────────────────────────────────────────────────────────────────────────────┘
┌──── Paths (8) ─────────────────────────────┐┌──── Measurement (4) ─────────┐
│ wlo1 Wi-Fi   ● degraded  4 ms / 18 ms  -67 dBm  [spark 15 min] ›           ││ Bedroom 2 · Flat 6 · Block A│
│ enp1s0 Cable ● ok        1 ms / 15 ms           [spark 15 min] ›           ││ 3 h 12 of 8 h ▓▓▓░░░░        │
└────────────────────────────────────────────┘│ [Switch point]               │
┌──── Last hour (12): compact timeline, failure ticks only + RTT ──────────────┐└──────────────────────────────┘
┌──── Recent incidents (8): 5 latest, link "All in Sessions ›" ┐┌─ Speed (4) ─┐
```

- **Verdict hero**: tone stripe + one sentence from the verdict code (translated) + the path strip.
  The path strip replaces the current topology SVG: a horizontal list of hops (HTML, flex), each
  hop a status dot + label + latency. On phone it wraps to a vertical list. No fixed viewBox,
  no sideways scroll.
- **Path rows** replace the big cards: one row per interface, expandable (Disclosure) to show
  the current card content (DNS, failures, channel, retries). The sparkline stays, 15 min, inside
  the row.
- **Last hour**: one compact timeline for all paths (failure ticks per path, RTT line). Full
  ranges live in Sessions.
- **Recent incidents**: the 5 latest network incidents from the live report, each "time ·
  duration · cause". Observer incidents are counted in one muted line, not listed.

### 4.2 Sessions (`#sessions`)

```
┌ Sessions list (3) ───────┐┌ Report (9) ───────────────────────────────────────────┐
│ ● Live   B1/F2/R2  3 h   ││ Bedroom 2 · 26 Nov 22:04 – 27 Nov 07:10 · 9 h 6 min   │
│ ☐ Night 3 B1/F2/K  9 h   ││ [Verdict sentence]                          [Export ▾]│
│ ☐ Night 2 B1/F2/R6 8 h   ││ KPI row: Availability · Incidents · Router RTT ·      │
│ … filter: point / date   ││          Internet RTT · Wi-Fi signal                  │
│ [Compare selected (2)]   ││ Timeline (range 1 h…all) with incident highlights     │
└──────────────────────────┘│ Hourly profile (24 cells)                             │
                            │ Incidents (list, click → highlight on timeline)       │
                            │ ▸ Findings & patterns (disclosure)                    │
                            │ ▸ Events (disclosure, filter chips)                   │
                            └───────────────────────────────────────────────────────┘
```

- The list replaces the `<select>`. Phone: the list is the first screen; tap → report
  (back arrow returns).
- **Compare** (uses `/api/compare`): tick 2–8 sessions → a compare view: aligned KPI table
  (one column per session), shared-incident list ("same moment at 2 points → router or line"),
  tolerance control (default 2 s) under "Advanced". Export compare as MD.
- **Export** is a menu: "Report (Markdown)", "Report (JSON)". Disabled for a live session with
  < 60 s of data. Uses `<a download>` (works under CSP).
- KPI rules: one value per tile, unit in smaller text, a tone only when a threshold is crossed,
  ⓘ explains the threshold. No composite strings like `18 ms (p95 40 ms)` in one tile: p95 goes
  to the tile's secondary line.

### 4.3 Map (`#map`)

```
┌ Building (3) ┐┌ Flat plan (6) ──────────────────────┐┌ Point details (3) ────────┐
│ Block A B    ││ SVG plan, rooms coloured by metric  ││ Bedroom 2 · B1/F2/R2      │
│ F3 [5][6]    ││ layer toggles: Status | Availability││ ● Partly measured 3/8 h   │
│ F2 [3][4]    ││   | Drops/h | RF estimate           ││ Availability 99.2 %       │
│ F1 [1][2]    ││ router ◆ · probe ● · selected room  ││ RF: 7.4 m · 2 walls · ~9dB│
│              ││ RF ray from router to selected room ││ Sessions at this point…   │
│              ││ legend (compact, one row)           ││ [Measure here next]       │
└──────────────┘└─────────────────────────────────────┘└───────────────────────────┘
┌ Plan checklist (12): progress per planned point, "also measured" collapsed ────────┐
┌ ▸ Points table (disclosure; same data as the checklist, sortable) ─────────────────┐
```

- **Start a measurement** moves into a dialog/sheet opened by "Switch point" or "Measure here
  next". The current inline form is always visible today and takes half the column.
  Confirmation stays explicit ("This closes the session at … and starts one at …").
- **RF estimate** becomes a map layer: a dashed line from the router to the selected room, wall
  crossings marked with small ticks, the dB estimate as a label. Details only in the side panel.
- **Above/Below floor** overlay stays, but as one toggle "Show floor above/below" in the layer
  menu, not a three-button group.
- Without a site file: the map is replaced by a points list (free-text points) with the same
  details panel. No empty map frame.
- Phone: Building strip becomes a horizontal chip row; plan full width; details as a bottom sheet.

### 4.4 Diagnostics (`#diag`)

Section nav (sticky chips): **Wi-Fi · Router · Observer · Events · Audit**.

- **Wi-Fi**: link facts (one KV card per Wi-Fi interface), spectrum (2.4 / 5 GHz), scan table.
  Table defaults to "our network + strongest 5 others"; "Show all N" expands. BSSIDs show only
  the last 3 octets by default (privacy when the screen is shared); full value on click.
- **Router**: UPnP telemetry, uptime, WAN rate.
- **Observer**: host health (CPU, temp, throttling, clock), LAN device count.
- **Events**: the full event log with filter chips (moved from the Now view).
- **Audit** (collapsed by default, needs token): router probe form and CVE lookup. Never runs
  on page load (see backend finding B1).
- **Recommendations** (advisor) move to the top of Diagnostics, and the verdict-based items
  also appear in the Now hero ("What to try"), so there is no "no issues" while the verdict is
  bad (finding 1.2).

---

## 5. Status model (one source of truth)

`status.ts` exports:

```ts
type Tone = "ok" | "warn" | "bad" | "info" | "neutral";
interface Status { tone: Tone; label: MsgKey; reason?: Msg; since?: string }
function verdictStatus(v: Verdict | null): Status;
function pathStatus(s: IfaceStatus): Status;     // state + last probe + debounce
function planStatus(p: PlanItem): Status;
function metricTone(kind: MetricKind, value: number): Tone; // thresholds in one table
```

Rules:

- A path that is `ok` by the debounced state but has a failed last probe shows `ok` with a muted
  "last probe failed" note, not a red badge next to a green number.
- Thresholds (availability 99.9 / 99.0 %, signal −67 / −75 dBm, busy 50 / 70 %, RTT …) live in
  one table that the ⓘ tips also read, so the tip text and the colour always agree.
- Colour is never the only carrier: every tone has a text label and, on maps, a pattern/outline.

---

## 6. Design tokens

Defined once in `:root` using `light-dark()` (decision D3), with `[data-theme]` forcing
`color-scheme`.

| Token group | Values |
|---|---|
| Type scale | 12 (caption) · 13 (secondary) · 14 (body) · 16 (section title) · 20 (view title) · 28 (hero value). Line-height 1.45 body, 1.2 numbers. Max 3 sizes per component. |
| Weight | 400 body, 600 titles and values. |
| Spacing | 4 · 8 · 12 · 16 · 24 · 32 (`--s1`…`--s6`). Nothing else. |
| Radius | 6 (controls, chips) · 10 (cards). Pills 999. |
| Breakpoints | 600 (phone → tablet), 960 (tablet → desktop), 1280 (max width 1200 content). |
| Layout | 12-column grid on ≥ 960, 4-column on < 600, gap 16 (desktop) / 12 (phone). |
| Colour | `--bg --surface --surface-2 --text --text-2 --border --accent` + tones `--ok/--warn/--bad/--info/--neutral` each with `-bg` and `-fg`. Data series: `--s-gw --s-net --s-sig --s-busy --s-lan`. WCAG AA (4.5:1) for text on its background in both themes; checked by a small script in `npm run check`. |
| Mono | only for ids, addresses and aligned numbers in tables. Never for prose. |
| Touch | interactive elements ≥ 44 × 44 px on < 600 px. |

---

## 7. Components

All in `src/web/ui/src/ui/` (new folder), each a function that returns an element; no classes,
no virtual DOM. Every component has: default, loading, empty, error (with retry) states where
it loads data.

| Component | Purpose | Notes |
|---|---|---|
| `Badge(status)` | state label | from the status model only |
| `Pill(status)` | header verdict | clickable variant |
| `Card({title, actions, body})` | the one panel container | header 44 px, optional disclosure |
| `Kpi({label, value, unit, sub, tone, tip})` | one number | value 28/20 px, sub line 12 px |
| `KpiRow(kpis)` | 2–6 KPIs | wraps 2 per row on phone |
| `PathStrip(hops)` | hop chain | HTML flex, wraps to vertical |
| `PathRow(iface)` | expandable interface row | Disclosure inside |
| `Sparkline`, `TimelineChart`, `HourlyStrip` | charts | canvas; colours from tokens; pointer + keyboard (←/→) inspection; text summary for screen readers |
| `IncidentItem`, `EventItem` | list rows | time · duration · cause · origin |
| `Segmented(options)` | 2–6 exclusive choices | `role=radiogroup`, arrows |
| `FilterChips(options)` | multi or single filter | count per chip |
| `DataTable({columns, rows, sort})` | tables | sticky header, numeric alignment, collapses to label/value cards < 600 px |
| `Disclosure(summary, body)` | progressive disclosure | `<details>`; remembers open state per id in `localStorage` |
| `InfoTip(key)` | ⓘ popover | `<button aria-describedby>`; stays inside viewport (flip/shift); Esc closes |
| `Banner({tone, text, action, dismiss})` | page-level notice | token missing, data gap, disk pressure |
| `EmptyState({title, hint, action})` | no data | always says *why* and *what next* |
| `ErrorState({message, retry})` | fetch failed | shows HTTP status; retry button |
| `Skeleton(lines)` | loading | CSS-only shimmer (disabled under reduced motion) |
| `Toast` | result of an action | `role=status`, 4 s |
| `Dialog` / `Sheet` | measurement form, compare | `<dialog>` element (CSP-safe), focus trap, Esc |
| `Field({label, hint, error})` | form input | label always visible, error under field |
| `Menu(items)` | ⋯ and Export | `<button aria-haspopup>` + list, keyboard |
| `KvList(rows)` | key/value facts | replaces the two `kv()` copies |
| `ProgressBar(value, target)` | plan progress | `role=progressbar` |
| `MapView({unit, layer, selected})` | flat plan SVG | layers: status, availability, drops, RF ray |
| `BuildingStrip(building)` | floor/flat picker | grid on desktop, chips on phone |

---

## 8. Interaction rules

- **Click a KPI** → scroll to and highlight the chart or list that explains it.
- **Click an incident** → in Sessions: highlight on the timeline and scroll to it; from Now:
  open Sessions at that time.
- **Hover/tap a chart** → crosshair + value bubble anchored to the chart (not a line of mono
  text below it). Keyboard: focus the chart, ←/→ move one minute, Esc clears.
- **Switch session** (Sessions list) → only the report column changes; URL keeps
  `#sessions/<id>` so it can be shared and reloaded.
- **Start a measurement** → dialog; confirm; on success a toast and the header context chip
  update; on 429 the dialog shows the wait time; on 401 a banner explains the token.
- **Read-only mode** (no token): action buttons are hidden, not disabled-without-reason. One
  muted line in the ⋯ menu says "Read-only: open with ?token=… to control".
- **Language change** re-renders in place; no reload; dates and numbers use `Intl` with the
  selected locale.
- **Loading**: skeletons for the first load only; later refreshes update in place without
  flashing. A stale indicator appears on a card when its data is older than 2× its refresh
  interval.
- **Nothing on screen without need**: no "Point at the timeline…" hints after the first use,
  no empty panels (hide or show an EmptyState with a reason), no buttons that do nothing in the
  current mode.

---

## 9. Decisions for the owner

| # | Question | Proposal |
|---|---|---|
| D1 | Merge Wi-Fi + System into one **Diagnostics** view, and add a **Sessions** view (history out of Live)? | Yes |
| D2 | Phone navigation: bottom tab bar or top scrollable tabs? | Bottom bar (thumb reach, header stays one row) |
| D3 | Use CSS `light-dark()` (Chrome 123+, Safari 17.5+, Firefox 120+) to define colours once? Old browsers would get the light theme only. | Yes |
| D4 | Replace the topology SVG with an HTML path strip (wraps on phone, translatable labels)? | Yes |
| D5 | Server prose (verdict summary, findings, advice, warnings, event text) → add stable `code` + `args` to the API next to the English `text`, and translate in the UI. This is a backend change in `api.rs`, `router/advice.rs`, `analyze`, `router/audit.rs`. | Yes, in a separate step before the UI rewrite |
| D6 | Read access: today a configured token gates **everything**. Earlier the owner wanted open viewing and token-only control. Add `[web] view = "open" \| "token"` (default `token`)? | Yes |
| D7 | Router audit + CVE lookup: keep in the UI under Diagnostics › Audit (collapsed, token only), or remove from the UI and keep as CLI? | Keep, collapsed |
| D8 | Masked BSSIDs/MACs on screen by default (click to reveal)? | Yes |
| D9 | Implementation order: (1) backend fixes from the review, (2) codes for i18n (D5), (3) tokens + components, (4) Now, (5) Sessions + compare, (6) Map, (7) Diagnostics, (8) a11y/contrast/CSP checks. Each step: `npm run check`, `npm run build`, CSP grep, screenshots at 1440 dark / 390 light. | Yes |

---

## 10. Acceptance checks (stage 2)

- `npm run check`, `npm run build` clean; `dist/` committed and current.
- CSP grep in CI: no `innerHTML|outerHTML|insertAdjacentHTML|eval(|new Function|\.style\.|style=`
  in `src/web/ui/src` and `index.html`.
- i18n check: a script fails when a string literal with letters reaches `text:`/`textContent`
  or a child argument of `el()` without `t()`, and when a UK key is missing (warning, not error).
- At 390 px: `document.documentElement.scrollWidth === innerWidth` on every view.
- Contrast: every text/background token pair ≥ 4.5:1 in both themes.
- Keyboard: every action reachable with Tab; visible focus ring; dialogs trap focus.
- Screenshots of each view (1440 dark, 390 light, UK) attached to the PR.

---

## 11. Interaction and motion (proposal, stage 3)

Stage 2 fixed *what* is on each screen. This section decides *how it behaves*: what a click,
a drag, a hover and a key do, and which changes move. Nothing here is built yet.

### 11.1 Principles

1. **Motion explains a change; it never decorates.** Something moves only when it changes place
   or state (a panel opens, an incident is focused, a verdict gets worse). Live numbers do not
   count up or bounce.
2. **Short and calm.** 120–200 ms, ease-out for entering, ease-in for leaving. One property at a
   time (opacity or transform), never layout properties.
3. **Reduced motion is a first-class mode.** `prefers-reduced-motion`: no movement, only
   instant state change or opacity.
4. **Every gesture has a key and a button.** Drag, hover and long-press are shortcuts; there is
   always a visible control that does the same.
5. **Direct manipulation only where position *is* the data:** the floor plan and the time axis.
   Lists (plan, sessions) are not dragged.

### 11.2 Input vocabulary (the same everywhere)

| Input | Meaning | Never |
|---|---|---|
| Click / tap | select or open | start a measurement, delete (those always confirm) |
| Hover | preview only (crosshair, tooltip) | the only way to see a value |
| Double-click | — (not used: hard on touch, easy to trigger by accident) | |
| Long-press (touch) | the hover preview of desktop | |
| Drag | change a position or a range | reorder lists |
| Esc | close the topmost layer (tip → menu → sheet → dialog) | |
| ← / → on a focused chart | move one minute; Shift = 10 min | |

### 11.3 Where drag helps (and where it does not)

| Place | Drag does | Without drag | Value |
|---|---|---|---|
| **Timeline** | brush a time range → zoom; incidents list filters to it | range buttons, keyboard | high: "what happened 02:10–02:40" is the core question |
| **Floor plan** | pan; pinch / wheel zoom (phone and desktop) | +/− buttons, fit | medium: plans of 12 × 12 m are small on a phone |
| **Layout editor** (pending feature) | move/resize rooms, walls, doors, points; snap to a 0.1 m grid and to other walls; Alt = no snap | numeric fields in a side panel | high, but only inside the editor |
| **Phone sheets** (point details, dialog) | swipe down to close | close button, Esc | low, expected by phone users |
| Plan checklist, sessions | — | — | dragging adds risk, no value |

### 11.4 Motion catalogue

| Event | Motion | Duration |
|---|---|---|
| View switch | content fades in; no slide (views are not a sequence) | 120 ms |
| Verdict worsens | hero colour cross-fades; the stripe pulses **once** | 200 ms + 1 pulse |
| New incident (live) | row slides in from top, highlighted for 2 s | 160 ms |
| Incident → timeline | smooth scroll, then a ring pulses on the minute | scroll + 600 ms |
| Map selection | room stroke thickens; RF ray draws from router to room | 180 ms |
| Dialog / sheet | fade + scale 0.98 → 1 (desktop), slide up (phone) | 150 ms |
| Menu, tooltip | fade only | 100 ms |
| Data refresh | none (values change in place); a stale dot after 2× refresh time | — |

### 11.5 Technical options (decision needed)

The CSP and the "no `.style`" rule shape what is possible:

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. CSS-only** | state classes + `transition`; drag only in SVG (`transform` attribute) | no new rules, smallest code | no FLIP list animations; HTML elements cannot follow the pointer |
| **B. A + Web Animations API** | `element.animate()` for FLIP and sheets; CSP does not cover it | smooth list and sheet motion, still no inline styles | relaxes our own "no `.style`" rule in spirit; needs a small `motion.ts` with a reduced-motion guard |
| **C. B + view transitions** | `document.startViewTransition()` for view switches | native cross-fades between views | Chrome/Safari only; Firefox falls back to instant |

Recommendation: **B** (with A as the fallback when the API is missing). It keeps the CSP strict and
puts all motion in one audited module.

### 11.6 Component layer (decision needed)

| Option | Idea | Fit |
|---|---|---|
| **1. Keep functions + `el()`** (today) | components are functions that return elements; full re-render per update | simplest; re-renders lose focus/scroll and make animation hard |
| **2. Small keyed renderer + signals** | ~300 lines: `signal()`, `effect()`, keyed list patching | animations and focus survive updates; still no framework |
| **3. Web Components** | custom elements with constructable stylesheets | native encapsulation, CSP-friendly; heavier boilerplate, styling across shadow roots is harder |

Recommendation: **2**. Motion (11.4) needs elements that survive updates; a keyed patch is the
smallest way to get that.

### 11.6a Decision after review (27.11)

The review argued, and the owner's direction agrees: **option A** for motion (CSS transitions,
`@starting-style`, SVG attributes, a small canvas `requestAnimationFrame` loop) and **no
reactive framework**. The per-second re-render problem is solved by `patch()` in `dom.ts`
(in-place update of existing nodes, `data-key` for rows bound to one record).

### 11.7 Order

1. Stage 2 gaps (list above), starting with the 1-hour timeline on Now.
2. Timeline brush (drag a range), ←/→ keys and a value bubble at the pointer.
3. Plan pan/zoom through the SVG `viewBox` (phones).
4. Calm CSS transitions from the catalogue (11.4).
5. Layout editor with snapping, as a separate later module (its own design pass first).
