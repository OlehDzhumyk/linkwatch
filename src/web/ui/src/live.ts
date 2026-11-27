// Status polling and live updates (server-sent events).

import type { Envelope } from "./api/Envelope.js";
import type { IfaceStatus } from "./api/IfaceStatus.js";
import { renderCards, renderHeader, recordSamplePoint } from "./cards.js";
import { fetchStatus, parseEnvelope } from "./client.js";
import { byId } from "./dom.js";
import { loadEvents, loadSpeed, renderEvents } from "./events.js";
import { LIVE, bus, state } from "./state.js";
import { t } from "./i18n.js";
import { renderHero } from "./now.js";
import { loadLiveReport, renderReport } from "./report.js";
import { renderSystem, renderSystemEvents } from "./system.js";
import { loadMinutes, renderTimelines } from "./timeline.js";
import { loadScan, renderTopology, renderWifiLink } from "./wifi.js";

/** Events kept in memory for the live list (as the server keeps). */
const EVENTS_KEPT = 2000;
const RETRY_MIN_MS = 1000;
const RETRY_MAX_MS = 30000;

export function syncRangeButtons(): void {
  for (const x of byId("range").querySelectorAll<HTMLButtonElement>("button")) {
    x.classList.toggle("on", Number(x.dataset["h"]) === state.hours);
  }
}

export async function loadStatus(): Promise<void> {
  const first = !state.status;
  const before = state.status?.session?.session;
  const r = await fetchStatus();
  if (!r) {
    updateStaleState();
    return;
  }
  state.status = r;
  state.lastUpdateMs = Date.now();
  updateStaleState();
  if (!first && r.session?.session !== before) bus.dispatchEvent(new Event("session-change"));
  if (!state.rangeUserSet && state.selectedSession === LIVE && r.started) {
    const ageMs = Date.now() - new Date(r.started).getTime();
    if (isFinite(ageMs) && ageMs < 2 * 3600e3 && state.hours !== 1) {
      state.hours = 1;
      syncRangeButtons();
      if (!first) void loadMinutes();
    }
  }
  renderHeader();
  renderCards();
  renderHero();
  renderWifiLink();
  renderSystem();
  renderReport();
}

let es: EventSource | null = null;
let retry = RETRY_MIN_MS;
let cardTimer: ReturnType<typeof setTimeout> | null = null;

/** Re-renders header, cards and Wi-Fi link summary at most once a second. */
function scheduleCards(): void {
  if (cardTimer) return;
  cardTimer = setTimeout(() => { cardTimer = null; renderHeader(); renderCards(); renderHero(); renderWifiLink(); }, 1000);
}

const STALE_AFTER_MS = 60_000;

export function updateStaleState(): void {
  const stale = state.lastUpdateMs > 0 && Date.now() - state.lastUpdateMs > STALE_AFTER_MS;
  byId("now-stale").hidden = !stale;
  const conn = byId("conn");
  const wrap = byId("conn-wrap");
  const txt = byId("conn-txt");
  if (stale) {
    conn.className = "conn stale";
    wrap.title = t("conn.stale");
    txt.textContent = t("conn.stale");
  } else {
    conn.className = "conn " + (state.live ? "live" : "down");
    const key = state.live ? "conn.live" : "conn.reconnecting";
    wrap.title = t(key);
    txt.textContent = t(key);
  }
}

function setConn(ok: boolean): void {
  state.live = ok;
  updateStaleState();
}

/** Live entry of an interface; created when the feed names one the status does not have yet. */
function ifaceOf(name: string): IfaceStatus | null {
  const s = state.status;
  if (!s) return null;
  let i = s.ifaces[name];
  if (!i) {
    i = {
      name, role: null, state: null, state_since: null, last: null, wifi: null, channel_load: null,
      minutes_count: 0, ticks: 0, gw_fail: 0, net_fail: 0, down_s: 0,
    };
    s.ifaces[name] = i;
  }
  return i;
}

function onEnvelope(env: Envelope): void {
  state.lastUpdateMs = Date.now();
  updateStaleState();
  switch (env.type) {
    case "sample": {
      recordSamplePoint(env);
      const i = ifaceOf(env.iface);
      if (!i) break;
      i.last = env;
      i.role = env.role;
      scheduleCards();
      break;
    }
    case "wifi": {
      const i = ifaceOf(env.iface);
      if (i) { i.wifi = env; scheduleCards(); }
      break;
    }
    case "channel_load": {
      const i = ifaceOf(env.iface);
      if (i) { i.channel_load = env; scheduleCards(); }
      break;
    }
    case "scan":
      void loadScan();
      break;
    case "speed":
      void loadSpeed();
      break;
    case "host":
      if (state.status) {
        state.status.host = env;
        renderSystem();
        renderTopology();
      }
      break;
    case "router":
      if (state.status) {
        state.status.router = env;
        renderTopology();
        renderSystem();
      }
      break;
    case "lan":
      if (state.status) {
        state.status.lan = env;
        renderTopology();
        renderSystem();
      }
      if (state.selectedSession === LIVE) {
        const cutoff = Date.now() - state.hours * 3600e3;
        state.lanSeries.push({
          t: env.ts,
          arp_alive: env.arp_alive,
          ping_alive: env.ping_alive,
          unique_seen: env.unique_seen,
        });
        state.lanSeries = state.lanSeries.filter((p) => new Date(p.t).getTime() >= cutoff);
        renderTimelines();
      }
      break;
    case "event":
      if (state.selectedSession === LIVE) {
        state.events.unshift(env);
        if (state.events.length > EVENTS_KEPT) state.events.length = EVENTS_KEPT;
        renderEvents();
        renderSystemEvents();
      }
      if (env.kind === "state_change" || env.kind === "verdict_change" || env.kind === "start" || env.kind === "dropped_records") {
        void loadStatus();
        if (env.kind === "state_change" || env.kind === "verdict_change") void loadLiveReport();
      }
      break;
    default:
      break;
  }
}

export function connect(): void {
  if (es) es.close();
  const src = new EventSource("/api/live");
  es = src;
  src.onopen = () => { retry = RETRY_MIN_MS; setConn(true); };
  src.onmessage = (m: MessageEvent<unknown>) => {
    if (typeof m.data !== "string") return;
    const env = parseEnvelope(m.data);
    if (!env) return;
    try {
      onEnvelope(env);
    } catch {
      // One odd record must not stop the live feed; the next poll repairs the view.
    }
  };
  src.addEventListener("lagged", () => {
    void loadStatus();
    if (state.selectedSession === LIVE) void loadEvents();
  });
  src.onerror = () => {
    setConn(false);
    if (src.readyState === EventSource.CLOSED) {
      src.close();
      if (es === src) es = null;
      setTimeout(connect, retry);
      retry = Math.min(retry * 2, RETRY_MAX_MS);
    }
  };
}
