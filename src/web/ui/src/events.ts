// Event list and speed test table.

import type { Envelope } from "./api/Envelope.js";
import { fetchEvents, fetchSpeed } from "./client.js";
import { byId, el } from "./dom.js";
import { type EventCategory, type EventSeverity, describe, fmtTime } from "./format.js";
import { t } from "./i18n.js";
import { bus, state } from "./state.js";

/** Most event lines shown. */
const MAX_SHOWN = 300;

// ---------- events ----------

function eventMatchesFilter(sev: EventSeverity, cat: EventCategory): boolean {
  const f = state.evFilter;
  if (f === "all") return true;
  if (f === "important") return sev !== "detail" || state.showAll;
  if (cat === f) return sev !== "detail" || state.showAll;
  return false;
}

export function makeEventItem(env: Envelope): { item: HTMLLIElement; sev: EventSeverity; cat: EventCategory } {
  const [text, sev, cat] = describe(env);
  const item = el("li", { class: sev === "detail" ? "" : sev },
    el("time", { datetime: env.ts, text: fmtTime(env.ts) }),
    el("span", { class: "txt", text }));
  return { item, sev, cat };
}

export function fillEventList(box: HTMLElement, countEl: HTMLElement, items: HTMLLIElement[], emptyMsg: string): void {
  countEl.textContent = String(items.length);
  if (!items.length) items.push(el("li", { class: "empty" }, el("span", { text: emptyMsg })));
  box.replaceChildren(...items);
}

export function renderEvents(): void {
  const items: HTMLLIElement[] = [];
  for (const env of state.events) {
    const { item, sev, cat } = makeEventItem(env);
    if (!eventMatchesFilter(sev, cat)) continue;
    items.push(item);
    if (items.length >= MAX_SHOWN) break;
  }
  fillEventList(byId("events"), byId("ev-count"), items, t("events.empty"));
}

export async function loadEvents(): Promise<void> {
  const r = await fetchEvents(state.selectedSession);
  if (r) {
    state.events = r.events;
    renderEvents();
    bus.dispatchEvent(new Event("events-change"));
  }
}

// ---------- speed ----------

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url || "";
  }
}

export function renderSpeed(): void {
  const rows = state.speed.slice(0, 8).map(({ t: ts, result: r }) => {
    const mb = (r.bytes / 1048576).toFixed(1);
    const secs = r.secs.toFixed(1);
    const srv = hostOf(r.url);
    return el("tr", { title: t("speed.row_tip", { mb, s: secs }) },
      el("td", { text: fmtTime(ts) }),
      el("td", { class: "mono", text: r.iface }),
      el("td", { class: "num", text: r.mbps !== undefined ? r.mbps.toFixed(0) : "–" }),
      el("td", { class: "col-wide", text: srv }),
      el("td", { class: r.err ? "err" : "ok", text: r.err ? r.err : t("speed.ok") }));
  });
  if (!rows.length) rows.push(el("tr", null, el("td", { colspan: 5, class: "empty", text: t("speed.empty") })));
  const body = byId("speed", HTMLTableElement).tBodies.item(0);
  if (body) body.replaceChildren(...rows);
}

export async function loadSpeed(): Promise<void> {
  const r = await fetchSpeed();
  if (r) {
    state.speed = r.speed;
    renderSpeed();
  }
}
