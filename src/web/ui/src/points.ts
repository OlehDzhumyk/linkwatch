// Measurement points: plan status, result colours, and the sessions recorded at a point.
// Used by the site map (site.ts), the Measurements panel (measure.ts) and the Now view.

import type { PlanItem } from "./api/PlanItem.js";
import type { PlanStatus } from "./api/PlanStatus.js";
import type { SessionEntry } from "./api/SessionEntry.js";
import { el } from "./dom.js";
import { type Tone, fmtDur, fmtTime, verdictLabel } from "./format.js";
import { type MsgKey, t, tPlural } from "./i18n.js";
import { LIVE, bus, state } from "./state.js";
import { availTone, dropsTone } from "./status.js";

export { availTone, dropsTone };

const STATUS_KEY: { readonly [K in PlanStatus]: MsgKey } = {
  todo: "plan.todo",
  active: "plan.active",
  partial: "plan.partial",
  done: "plan.done",
};
export const STATUS_TONE: { readonly [K in PlanStatus]: Tone } = {
  todo: "neutral",
  active: "info",
  partial: "warn",
  done: "ok",
};

export function statusText(s: PlanStatus): string {
  return t(STATUS_KEY[s]);
}

export function planItem(point: string): PlanItem | undefined {
  return state.plan?.items.find((i) => i.point === point);
}

/** CSS class of a map shape for the selected colour mode: `st-<status>` or `res-<tone>`. */
export function pointClass(point: string): string {
  const it = planItem(point);
  if (state.colorMode === "status") return it ? "st-" + it.status : "st-none";
  const tone = state.colorMode === "availability" ? availTone(it?.availability_pct) : dropsTone(it?.drops_per_h);
  return "res-" + (tone ?? "none");
}

/** Short text of the result of a point for the selected colour mode. */
export function resultText(it: PlanItem | undefined): string {
  if (!it) return "";
  if (state.colorMode === "availability") {
    return it.availability_pct === null ? t("plan.no_result") : t("plan.avail_val", { v: it.availability_pct.toFixed(2) });
  }
  if (state.colorMode === "drops") {
    return it.drops_per_h === null ? t("plan.no_result") : t("plan.drops_val", { v: it.drops_per_h.toFixed(1) });
  }
  return statusText(it.status);
}

export function fmtHours(s: number): string {
  const h = s / 3600;
  return t("u.h", { n: h < 10 ? h.toFixed(1) : String(Math.round(h)) });
}

/** "Bedroom 3 · Flat 2 · Block A" from the plan, else the point id. */
export function pointLabel(point: string | null | undefined): string {
  if (!point) return t("ctx.no_point");
  const it = planItem(point);
  if (!it || it.name === point) return point;
  return [it.name, it.unit_label, it.building_name].filter((x): x is string => Boolean(x)).join(" · ");
}

/** Measured / planned text, e.g. "3.5 h of 8 h" or "3.5 h measured". */
export function progressText(it: PlanItem): string {
  return it.target_s !== null
    ? t("plan.of", { a: fmtHours(it.measured_s), b: fmtHours(it.target_s) })
    : t("plan.measured", { a: fmtHours(it.measured_s) });
}

export function sessionsText(n: number): string {
  return tPlural("plan.session_one", "plan.session_other", n);
}

export function statusChip(status: PlanStatus): HTMLElement {
  return el("span", { class: "pill small " + STATUS_TONE[status], text: statusText(status) });
}

export function sessionsAt(point: string): SessionEntry[] {
  return state.sessions.filter((s) => s.point === point);
}

/** Opens a session in the Sessions view (LIVE for the running one). */
export function viewSession(id: string): void {
  state.selectedSession = id;
  state.rangeUserSet = true;
  state.highlightTs = null;
  bus.dispatchEvent(new CustomEvent("switch-tab", { detail: "sessions" }));
  bus.dispatchEvent(new Event("session-selected"));
}

/** One block per session at `point`, newest first: time, duration, verdict, availability, note. */
export function sessionList(point: string): HTMLElement[] {
  const list = sessionsAt(point);
  if (!list.length) return [el("div", { class: "empty", text: t("plan.no_sessions") })];
  return list.map((s) => {
    const [vText, vTone] = s.verdict ? verdictLabel(s.verdict) : [t("plan.no_summary"), "neutral" as Tone];
    const facts: string[] = [];
    if (s.availability_pct !== null) facts.push(t("plan.avail_val", { v: s.availability_pct.toFixed(2) }));
    if (s.drops_per_h !== null) facts.push(t("plan.drops_val", { v: s.drops_per_h.toFixed(1) }));
    return el("div", { class: "sess" },
      el("div", { class: "row" },
        el("b", { text: s.label || s.id }),
        el("span", { class: "pill small " + (s.current ? "info" : vTone), text: s.current ? t("plan.active") : vText })),
      el("div", { class: "muted small", text: fmtTime(s.started) + " · " + fmtDur(s.duration_s) }),
      facts.length ? el("div", { class: "small", text: facts.join(" · ") }) : null,
      s.note ? el("div", { class: "small note", text: s.note }) : null,
      el("button", {
        type: "button",
        class: "ctrl link-btn",
        text: t("plan.open_session"),
        onclick: () => viewSession(s.current ? LIVE : s.id),
      }));
  });
}
