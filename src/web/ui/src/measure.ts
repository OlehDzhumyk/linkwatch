// Measurements panel (Map view): where the box measures now, the plan checklist with progress,
// and the dialog that starts a measurement at another point (two steps: choose, confirm).

import type { PlanItem } from "./api/PlanItem.js";
import { type SessionRequestBody, fetchControl, fetchPlan, postSession } from "./client.js";
import { byId, el } from "./dom.js";
import { fmtDur, fmtTime, secsSince } from "./format.js";
import { t } from "./i18n.js";
import { fmtHours, pointLabel, progressText, sessionList, sessionsText, statusChip } from "./points.js";
import { focusPoint, renderSite } from "./site.js";
import { bus, state } from "./state.js";

/** Free-text point ids without a site file (same rule as the server). */
const FREE_POINT = /^[A-Za-z0-9 _./-]{1,64}$/;

type MsgTone = "ok" | "bad" | "info";

function message(id: "meas-msg" | "meas-dlg-msg", text: string, tone: MsgTone): void {
  const m = byId(id);
  m.textContent = text;
  m.className = "msg small " + tone;
  m.hidden = text === "";
}

/** Point, label, note and start of the running session (control answer, else status). */
function current(): { point: string | null; label: string | null; note: string | null; started: string | null } {
  const c = state.control;
  if (c) return { point: c.point, label: c.label, note: c.note, started: c.started };
  const s = state.status?.session;
  return { point: s?.point ?? null, label: s?.label ?? null, note: s?.note ?? null, started: s?.started ?? null };
}

export function renderMeasureCurrent(): void {
  const c = current();
  const rows: [string, string][] = [[t("map.f_point"), c.point ? pointLabel(c.point) : t("ctx.no_point")]];
  if (c.point && pointLabel(c.point) !== c.point) rows.push([t("map.f_point_id"), c.point]);
  if (c.label) rows.push([t("map.f_label"), c.label]);
  if (c.note) rows.push([t("map.f_note"), c.note]);
  if (c.started) {
    rows.push([t("map.f_started"), fmtTime(c.started)]);
    rows.push([t("map.f_duration"), fmtDur(secsSince(c.started))]);
  }
  byId("meas-current").replaceChildren(...rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]));
}

/** Options of the point picker: one group per flat (building › flat), rooms and probe points. */
function fillPicker(): void {
  const sel = byId("meas-point", HTMLSelectElement);
  const keep = sel.dataset["touched"] === "1" ? sel.value : (current().point ?? "");
  const groups: HTMLElement[] = [el("option", { value: "", text: t("map.no_point_opt") })];
  const plannedHours = new Map((state.plan?.items ?? []).filter((i) => i.target_s !== null).map((i) => [i.point, i.target_s ?? 0]));
  for (const b of state.site?.buildings ?? []) {
    for (const f of [...b.floors].sort((x, y) => x.floor - y.floor)) {
      for (const u of f.units) {
        const opts: HTMLElement[] = [];
        for (const r of u.rooms) {
          if (!r.full_id) continue;
          const h = plannedHours.get(r.full_id);
          opts.push(el("option", { value: r.full_id, text: r.name + (h !== undefined ? " · " + t("map.planned", { h: fmtHours(h) }) : "") }));
        }
        for (const p of u.points) {
          if (p.kind !== "probe" && p.kind !== "other") continue;
          opts.push(el("option", { value: p.full_id, text: p.name + " (" + t("map.point_kind") + ")" }));
        }
        if (opts.length) groups.push(el("optgroup", { label: b.name + " › " + u.label + " (" + t("map.floor_n", { n: f.floor }) + ")" }, ...opts));
      }
    }
  }
  sel.replaceChildren(...groups);
  sel.value = [...sel.options].some((o) => o.value === keep) ? keep : "";
  byId("meas-points").replaceChildren(...(state.control?.known_points ?? []).map((p) => el("option", { value: p })));
}

export function renderMeasure(): void {
  renderMeasureCurrent();
  const c = state.control;
  const enabled = Boolean(c?.enabled);
  const pill = byId("meas-mode");
  pill.textContent = c ? t(enabled ? "map.control_on" : "map.read_only") : "";
  pill.className = "pill small " + (enabled ? "ok" : "neutral");
  byId("meas-open").hidden = !enabled;
  const reason = byId("meas-reason");
  reason.hidden = enabled || !c;
  reason.textContent = c?.reason ? t("map.why_read_only", { r: c.reason }) : "";
  const site = Boolean(c?.site);
  byId("meas-point-wrap").hidden = !site;
  byId("meas-text-wrap").hidden = site;
  if (enabled) fillPicker();
}

function chosen(): SessionRequestBody | string {
  const site = Boolean(state.control?.site);
  const point = site ? byId("meas-point", HTMLSelectElement).value : byId("meas-point-text", HTMLInputElement).value.trim();
  const label = byId("meas-label", HTMLInputElement).value.trim();
  const note = byId("meas-note", HTMLInputElement).value.trim();
  if (!site && point && !FREE_POINT.test(point)) return t("map.err_point");
  if (label.length > 200 || note.length > 200) return t("map.err_len");
  const body: SessionRequestBody = {};
  if (point) body.point = point;
  if (label) body.label = label;
  if (note) body.note = note;
  return body;
}

let pending: SessionRequestBody | null = null;

function setStep(confirm: boolean): void {
  byId("meas-confirm").hidden = !confirm;
  byId("meas-start").hidden = confirm;
  byId("meas-yes").hidden = !confirm;
  for (const id of ["meas-point", "meas-point-text", "meas-label", "meas-note"]) {
    const f = byId(id);
    if (f instanceof HTMLInputElement || f instanceof HTMLSelectElement) f.disabled = confirm;
  }
}

function showConfirm(body: SessionRequestBody): void {
  pending = body;
  const c = current();
  byId("meas-confirm-text").textContent = t("map.confirm", {
    from: pointLabel(c.point),
    d: c.started ? fmtDur(secsSince(c.started)) : "–",
    to: pointLabel(body.point),
  });
  setStep(true);
  byId("meas-yes", HTMLButtonElement).focus();
}

/** Opens the dialog, optionally with a point already chosen. */
export function openMeasureDialog(point?: string): void {
  if (!state.control?.enabled) return;
  const dlg = byId("meas-dialog", HTMLDialogElement);
  pending = null;
  setStep(false);
  message("meas-dlg-msg", "", "info");
  fillPicker();
  if (point !== undefined) {
    if (state.control.site) {
      const sel = byId("meas-point", HTMLSelectElement);
      sel.value = point;
      sel.dataset["touched"] = "1";
    } else {
      byId("meas-point-text", HTMLInputElement).value = point;
    }
  }
  if (!dlg.open) dlg.showModal();
  (state.control.site ? byId("meas-point") : byId("meas-point-text")).focus();
}

function closeDialog(): void {
  const dlg = byId("meas-dialog", HTMLDialogElement);
  pending = null;
  if (dlg.open) dlg.close();
}

async function confirmSwitch(): Promise<void> {
  const body = pending;
  if (!body) return;
  const yes = byId("meas-yes", HTMLButtonElement);
  const no = byId("meas-no", HTMLButtonElement);
  yes.disabled = true;
  no.disabled = true;
  message("meas-dlg-msg", t("map.switching"), "info");
  const r = await postSession(body);
  yes.disabled = false;
  no.disabled = false;
  if (r.ok) {
    closeDialog();
    message("meas-msg", t("map.switched", { p: pointLabel(body.point), t: fmtTime(new Date().toISOString()) }), "ok");
    byId("meas-note", HTMLInputElement).value = "";
    byId("meas-point", HTMLSelectElement).dataset["touched"] = "";
    bus.dispatchEvent(new Event("session-change"));
  } else {
    setStep(false);
    message("meas-dlg-msg", t("map.not_switched", { e: r.error }), "bad");
  }
}

export function initMeasure(): void {
  // Enter in a field moves to the confirmation step; it never submits the page.
  byId("meas-form", HTMLFormElement).addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (byId("meas-confirm").hidden) byId("meas-start", HTMLButtonElement).click();
  });
  byId("meas-point", HTMLSelectElement).addEventListener("change", (ev) => {
    if (ev.target instanceof HTMLSelectElement) ev.target.dataset["touched"] = "1";
  });
  byId("meas-open").addEventListener("click", () => openMeasureDialog());
  byId("meas-start").addEventListener("click", () => {
    const b = chosen();
    if (typeof b === "string") { message("meas-dlg-msg", b, "bad"); return; }
    message("meas-dlg-msg", "", "info");
    showConfirm(b);
  });
  byId("meas-yes").addEventListener("click", () => void confirmSwitch());
  byId("meas-no").addEventListener("click", () => {
    if (pending) { pending = null; setStep(false); return; }
    closeDialog();
  });
  byId("meas-dialog").addEventListener("close", () => { pending = null; setStep(false); });
  bus.addEventListener("pick-point", (ev) => {
    if (!(ev instanceof CustomEvent) || typeof ev.detail !== "string") return;
    openMeasureDialog(ev.detail);
  });
}

function planRow(it: PlanItem): HTMLElement {
  const prog = el("progress", {
    class: "plan-prog " + it.status,
    max: it.target_s ?? Math.max(it.measured_s, 1),
    value: Math.min(it.measured_s, it.target_s ?? it.measured_s),
    "aria-label": progressText(it),
  });
  const where = [it.unit_label, it.building_name].filter((x): x is string => Boolean(x)).join(" · ");
  return el("li", null, el("button", {
    type: "button",
    class: "plan-item " + it.status,
    "data-point": it.point,
    "aria-label": pointLabel(it.point) + ": " + progressText(it),
    onclick: () => showPoint(it),
  },
  el("span", { class: "plan-top" },
    el("span", { class: "plan-name" }, el("b", { text: it.name }), where ? el("span", { class: "muted small", text: " " + where }) : null),
    statusChip(it.status)),
  prog,
  el("span", { class: "plan-meta small muted", text: progressText(it) + " · " + sessionsText(it.sessions) + (it.note ? " · " + it.note : "") })));
}

function showPoint(it: PlanItem): void {
  for (const b of byId("plan-list").querySelectorAll<HTMLButtonElement>("button.plan-item")) {
    b.classList.toggle("sel", b.dataset["point"] === it.point);
  }
  if (state.site && focusPoint(it.point)) return;
  const box = byId("plan-info");
  box.hidden = false;
  const actions: HTMLElement[] = [];
  if (state.control?.enabled && state.control.point !== it.point && !state.control.site) {
    actions.push(el("button", {
      type: "button",
      class: "ctrl primary",
      text: t("map.measure_next"),
      onclick: () => openMeasureDialog(it.point),
    }));
  }
  box.replaceChildren(el("h3", { text: pointLabel(it.point) }), ...actions, ...sessionList(it.point));
}

export function renderPlan(): void {
  const items = state.plan?.items ?? [];
  byId("plan-box").hidden = items.length === 0;
  const planned = items.filter((i) => i.planned);
  const extra = items.filter((i) => !i.planned);
  byId("plan-title").textContent = t(planned.length ? "map.plan" : "map.measured_points");
  const done = planned.filter((i) => i.status === "done").length;
  byId("plan-sum").textContent = planned.length
    ? t("map.plan_sum", {
        done,
        n: planned.length,
        a: fmtHours(planned.reduce((a, i) => a + Math.min(i.measured_s, i.target_s ?? 0), 0)),
        b: fmtHours(planned.reduce((a, i) => a + (i.target_s ?? 0), 0)),
      })
    : t("map.points_n", { n: items.length });
  const nodes: HTMLElement[] = planned.map(planRow);
  if (planned.length && extra.length) nodes.push(el("li", { class: "plan-sep small muted", text: t("map.also_measured") }));
  nodes.push(...extra.map(planRow));
  byId("plan-list").replaceChildren(...nodes);
  byId("plan-hint").textContent = !state.site
    ? t("map.hint_nosite")
    : planned.length
      ? t("map.hint_select")
      : t("map.hint_add_plan");
}

export async function loadControl(): Promise<void> {
  const r = await fetchControl();
  if (!r) return;
  state.control = r;
  renderMeasure();
}

export async function loadPlan(): Promise<void> {
  const r = await fetchPlan();
  if (!r) return;
  state.plan = r;
  renderPlan();
  renderMeasureCurrent();
  if (state.control?.enabled) fillPicker();
  if (state.site) renderSite();
}
