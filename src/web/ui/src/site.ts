// Site plan as a status map: building switcher, a side view of the building (floors stacked,
// one cell per flat) and the selected flat drawn in detail with walls, doors, vertical neighbors,
// and adjacent-floor overlay.

import type { AreaView } from "./api/AreaView.js";
import type { BuildingView } from "./api/BuildingView.js";
import type { DoorView } from "./api/DoorView.js";
import type { PointView } from "./api/PointView.js";
import type { ScanBss } from "./api/ScanBss.js";
import type { UnitView } from "./api/UnitView.js";
import type { VerticalNeighbor } from "./api/VerticalNeighbor.js";
import type { WallMaterial } from "./api/WallMaterial.js";
import { fetchSessions, fetchSite } from "./client.js";
import { byId, el, sv } from "./dom.js";
import { band, freqToChannel } from "./format.js";
import {
  availTone, dropsTone, planItem, pointClass, pointLabel, progressText,
  resultText, sessionList, statusChip, statusText,
} from "./points.js";
import { renderSessionList } from "./sessions.js";
import { ADJ_FLOORS, COLOR_MODES, bus, oneOf, state } from "./state.js";
import { type MsgKey, t, tDyn } from "./i18n.js";
import { maskedMac } from "./wifi.js";
import { tip } from "./tips.js";

/** What the monitor sees live of one BSSID / MAC. */
interface LiveHit {
  b: ScanBss | undefined;
  connected: boolean;
  ch: number | null | undefined;
  band: string | undefined;
  sig: number | undefined;
}

const WALL_LOSS: { readonly [M in WallMaterial]: MsgKey } = {
  concrete: "wall.concrete",
  brick: "wall.brick",
  drywall: "wall.drywall",
  glass: "wall.glass",
  wood: "wall.wood",
};

/** Floor name: "Ground floor" for 0, else "Floor n". */
function floorName(n: number): string {
  return n === 0 ? t("map.ground") : t("map.floor_n", { n });
}

/** Crossing point of segments a–b and c–d, or null. */
function segHit(a: readonly [number, number], b: readonly [number, number], c: readonly [number, number], d: readonly [number, number]): [number, number] | null {
  const r = [b[0] - a[0], b[1] - a[1]];
  const q = [d[0] - c[0], d[1] - c[1]];
  const den = (r[0] ?? 0) * (q[1] ?? 0) - (r[1] ?? 0) * (q[0] ?? 0);
  if (Math.abs(den) < 1e-9) return null;
  const tt = ((c[0] - a[0]) * (q[1] ?? 0) - (c[1] - a[1]) * (q[0] ?? 0)) / den;
  const uu = ((c[0] - a[0]) * (r[1] ?? 0) - (c[1] - a[1]) * (r[0] ?? 0)) / den;
  if (tt <= 0.01 || tt >= 0.99 || uu < 0 || uu > 1) return null;
  return [a[0] + tt * (r[0] ?? 0), a[1] + tt * (r[1] ?? 0)];
}

function liveBssidMap(): Map<string, LiveHit> {
  const map = new Map<string, LiveHit>();
  for (const s of Object.values(state.scan)) {
    const our = (s.our_bssid ?? "").toLowerCase();
    for (const b of s.report.bss) {
      const k = b.bssid.toLowerCase();
      if (!k) continue;
      const connected = Boolean(b.associated || (our && our === k));
      const ch = b.channel ?? freqToChannel(b.freq_mhz);
      map.set(k, { b, connected, ch, band: band(b.freq_mhz), sig: undefined });
    }
  }
  for (const i of Object.values(state.status?.ifaces ?? {})) {
    const w = i.wifi;
    if (w && w.connected && w.bssid) {
      const k = w.bssid.toLowerCase();
      const prev = map.get(k);
      map.set(k, {
        b: prev?.b,
        connected: true,
        ch: w.channel ?? prev?.ch,
        band: band(w.freq_mhz) || prev?.band,
        sig: w.signal_avg_dbm ?? w.signal_dbm,
      });
    }
  }
  return map;
}

function pointMatches(p: PointView, liveMap: Map<string, LiveHit>): (LiveHit & { mac: string })[] {
  const macs = [...(p.bssids ?? []), p.mac ?? ""].filter(Boolean).map((m) => m.toLowerCase());
  const hits: (LiveHit & { mac: string })[] = [];
  for (const m of macs) {
    const h = liveMap.get(m);
    if (h) hits.push({ mac: m, ...h });
  }
  return hits;
}

function pointShape(p: PointView, cls: string, onClick: (() => void) | null): SVGElement {
  const [x, y] = p.at;
  const attrs = onClick ? { onclick: onClick } : {};
  if (p.kind === "router") {
    return sv("rect", { x: x - 0.22, y: y - 0.22, width: 0.44, height: 0.44, class: cls, transform: "rotate(45 " + x + " " + y + ")", ...attrs });
  }
  if (p.kind === "ap") {
    return sv("rect", { x: x - 0.22, y: y - 0.22, width: 0.44, height: 0.44, rx: 0.08, class: cls, ...attrs });
  }
  if (p.kind === "booster") {
    const pts = [[x, y - 0.28], [x + 0.26, y + 0.2], [x - 0.26, y + 0.2]].map((q) => q.join(",")).join(" ");
    return sv("polygon", { points: pts, class: cls, ...attrs });
  }
  return sv("circle", { cx: x, cy: y, r: p.kind === "probe" ? 0.25 : 0.21, class: cls, ...attrs });
}

const polyPoints = (poly: readonly (readonly [number, number])[]): string => poly.map((p) => p.join(",")).join(" ");

function pointInPoly(poly: readonly (readonly [number, number])[], p: readonly [number, number]): boolean {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const a = poly[i];
    const b = poly[j];
    if (!a || !b) continue;
    if ((a[1] > p[1]) !== (b[1] > p[1]) && p[0] < ((b[0] - a[0]) * (p[1] - a[1])) / (b[1] - a[1]) + a[0]) {
      inside = !inside;
    }
  }
  return inside;
}

/** Enter and Space activate a focusable SVG shape like a button. */
function keyActivate(fn: () => void): (ev: Event) => void {
  return (ev: Event) => {
    if (ev instanceof KeyboardEvent && (ev.key === "Enter" || ev.key === " ")) {
      ev.preventDefault();
      fn();
    }
  };
}

function allUnits(b: BuildingView): UnitView[] {
  return [...b.floors].sort((x, y) => x.floor - y.floor).flatMap((f) => f.units);
}

/** Building and flat of a point id (`B1/F2/R3` -> `B1`, `B1/F2`). */
function unitOf(point: string | null | undefined): [string, string] | null {
  const parts = (point ?? "").split("/");
  return parts.length >= 3 && parts[0] && parts[1] ? [parts[0], parts[0] + "/" + parts[1]] : null;
}

const UNIT_RANK: { readonly [k: string]: number } = { "st-none": 0, "st-todo": 1, "st-done": 2, "st-partial": 3, "st-active": 4, "res-none": 0, "res-ok": 1, "res-warn": 2, "res-bad": 3 };

function unitClass(u: UnitView): string {
  const items = (state.plan?.items ?? []).filter((i) => i.point.startsWith(u.full_id + "/"));
  if (state.colorMode !== "status") {
    let best = "res-none";
    for (const i of items) {
      const t = state.colorMode === "availability" ? availTone(i.availability_pct) : dropsTone(i.drops_per_h);
      const c = "res-" + (t ?? "none");
      if ((UNIT_RANK[c] ?? 0) > (UNIT_RANK[best] ?? 0)) best = c;
    }
    return best;
  }
  if (items.some((i) => i.status === "active")) return "st-active";
  const planned = items.filter((i) => i.planned);
  if (planned.length && planned.every((i) => i.status === "done")) return "st-done";
  if (items.some((i) => i.measured_s > 0)) return "st-partial";
  return planned.length ? "st-todo" : "st-none";
}

function unitSummary(u: UnitView): string {
  const items = (state.plan?.items ?? []).filter((i) => i.point.startsWith(u.full_id + "/"));
  const planned = items.filter((i) => i.planned);
  const parts: string[] = [];
  if (items.some((i) => i.status === "active")) parts.push(t("plan.active"));
  if (planned.length) parts.push(t("map.unit_done", { a: planned.filter((i) => i.status === "done").length, b: planned.length }));
  else if (items.length) parts.push(t("map.unit_measured", { n: items.length }));
  return parts.join(" · ");
}

function renderBuildingButtons(site: readonly BuildingView[]): void {
  byId("site-buildings").replaceChildren(...site.map((b) => el("button", {
    type: "button",
    class: b.id === state.building ? "on" : "",
    "aria-pressed": b.id === state.building ? "true" : "false",
    text: b.name,
    onclick: () => { state.building = b.id; state.unit = null; renderSite(); },
  })));
}

/** Side view: top floor first, one button per flat; highlights vertical stack peers. */
function renderBuildingView(b: BuildingView): void {
  const selUnit = allUnits(b).find((u) => u.full_id === state.unit) ?? null;
  const floors = [...b.floors].sort((x, y) => y.floor - x.floor);
  byId("site-building").replaceChildren(...floors.map((f) => el("div", { class: "bv-floor" },
    el("div", { class: "bv-label small muted", text: floorName(f.floor) }),
    el("div", { class: "bv-units" }, ...[...f.units].sort((x, y) => x.x - y.x).map((u) => {
      const sel = u.full_id === state.unit;
      const inStack = selUnit !== null && !sel && u.x < selUnit.x + selUnit.width_m - 0.1 && u.x + u.width_m > selUnit.x + 0.1;
      const summary = unitSummary(u);
      return el("button", {
        type: "button",
        class: "bv-unit " + unitClass(u) + (sel ? " sel" : inStack ? " stack-rel" : ""),
        "aria-pressed": sel ? "true" : "false",
        "aria-label": u.label + (summary ? ", " + summary : "") + (sel ? ", " + t("map.shown") : inStack ? ", " + t("map.stacked") : ""),
        onclick: () => { state.unit = u.full_id; renderSite(); },
      }, el("span", { class: "bv-name", text: u.label }), summary ? el("span", { class: "bv-sum", text: summary }) : null);
    })))));
}

function renderLegend(): void {
  const sw = (cls: string, text: string): HTMLElement => el("span", null, el("i", { class: "sw-room " + cls }), text);
  const items = state.colorMode === "status"
    ? [sw("st-none", t("plan.not_planned")), sw("st-todo", statusText("todo")), sw("st-active", statusText("active")), sw("st-partial", statusText("partial")), sw("st-done", statusText("done"))]
    : state.colorMode === "availability"
      ? [sw("res-ok", "≥ 99.9 %"), sw("res-warn", "≥ 99 %"), sw("res-bad", "< 99 %"), sw("res-none", t("plan.no_result"))]
      : [sw("res-ok", t("map.lt_drops", { n: "0.5" })), sw("res-warn", t("map.lt_drops", { n: "2" })), sw("res-bad", t("map.ge_drops", { n: "2" })), sw("res-none", t("plan.no_result"))];
  byId("site-legend").replaceChildren(
    ...items,
    el("span", null, el("i", { class: "ico-diamond" }), t("pk.router")),
    el("span", null, el("i", { class: "ico-sq" }), t("pk.ap")),
    el("span", null, el("i", { class: "ico-tri" }), t("pk.booster")),
    el("span", null, el("i", { class: "ico-dot" }), t("pk.probe")),
    el("span", { class: "tip-lbl" }, el("i", { class: "sw-wall concrete" }), t("wm.concrete"), el("i", { class: "sw-wall brick" }), t("wm.brick"), el("i", { class: "sw-wall drywall" }), t("wm.drywall"), tip("walls")),
  );
  for (const b of byId("site-color").querySelectorAll<HTMLButtonElement>("button")) {
    const on = b.dataset["c"] === state.colorMode;
    b.classList.toggle("on", on);
    b.setAttribute("aria-pressed", on ? "true" : "false");
  }
  for (const b of byId("site-adj").querySelectorAll<HTMLButtonElement>("button")) {
    const on = b.dataset["adj"] === state.adjFloor;
    b.classList.toggle("on", on);
    b.setAttribute("aria-pressed", on ? "true" : "false");
  }
}

function appendDoor(svg: SVGSVGElement, d: DoorView): void {
  const [x1, y1] = d.from;
  const [x2, y2] = d.to;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const len = Math.hypot(dx, dy);
  if (len <= 1e-4) return;

  const kindCls = " door-" + d.kind;
  svg.append(sv("line", { x1, y1, x2, y2, class: "door-gap" }));

  if (d.swing === "sliding") {
    const ux = (-dy / len) * 0.06;
    const uy = (dx / len) * 0.06;
    svg.append(sv("line", { x1: x1 + ux, y1: y1 + uy, x2: x2 + ux, y2: y2 + uy, class: "door-leaf" + kindCls }));
    svg.append(sv("line", { x1: x1 - ux, y1: y1 - uy, x2: x2 - ux, y2: y2 - uy, class: "door-leaf" + kindCls }));
  } else if (d.swing === "double") {
    const hx = dx / 2;
    const hy = dy / 2;
    const hr = len / 2;
    const o1x = x1 + hy;
    const o1y = y1 - hx;
    const o2x = x2 + hy;
    const o2y = y2 - hx;
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    svg.append(sv("path", { d: `M ${mx} ${my} A ${hr} ${hr} 0 0 0 ${o1x} ${o1y}`, class: "door-arc" + kindCls }));
    svg.append(sv("path", { d: `M ${mx} ${my} A ${hr} ${hr} 0 0 1 ${o2x} ${o2y}`, class: "door-arc" + kindCls }));
    svg.append(sv("line", { x1, y1, x2: o1x, y2: o1y, class: "door-leaf" + kindCls }));
    svg.append(sv("line", { x1: x2, y1: y2, x2: o2x, y2: o2y, class: "door-leaf" + kindCls }));
  } else {
    const open = d.swing === "left" ? [x1 + dy, y1 - dx] : [x1 - dy, y1 + dx];
    const sweep = d.swing === "left" ? 0 : 1;
    svg.append(sv("path", { d: `M ${x2} ${y2} A ${len} ${len} 0 0 ${sweep} ${open[0]} ${open[1]}`, class: "door-arc" + kindCls }));
    svg.append(sv("line", { x1, y1, x2: open[0], y2: open[1], class: "door-leaf" + kindCls }));
  }

  const label = d.label ?? (d.kind === "exit" ? t("map.exit") : null);
  if (label) {
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const ox = d.swing === "left" ? dy / len : -dy / len;
    const oy = d.swing === "left" ? -dx / len : dx / len;
    svg.append(sv("text", { x: mx + ox * 0.52, y: my + oy * 0.52, class: "door-lbl" + kindCls, text: label }));
  }
}

function appendAdjOverlay(svg: SVGSVGElement, b: BuildingView, u: UnitView, floor: number): void {
  if (state.adjFloor === "off") return;
  const targetFloor = state.adjFloor === "above" ? floor + 1 : floor - 1;
  const fl = b.floors.find((x) => x.floor === targetFloor);
  if (!fl) return;
  const prefix = (state.adjFloor === "above" ? "↑ " : "↓ ") + floorName(targetFloor);
  for (const adj of fl.units) {
    if (adj.x >= u.x + u.width_m || adj.x + adj.width_m <= u.x || adj.y >= u.y + u.depth_m || adj.y + adj.depth_m <= u.y) {
      continue;
    }
    for (const r of adj.rooms) {
      svg.append(sv("polygon", { points: polyPoints(r.poly), class: "ghost-room" }));
    }
    for (const p of adj.points) {
      if (p.kind !== "router" && p.kind !== "ap" && p.kind !== "booster") continue;
      const g = pointShape(p, "ghost-pt " + p.kind, null);
      svg.append(g);
      svg.append(sv("text", { x: p.at[0], y: p.at[1] - 0.36, class: "ghost-lbl", text: prefix + ": " + p.name }));
    }
  }
}

/** Line from the router to the selected room, with marks where it crosses walls (RF estimate). */
function appendRfRay(svg: SVGSVGElement, u: UnitView): void {
  const room = u.rooms.find((r) => r.full_id === state.selected);
  const rf = room?.rf;
  if (!room || !rf) return;
  const router = u.points.find((p) => p.full_id === rf.router_point);
  if (!router) return;
  const a = router.at;
  const b = room.centroid;
  svg.append(sv("line", { x1: a[0], y1: a[1], x2: b[0], y2: b[1], class: "rf-ray" }));
  for (const w of u.walls) {
    const hit = segHit(a, b, w.from, w.to);
    if (hit) svg.append(sv("circle", { cx: hit[0], cy: hit[1], r: 0.11, class: "rf-hit" }));
  }
  svg.append(sv("text", { x: (a[0] + b[0]) / 2, y: (a[1] + b[1]) / 2 - 0.25, class: "rf-lbl", text: "≈ " + rf.obstacle_loss_db.toFixed(0) + " dB" }));
}

/** The selected flat in detail. */
function renderUnit(b: BuildingView, u: UnitView, floor: number): void {
  const liveMap = liveBssidMap();
  const pad = 0.45, top = 0.35;
  const svg = sv("svg", {
    class: "plan",
    viewBox: [u.x - pad, u.y - top, u.width_m + 2 * pad, u.depth_m + top + pad].join(" "),
    role: "group",
    "aria-label": b.name + ", " + u.label + ", " + floorName(floor),
  });
  const defs = sv("defs");
  const pat = sv("pattern", { id: "hatch", width: 0.5, height: 0.5, patternUnits: "userSpaceOnUse", patternTransform: "rotate(45)" });
  pat.append(sv("line", { x1: 0, y1: 0, x2: 0, y2: 0.5, class: "hatch-line" }));
  defs.append(pat);
  svg.append(defs);

  for (const r of u.rooms) {
    const rid = r.full_id ?? "";
    const it = planItem(rid);
    const pick = (): void => selectPoint(rid, r.name, null, r);
    const desc = r.name + ", " + (it ? resultText(it) : state.colorMode === "status" ? t("plan.not_planned") : t("plan.no_result"));
    const poly = sv("polygon", {
      points: polyPoints(r.poly),
      class: ["room", pointClass(rid), state.selected === rid ? "sel" : ""].join(" ").trim(),
      tabindex: 0,
      role: "button",
      "aria-label": desc,
      onclick: pick,
      onkeydown: keyActivate(pick),
    });
    poly.append(sv("title", { text: rid + " · " + desc }));
    svg.append(poly);
    svg.append(sv("text", { x: r.centroid[0], y: r.centroid[1] - 0.2, class: "room-name", text: r.name }));
    svg.append(sv("text", { x: r.centroid[0], y: r.centroid[1] + 0.25, class: "room-sub", text: it ? (state.colorMode === "status" ? progressText(it) : resultText(it)) : (r.id ?? "") }));
  }

  for (const fx of u.fixed) {
    const poly = sv("polygon", { points: polyPoints(fx.poly), class: "fixed" });
    poly.append(sv("title", { text: fx.name + " (" + t("map.not_tested") + ")" }));
    svg.append(poly);
    svg.append(sv("text", { x: fx.centroid[0], y: fx.centroid[1], class: "room-sub", text: fx.name }));
  }

  svg.append(sv("rect", { x: u.x, y: u.y, width: u.width_m, height: u.depth_m, class: "unit-outline" }));

  for (const w of u.walls) {
    const ln = sv("line", {
      x1: w.from[0], y1: w.from[1], x2: w.to[0], y2: w.to[1],
      class: "wall wall-" + w.material,
    });
    ln.append(sv("title", { text: t(WALL_LOSS[w.material]) + (w.thickness_cm !== undefined ? " · " + w.thickness_cm + " cm" : "") }));
    svg.append(ln);
  }
  for (const d of u.doors) appendDoor(svg, d);

  appendAdjOverlay(svg, b, u, floor);

  for (const p of u.points) {
    const hits = pointMatches(p, liveMap);
    const isConn = hits.some((h) => h.connected);
    const liveCls = isConn ? " live-conn" : hits.length ? " live-seen" : "";
    const measured = planItem(p.full_id);
    const cls = "pt " + p.kind + (measured ? " " + pointClass(p.full_id) : "") + liveCls;
    const hostRoom = u.rooms.find((r) => pointInPoly(r.poly, p.at)) ?? null;
    const pick = (): void => selectPoint(p.full_id, p.name, p, hostRoom);
    const shape = pointShape(p, cls, pick);
    shape.setAttribute("tabindex", "0");
    shape.setAttribute("role", "button");
    shape.setAttribute("aria-label", p.name + " (" + tDyn("pk." + p.kind, p.kind) + ")");
    shape.addEventListener("keydown", keyActivate(pick));
    let title = p.full_id + " · " + p.name;
    const best = hits[0];
    if (best) {
      const sig = best.sig ?? best.b?.signal_dbm;
      title += " · " + t("map.live") + (sig !== undefined ? " " + Math.round(sig) + " dBm" : "") + (best.ch ? " ch " + best.ch : "");
    }
    shape.append(sv("title", { text: title }));
    svg.append(shape);
    if (isConn) svg.append(sv("circle", { cx: p.at[0], cy: p.at[1], r: 0.42, class: "cur live" }));
    if (state.site?.current_point === p.full_id) svg.append(sv("circle", { cx: p.at[0], cy: p.at[1], r: 0.5, class: "cur" }));
  }
  appendRfRay(svg, u);
  const title = b.name + " · " + u.label + " · " + floorName(floor);
  byId("site").replaceChildren(el("div", { class: "floor" }, el("div", { class: "floor-title", text: title }), svg));
}

export function renderSite(): void {
  const site = state.site;
  if (!site) return;
  byId("site-panel").hidden = false;
  byId("map-workspace").classList.remove("no-site");
  const cur = unitOf(site.current_point);
  if (!state.building || !site.buildings.some((b) => b.id === state.building)) {
    state.building = (site.buildings.find((b) => b.id === cur?.[0]) ?? site.buildings[0])?.id ?? null;
  }
  renderBuildingButtons(site.buildings);
  renderLegend();
  const b = site.buildings.find((x) => x.id === state.building);
  if (!b) {
    byId("site-building").replaceChildren();
    byId("site").replaceChildren(el("div", { class: "empty", text: t("map.no_buildings") }));
    return;
  }
  const units = allUnits(b);
  if (!state.unit || !units.some((u) => u.full_id === state.unit)) {
    state.unit = (units.find((u) => u.full_id === cur?.[1]) ?? units[0])?.full_id ?? null;
  }
  renderBuildingView(b);
  const f = b.floors.find((fl) => fl.units.some((u) => u.full_id === state.unit));
  const u = f?.units.find((x) => x.full_id === state.unit);
  if (f && u) renderUnit(b, u, f.floor);
  else byId("site").replaceChildren(el("div", { class: "empty", text: t("map.no_flats") }));
}

function neighborRow(arrow: string, list: readonly VerticalNeighbor[]): HTMLElement | null {
  if (!list.length) return null;
  const btns = list.map((n) => {
    const it = planItem(n.point);
    const sub = n.kind === "room" && it ? " · " + resultText(it) : n.kind !== "room" ? " (" + n.kind + ")" : "";
    return el("button", {
      type: "button",
      class: "ctrl vstack-btn",
      text: n.unit_label + " · " + n.name + sub,
      onclick: () => focusPoint(n.point),
    });
  });
  return el("div", { class: "vstack-row" }, el("span", { class: "small muted", text: arrow }), ...btns);
}

function selectPoint(id: string, name: string, pt: PointView | null, area: AreaView | null): void {
  state.selected = id;
  renderSite();
  const box = byId("site-info");
  const extra: HTMLElement[] = [];
  if (pt) {
    const macs = [pt.mac, ...(pt.bssids ?? [])].filter((m): m is string => Boolean(m));
    extra.push(el("div", { class: "small muted row-wrap" },
      el("span", { text: tDyn("pk." + pt.kind, pt.kind) }),
      ...macs.map((m) => maskedMac(m)),
      pt.notes ? el("span", { text: pt.notes }) : null));
    for (const h of pointMatches(pt, liveBssidMap())) {
      const sig = h.sig ?? h.b?.signal_dbm;
      extra.push(el("div", {
        class: "small",
        text: t("map.live_rf") + ": " + t(h.connected ? "bss.connected" : "map.seen") +
          (sig !== undefined ? " · " + Math.round(sig) + " dBm" : "") +
          (h.ch ? " · ch " + h.ch : "") +
          (h.b?.width_mhz ? " / " + h.b.width_mhz + " MHz" : ""),
      }));
    }
  }
  const vRows = [
    neighborRow("↑ " + t("map.above"), area?.above ?? []),
    neighborRow("↓ " + t("map.below"), area?.below ?? []),
  ].filter((x): x is HTMLElement => x !== null);
  const vstack = vRows.length ? el("div", { class: "vstack" }, ...vRows) : null;
  if (area?.rf) {
    extra.push(el("div", { class: "rf-box" },
      el("strong", { text: t("map.rf_title", { loss: area.rf.obstacle_loss_db.toFixed(0) }) }),
      el("span", {
        text: t("map.rf_est", {
          router: pointLabel(area.rf.router_point),
          dist: area.rf.distance_m.toFixed(1),
          walls: area.rf.walls_crossed,
          floors: area.rf.floors_crossed,
        }),
      })));
  }

  const it = planItem(id);
  const head = el("h3", { text: (it ? pointLabel(id) : name) });
  const facts = el("div", { class: "row-wrap" },
    el("span", { class: "mono small muted", text: id }),
    it ? statusChip(it.status) : el("span", { class: "pill small neutral", text: t("plan.not_planned") }),
    it ? el("span", { class: "small", text: progressText(it) }) : null,
    it?.note ? el("span", { class: "small note", text: it.note }) : null);
  const actions: HTMLElement[] = [];
  if (state.control?.enabled && state.control.point !== id && (!pt || pt.kind === "probe" || pt.kind === "other")) {
    actions.push(el("button", {
      type: "button",
      class: "ctrl primary",
      text: t("map.measure_next"),
      onclick: () => bus.dispatchEvent(new CustomEvent<string>("pick-point", { detail: id })),
    }));
  }
  box.replaceChildren(head, facts, ...extra, ...(vstack ? [vstack] : []), ...actions, el("h4", { text: t("map.sessions_here") }), ...sessionList(id));
}

/** Shows a point on the map (from the plan list or vertical stack): its building, flat and sessions. */
export function focusPoint(point: string): boolean {
  const site = state.site;
  const where = unitOf(point);
  if (!site || !where) return false;
  const b = site.buildings.find((x) => x.id === where[0]);
  const u = b ? allUnits(b).find((x) => x.full_id === where[1]) : undefined;
  if (!u) return false;
  state.building = where[0];
  state.unit = where[1];
  const room = u.rooms.find((r) => r.full_id === point) ?? null;
  const pt = u.points.find((p) => p.full_id === point) ?? null;
  selectPoint(point, room?.name ?? pt?.name ?? point, pt, room);
  if (window.innerWidth < 1020) byId("site-panel").scrollIntoView({ behavior: "smooth", block: "start" });
  return true;
}

export function initSiteControls(): void {
  for (const b of byId("site-color").querySelectorAll<HTMLButtonElement>("button")) {
    b.addEventListener("click", () => {
      const c = b.dataset["c"];
      if (!oneOf(COLOR_MODES, c)) return;
      state.colorMode = c;
      renderSite();
    });
  }
  for (const b of byId("site-adj").querySelectorAll<HTMLButtonElement>("button")) {
    b.addEventListener("click", () => {
      const adj = b.dataset["adj"];
      if (!oneOf(ADJ_FLOORS, adj)) return;
      state.adjFloor = adj;
      renderSite();
    });
  }
}

export async function loadSite(): Promise<void> {
  const r = await fetchSite();
  if (!r) {
    byId("site-panel").hidden = true;
    byId("map-workspace").classList.add("no-site");
    return;
  }
  state.site = r;
  renderSite();
}

export async function loadSessions(): Promise<void> {
  const r = await fetchSessions();
  if (r) {
    state.sessions = r.sessions;
    renderSessionList();
    if (state.site) renderSite();
  }
}