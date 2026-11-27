// Per-interface timeline charts (minute buckets) and LAN active device count chart.

import type { LanPoint } from "./api/LanPoint.js";
import type { MinuteBucket } from "./api/MinuteBucket.js";
import { fetchMinutes } from "./client.js";
import { byId, cssVar, el, prepareCanvas } from "./dom.js";
import { fmtTime, ms, stateLabel } from "./format.js";
import { t } from "./i18n.js";
import { LIVE, state } from "./state.js";

/** What the last draw of a timeline canvas showed, for pointer lookups. */
interface TimelineView {
  start: number;
  end: number;
  L: number;
  pw: number;
  buckets: readonly MinuteBucket[];
  /** Minute under the pointer (ms since epoch), drawn as a crosshair. */
  hoverT: number | null;
}

interface LanView {
  start: number;
  end: number;
  L: number;
  pw: number;
  points: readonly LanPoint[];
  hoverT: number | null;
}

const views = new WeakMap<HTMLCanvasElement, TimelineView>();
const lanViews = new WeakMap<HTMLCanvasElement, LanView>();

const tOf = (b: MinuteBucket): number => new Date(b.t).getTime();
const pOf = (p: LanPoint): number => new Date(p.t).getTime();

function timeWindow(
  bucketsByIface: { readonly [k: string]: readonly MinuteBucket[] },
  lan: readonly LanPoint[],
  hours: number,
): [number, number] {
  let end = Date.now();
  if (state.selectedSession !== LIVE) {
    let maxT = -Infinity;
    for (const arr of Object.values(bucketsByIface)) {
      for (const b of arr) maxT = Math.max(maxT, tOf(b));
    }
    for (const p of lan) maxT = Math.max(maxT, pOf(p));
    if (isFinite(maxT)) end = maxT + 60e3;
  }
  return [end - hours * 3600e3, end];
}

function drawTimeGrid(
  c: CanvasRenderingContext2D,
  W: number, H: number, L: number, pw: number,
  start: number, end: number, hours: number, gridTop: number,
): (t: number) => number {
  const x = (t: number): number => L + ((t - start) / (end - start)) * pw;
  c.font = "10px " + cssVar("--mono");
  c.fillStyle = cssVar("--muted");
  c.strokeStyle = cssVar("--grid");
  c.lineWidth = 1;

  // grid ticks: support 15m/1h/3h/6h/24h/72h cleanly
  const pxPerMin = pw / (hours * 60);
  const stepMin = [3, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440].find((m) => m * pxPerMin >= 48) ?? 1440;
  const stepMs = stepMin * 60e3;
  const firstT = Math.ceil(start / stepMs) * stepMs;
  for (let t = firstT; t <= end; t += stepMs) {
    const d = new Date(t);
    const px = Math.round(x(t)) + 0.5;
    c.beginPath(); c.moveTo(px, gridTop); c.lineTo(px, H - 14); c.stroke();
    const lbl = d.getHours() === 0 && d.getMinutes() === 0
      ? d.toLocaleDateString([], { day: "numeric", month: "short" })
      : String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
    if (px + 2 + c.measureText(lbl).width <= W) c.fillText(lbl, px + 2, H - 3);
  }
  return x;
}

function drawCrosshair(
  c: CanvasRenderingContext2D,
  hx: number, L: number, W: number, R: number, top: number, bottom: number,
): void {
  if (hx < L || hx > W - R) return;
  c.save();
  c.strokeStyle = cssVar("--crosshair");
  c.setLineDash([3, 3]);
  c.beginPath();
  c.moveTo(hx, top);
  c.lineTo(hx, bottom);
  c.stroke();
  c.restore();
}

function drawHighlight(
  c: CanvasRenderingContext2D,
  x: (t: number) => number,
  start: number, end: number, L: number, W: number, R: number, top: number, bottom: number,
): void {
  const ht = state.highlightTs;
  if (ht === null || ht < start || ht > end) return;
  const px = x(ht);
  if (px < L || px > W - R) return;
  c.save();
  c.fillStyle = cssVar("--warn-bg");
  c.fillRect(Math.max(L, px - 5), top, Math.min(10, W - R - Math.max(L, px - 5)), bottom - top);
  c.strokeStyle = cssVar("--warn");
  c.lineWidth = 2;
  c.beginPath();
  c.moveTo(px, top);
  c.lineTo(px, bottom);
  c.stroke();
  c.restore();
}

/** Y-axis label, right-aligned 4 px left of the plot so it never touches the lines. */
function axisLabel(c: CanvasRenderingContext2D, text: string, left: number, y: number): void {
  const a = c.textAlign;
  c.textAlign = "right";
  c.fillText(text, left - 4, y);
  c.textAlign = a;
}

function drawTimeline(
  canvas: HTMLCanvasElement,
  buckets: readonly MinuteBucket[],
  hours: number,
  start: number,
  end: number,
): void {
  const hoverT = views.get(canvas)?.hoverT ?? null;
  const cv = prepareCanvas(canvas);
  if (!cv) return;
  const { c, W, H } = cv;

  const L = 46, R = 6;
  const pw = W - L - R;
  const failTop = 2, failH = 16;
  const rttTop = 22, rttH = Math.round((H - 22 - 16) * 0.55);
  const wTop = rttTop + rttH + 6, wH = H - wTop - 16;
  const colWidth = Math.max(1.5, pw / (hours * 60));

  const x = drawTimeGrid(c, W, H, L, pw, start, end, hours, rttTop);
  axisLabel(c, t("tl.fail_axis"), L, failTop + 12);

  const rtts: number[] = [];
  for (const b of buckets) {
    if (b.net_rtt_avg !== null) rtts.push(b.net_rtt_avg);
    if (b.gw_rtt_avg !== null) rtts.push(b.gw_rtt_avg);
  }
  rtts.sort((a, b) => a - b);
  const p98 = rtts[Math.floor(rtts.length * 0.98)] ?? 50;
  const rttMax = Math.min(1000, Math.max(20, Math.ceil(p98 / 10) * 10));
  const yR = (v: number): number => rttTop + rttH - (Math.min(v, rttMax) / rttMax) * rttH;
  axisLabel(c, rttMax + "ms", L, rttTop + 8);
  axisLabel(c, "0", L, rttTop + rttH);
  c.beginPath(); c.moveTo(L, rttTop + rttH + 0.5); c.lineTo(W - R, rttTop + rttH + 0.5); c.stroke();

  const hasWifi = buckets.some((b) => b.signal_dbm !== null || b.busy_pct !== null);
  if (hasWifi) {
    axisLabel(c, "-30", L, wTop + 8);
    axisLabel(c, "-90", L, wTop + wH);
    c.fillStyle = cssVar("--busy");
    for (const b of buckets) {
      if (b.busy_pct === null) continue;
      const h = (Math.min(100, b.busy_pct) / 100) * wH;
      c.fillRect(x(tOf(b)), wTop + wH - h, colWidth, h);
    }
  }

  c.fillStyle = cssVar("--bad");
  for (const b of buckets) {
    const f = Math.max(b.gw_fail, b.net_fail);
    if (!f || !b.ticks) continue;
    const h = Math.max(4, (f / b.ticks) * failH);
    c.fillRect(x(tOf(b)), failTop + failH - h, Math.max(1.5, colWidth), h);
  }

  const line = (key: "gw_rtt_avg" | "net_rtt_avg" | "signal_dbm", color: string, yf: (v: number) => number): void => {
    c.strokeStyle = color;
    c.lineWidth = 1.5;
    c.beginPath();
    let prevT: number | null = null;
    for (const b of buckets) {
      const v = b[key];
      const t = tOf(b);
      if (v === null) { prevT = null; continue; }
      const px = x(t) + colWidth / 2, py = yf(v);
      if (prevT === null || t - prevT > 120e3) c.moveTo(px, py); else c.lineTo(px, py);
      prevT = t;
    }
    c.stroke();
  };
  line("gw_rtt_avg", cssVar("--gw"), yR);
  line("net_rtt_avg", cssVar("--net"), yR);
  if (hasWifi) {
    const yS = (v: number): number => wTop + wH - ((Math.max(-90, Math.min(-30, v)) + 90) / 60) * wH;
    line("signal_dbm", cssVar("--sig"), yS);
  }

  if (hoverT) drawCrosshair(c, x(hoverT) + colWidth / 2, L, W, R, failTop, H - 14);
  drawHighlight(c, x, start, end, L, W, R, failTop, H - 14);
  views.set(canvas, { start, end, L, pw, buckets, hoverT });
}

function drawLanTimeline(
  canvas: HTMLCanvasElement,
  points: readonly LanPoint[],
  allBuckets: readonly MinuteBucket[],
  hours: number,
  start: number,
  end: number,
): void {
  const hoverT = lanViews.get(canvas)?.hoverT ?? null;
  const cv = prepareCanvas(canvas);
  if (!cv) return;
  const { c, W, H } = cv;

  const L = 46, R = 6;
  const pw = W - L - R;
  const failTop = 2, failH = 12;
  const chartTop = 18, chartH = H - chartTop - 16;
  const colWidth = Math.max(1.5, pw / (hours * 60));

  const x = drawTimeGrid(c, W, H, L, pw, start, end, hours, chartTop);
  axisLabel(c, t("tl.fail_axis"), L, failTop + 10);

  // Align failures from all interfaces on the top strip.
  const failFrac = new Map<number, number>();
  for (const b of allBuckets) {
    const f = Math.max(b.gw_fail, b.net_fail);
    if (!f || !b.ticks) continue;
    const t = tOf(b);
    if (t < start || t > end) continue;
    failFrac.set(t, Math.max(failFrac.get(t) ?? 0, Math.min(1, f / b.ticks)));
  }
  c.fillStyle = cssVar("--bad");
  for (const [t, frac] of failFrac) {
    const h = Math.max(4, frac * failH);
    c.fillRect(x(t), failTop + failH - h, Math.max(1.5, colWidth), h);
  }

  const pts = [...points]
    .filter((p) => pOf(p) >= start && pOf(p) <= end)
    .sort((a, b) => pOf(a) - pOf(b));
  const maxArp = pts.reduce((m, p) => Math.max(m, p.arp_alive, p.ping_alive), 0);
  const maxY = Math.max(10, Math.ceil(maxArp / 5) * 5);
  const y = (v: number): number => chartTop + chartH - (Math.min(v, maxY) / maxY) * chartH;

  c.fillStyle = cssVar("--muted");
  axisLabel(c, String(maxY), L, chartTop + 8);
  axisLabel(c, "0", L, chartTop + chartH);
  c.strokeStyle = cssVar("--grid");
  c.beginPath(); c.moveTo(L, chartTop + chartH + 0.5); c.lineTo(W - R, chartTop + chartH + 0.5); c.stroke();

  if (pts.length) {
    const maxGapMs = 35 * 60e3;
    const segments: LanPoint[][] = [];
    for (const p of pts) {
      const seg = segments[segments.length - 1];
      const prev = seg?.[seg.length - 1];
      if (!seg || !prev || pOf(p) - pOf(prev) > maxGapMs) segments.push([p]);
      else seg.push(p);
    }

    const base = chartTop + chartH;
    c.save();
    for (const seg of segments) {
      if (seg.length >= 2) {
        c.fillStyle = cssVar("--info-bg");
        c.beginPath();
        const first = seg[0];
        const last = seg[seg.length - 1];
        if (first && last) {
          c.moveTo(x(pOf(first)), base);
          for (const p of seg) c.lineTo(x(pOf(p)), y(p.arp_alive));
          c.lineTo(x(pOf(last)), base);
          c.closePath();
          c.fill();
        }
        c.strokeStyle = cssVar("--info");
        c.lineWidth = 1.8;
        c.beginPath();
        seg.forEach((p, i) => {
          const px = x(pOf(p)), py = y(p.arp_alive);
          if (i === 0) c.moveTo(px, py); else c.lineTo(px, py);
        });
        c.stroke();
      }
      c.strokeStyle = cssVar("--muted");
      c.lineWidth = 1.2;
      c.setLineDash([3, 3]);
      c.beginPath();
      seg.forEach((p, i) => {
        const px = x(pOf(p)), py = y(p.ping_alive);
        if (i === 0) c.moveTo(px, py); else c.lineTo(px, py);
      });
      c.stroke();
      c.setLineDash([]);
    }

    c.fillStyle = cssVar("--info");
    for (const p of pts) {
      c.beginPath();
      c.arc(x(pOf(p)), y(p.arp_alive), 2.2, 0, Math.PI * 2);
      c.fill();
    }
    c.restore();
  }

  if (hoverT) drawCrosshair(c, x(hoverT), L, W, R, failTop, H - 14);
  drawHighlight(c, x, start, end, L, W, R, failTop, H - 14);
  lanViews.set(canvas, { start, end, L, pw, points: pts, hoverT });
}

function bucketInfo(name: string, b: MinuteBucket): string {
  const p = [name, fmtTime(b.t)];
  p.push(t("tl.measured", { n: b.ticks }));
  if (b.gw_fail || b.net_fail) p.push(t("tl.fail", { gw: b.gw_fail, net: b.net_fail }));
  if (b.gw_rtt_avg !== null) p.push(t("tl.router", { v: ms(b.gw_rtt_avg), max: ms(b.gw_rtt_max) }));
  if (b.net_rtt_avg !== null) p.push(t("tl.internet", { v: ms(b.net_rtt_avg), max: ms(b.net_rtt_max) }));
  if (b.signal_dbm !== null) p.push(t("tl.signal", { v: b.signal_dbm }));
  if (b.busy_pct !== null) p.push(t("tl.busy", { v: Math.round(b.busy_pct) }));
  if (b.worst) p.push(t("tl.worst", { s: stateLabel(b.worst)[0] }));
  return p.join(" · ");
}

function onTimelinePointer(cv: HTMLCanvasElement, name: string, ev: PointerEvent): void {
  const g = views.get(cv);
  if (!g || !g.buckets.length) return;
  const r = cv.getBoundingClientRect();
  const t = g.start + ((ev.clientX - r.left - g.L) / g.pw) * (g.end - g.start);
  let best: MinuteBucket | null = null, bd = Infinity;
  for (const b of g.buckets) {
    const d = Math.abs(tOf(b) + 30e3 - t);
    if (d < bd) { bd = d; best = b; }
  }
  const maxSnap = Math.max(5 * 60e3, (g.end - g.start) / 40);
  if (best && bd < maxSnap) {
    g.hoverT = tOf(best);
    drawTimeline(cv, g.buckets, state.hours, g.start, g.end);
    byId("tl-info").textContent = bucketInfo(name, best);
  }
}

function onTimelineLeave(cv: HTMLCanvasElement, name: string): void {
  const g = views.get(cv);
  if (g?.hoverT) {
    g.hoverT = null;
    drawTimeline(cv, state.minutes[name] ?? [], state.hours, g.start, g.end);
  }
}

function onLanPointer(cv: HTMLCanvasElement, allBuckets: readonly MinuteBucket[], ev: PointerEvent): void {
  const g = lanViews.get(cv);
  if (!g || !g.points.length) return;
  const r = cv.getBoundingClientRect();
  const tm = g.start + ((ev.clientX - r.left - g.L) / g.pw) * (g.end - g.start);
  let best: LanPoint | null = null, bd = Infinity;
  for (const p of g.points) {
    const d = Math.abs(pOf(p) - tm);
    if (d < bd) { bd = d; best = p; }
  }
  const maxSnap = Math.max(10 * 60e3, (g.end - g.start) / 25);
  if (best && bd < maxSnap) {
    g.hoverT = pOf(best);
    drawLanTimeline(cv, g.points, allBuckets, state.hours, g.start, g.end);
    byId("tl-info").textContent =
      t("tl.lan_info", { t: fmtTime(best.t), arp: best.arp_alive, ping: best.ping_alive, seen: best.unique_seen });
  }
}

function onLanLeave(cv: HTMLCanvasElement, allBuckets: readonly MinuteBucket[]): void {
  const g = lanViews.get(cv);
  if (g?.hoverT) {
    g.hoverT = null;
    drawLanTimeline(cv, g.points, allBuckets, state.hours, g.start, g.end);
  }
}

export function renderTimelines(): void {
  const box = byId("timelines");
  const names = Object.keys(state.minutes);
  const lan = state.lanSeries;
  if (!names.length && !lan.length) {
    box.replaceChildren(el("div", { class: "empty", text: t("tl.no_data") }));
    return;
  }
  const [start, end] = timeWindow(state.minutes, lan, state.hours);
  const canvases = names.map((name) => {
    const cv = el("canvas", { "data-iface": name, "aria-label": t("tl.aria", { n: name }), role: "img" });
    cv.addEventListener("pointermove", (ev) => onTimelinePointer(cv, name, ev));
    cv.addEventListener("pointerdown", (ev) => onTimelinePointer(cv, name, ev));
    cv.addEventListener("pointerleave", () => onTimelineLeave(cv, name));
    return [cv, name] as const;
  });
  const nodes: HTMLElement[] = canvases.map(([cv, name]) =>
    el("div", { class: "tl" }, el("div", { class: "tl-title", text: name }), cv),
  );
  const allBuckets = Object.values(state.minutes).flat();
  let lanCv: HTMLCanvasElement | null = null;
  if (lan.length) {
    lanCv = el("canvas", { "aria-label": t("tl.lan_title"), role: "img" });
    const cvRef = lanCv;
    cvRef.addEventListener("pointermove", (ev) => onLanPointer(cvRef, allBuckets, ev));
    cvRef.addEventListener("pointerdown", (ev) => onLanPointer(cvRef, allBuckets, ev));
    cvRef.addEventListener("pointerleave", () => onLanLeave(cvRef, allBuckets));
    nodes.push(el("div", { class: "tl tl-lan" }, el("div", { class: "tl-title", text: t("tl.lan_title") }), lanCv));
  }
  box.replaceChildren(...nodes);
  for (const [cv, name] of canvases) drawTimeline(cv, state.minutes[name] ?? [], state.hours, start, end);
  if (lanCv) drawLanTimeline(lanCv, lan, allBuckets, state.hours, start, end);
}

export function focusTimestamp(iso: string): void {
  const tm = new Date(iso).getTime();
  if (!isFinite(tm)) return;
  state.highlightTs = tm;
  renderTimelines();
  byId("tl-info").textContent = t("tl.focused", { t: fmtTime(iso) });
  byId("h-timeline").scrollIntoView({ behavior: "smooth", block: "start" });
}

export async function loadMinutes(): Promise<void> {
  const r = await fetchMinutes(state.selectedSession, state.hours);
  if (r) {
    state.minutes = r.ifaces;
    state.lanSeries = r.lan;
    renderTimelines();
  }
}
