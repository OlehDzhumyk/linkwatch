// Per-interface timeline charts (Sessions full range + Now compact 1 h view) and LAN device chart.
// Supports hover/crosshair + canvas value bubble, keyboard ←/→ (Shift = 10 min), brush-drag zoom,
// and a calm highlight ring pulse when jumping from an incident.

import type { LanPoint } from "./api/LanPoint.js";
import type { MinuteBucket } from "./api/MinuteBucket.js";
import { fetchMinutes } from "./client.js";
import { byId, cssVar, el, prepareCanvas } from "./dom.js";
import { fmtTime, fmtTimeShort, ms, stateLabel } from "./format.js";
import { getLang, t } from "./i18n.js";
import { LIVE, bus, state } from "./state.js";
import { errorState } from "./ui.js";

type TimelineMode = "sessions" | "now";

interface BubbleLine {
  text: string;
  color?: string;
  bold?: boolean;
}

interface TimelineView {
  mode: TimelineMode;
  name: string;
  infoId: string;
  start: number;
  end: number;
  hours: number;
  L: number;
  pw: number;
  buckets: readonly MinuteBucket[];
  hoverT: number | null;
}

interface LanView {
  infoId: string;
  start: number;
  end: number;
  hours: number;
  L: number;
  pw: number;
  points: readonly LanPoint[];
  allBuckets: readonly MinuteBucket[];
  hoverT: number | null;
}

const views = new WeakMap<HTMLCanvasElement, TimelineView>();
const lanViews = new WeakMap<HTMLCanvasElement, LanView>();
let sessionCanvases: { cv: HTMLCanvasElement; name: string; isLan: boolean }[] = [];
let nowCanvases: { cv: HTMLCanvasElement; name: string }[] = [];
let dragBand: readonly [number, number] | null = null;
let pulseProgress: number | null = null;
let pulseRaf: number | null = null;

const tOf = (b: MinuteBucket): number => new Date(b.t).getTime();
const pOf = (p: LanPoint): number => new Date(p.t).getTime();

function sessionTimeWindow(
  bucketsByIface: { readonly [k: string]: readonly MinuteBucket[] },
  lan: readonly LanPoint[],
  hours: number,
): readonly [number, number] {
  if (state.brushRange) return state.brushRange;
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

function nowTimeWindow(): readonly [number, number] {
  const end = Date.now();
  return [end - 3600e3, end];
}

function drawTimeGrid(
  c: CanvasRenderingContext2D,
  W: number, H: number, L: number, pw: number,
  start: number, end: number, hours: number, gridTop: number,
): (tm: number) => number {
  const x = (tm: number): number => L + ((tm - start) / (end - start)) * pw;
  c.font = "10px " + cssVar("--mono");
  c.fillStyle = cssVar("--muted");
  c.strokeStyle = cssVar("--grid");
  c.lineWidth = 1;

  const pxPerMin = pw / Math.max(1, hours * 60);
  const stepMin = [1, 2, 3, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440].find((m) => m * pxPerMin >= 48) ?? 1440;
  const stepMs = stepMin * 60e3;
  const firstT = Math.ceil(start / stepMs) * stepMs;
  const lang = getLang();
  for (let tm = firstT; tm <= end; tm += stepMs) {
    const d = new Date(tm);
    const px = Math.round(x(tm)) + 0.5;
    c.beginPath(); c.moveTo(px, gridTop); c.lineTo(px, H - 14); c.stroke();
    const lbl = d.getHours() === 0 && d.getMinutes() === 0
      ? d.toLocaleDateString(lang, { day: "numeric", month: "short" })
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

function drawBrushBand(
  c: CanvasRenderingContext2D,
  x: (tm: number) => number,
  L: number, W: number, R: number, top: number, bottom: number,
): void {
  if (!dragBand) return;
  const x0 = Math.max(L, Math.min(W - R, x(dragBand[0])));
  const x1 = Math.max(L, Math.min(W - R, x(dragBand[1])));
  const left = Math.min(x0, x1);
  const w = Math.max(2, Math.abs(x1 - x0));
  c.save();
  c.globalAlpha = 0.55;
  c.fillStyle = cssVar("--info-bg");
  c.fillRect(left, top, w, bottom - top);
  c.globalAlpha = 1;
  c.strokeStyle = cssVar("--accent");
  c.lineWidth = 1.5;
  c.beginPath();
  c.moveTo(left, top); c.lineTo(left, bottom);
  c.moveTo(left + w, top); c.lineTo(left + w, bottom);
  c.stroke();
  c.restore();
}

function drawHighlight(
  c: CanvasRenderingContext2D,
  x: (tm: number) => number,
  start: number, end: number, L: number, W: number, R: number, top: number, bottom: number,
  pulse: number | null,
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
  if (pulse !== null) {
    const cy = (top + bottom) / 2;
    c.globalAlpha = Math.max(0, 1 - pulse);
    c.strokeStyle = cssVar("--accent");
    c.lineWidth = 2;
    c.beginPath();
    c.arc(px, cy, 4 + pulse * 18, 0, Math.PI * 2);
    c.stroke();
  }
  c.restore();
}

function roundBox(c: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number): void {
  const rr = Math.min(r, w / 2, h / 2);
  c.beginPath();
  c.moveTo(x + rr, y);
  c.arcTo(x + w, y, x + w, y + h, rr);
  c.arcTo(x + w, y + h, x, y + h, rr);
  c.arcTo(x, y + h, x, y, rr);
  c.arcTo(x, y, x + w, y, rr);
  c.closePath();
}

function drawValueBubble(
  c: CanvasRenderingContext2D,
  W: number, H: number, L: number, R: number,
  anchorX: number,
  lines: readonly BubbleLine[],
): void {
  if (!lines.length || W < L + R + 90) return;
  const mono = cssVar("--mono");
  const sans = cssVar("--sans");
  const px = 8, py = 6, lineH = 14;
  let maxW = 0;
  for (const ln of lines) {
    c.font = ln.bold ? "600 11px " + sans : "11px " + mono;
    maxW = Math.max(maxW, c.measureText(ln.text).width);
  }
  const bw = Math.min(W - L - R - 6, Math.ceil(maxW + px * 2));
  const bh = py * 2 + lines.length * lineH - 2;
  let bx = anchorX + 10;
  if (bx + bw > W - R) bx = anchorX - 10 - bw;
  bx = Math.max(L + 2, Math.min(W - R - bw, bx));
  const by = Math.min(4, Math.max(2, H - 18 - bh));

  c.save();
  roundBox(c, bx, by, bw, bh, 6);
  c.fillStyle = cssVar("--panel");
  c.fill();
  c.strokeStyle = cssVar("--border");
  c.lineWidth = 1;
  c.stroke();
  c.clip();
  c.textAlign = "left";
  c.textBaseline = "top";
  lines.forEach((ln, idx) => {
    c.font = ln.bold ? "600 11px " + sans : "11px " + mono;
    c.fillStyle = ln.color ?? cssVar("--fg");
    c.fillText(ln.text, bx + px, by + py + idx * lineH);
  });
  c.restore();
}

/** Y-axis label, right-aligned 4 px left of the plot so it never touches the lines. */
function axisLabel(c: CanvasRenderingContext2D, text: string, left: number, y: number): void {
  const a = c.textAlign;
  c.textAlign = "right";
  c.fillText(text, left - 4, y);
  c.textAlign = a;
}

function bucketBubbleLines(b: MinuteBucket): BubbleLine[] {
  const [sLbl] = stateLabel(b.worst);
  const lines: BubbleLine[] = [
    { text: fmtTimeShort(b.t) + " · " + sLbl, color: cssVar("--fg"), bold: true },
    { text: ms(b.gw_rtt_avg) + " / " + ms(b.net_rtt_avg), color: cssVar("--net") },
  ];
  if (b.gw_fail || b.net_fail) {
    lines.push({ text: t("tl.fail", { gw: b.gw_fail, net: b.net_fail }), color: cssVar("--bad") });
  } else if (b.signal_dbm !== null || b.busy_pct !== null) {
    const extra: string[] = [];
    if (b.signal_dbm !== null) extra.push(b.signal_dbm + " dBm");
    if (b.busy_pct !== null) extra.push(Math.round(b.busy_pct) + "%");
    lines.push({ text: extra.join(" · "), color: cssVar("--sig") });
  }
  return lines;
}

function drawTimeline(
  canvas: HTMLCanvasElement,
  mode: TimelineMode,
  name: string,
  infoId: string,
  allBuckets: readonly MinuteBucket[],
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
  const compact = mode === "now";
  const failTop = 2, failH = compact ? 12 : 16;
  const rttTop = compact ? 18 : 22;
  const rttH = Math.round((H - rttTop - 16) * 0.56);
  const wTop = rttTop + rttH + 5, wH = Math.max(12, H - wTop - 16);
  const spanMin = Math.max(1, (end - start) / 60e3);
  const colWidth = Math.max(1.5, pw / spanMin);

  const buckets = allBuckets.filter((b) => {
    const tm = tOf(b);
    return tm + 60e3 >= start && tm <= end;
  });

  const x = drawTimeGrid(c, W, H, L, pw, start, end, hours, rttTop);
  axisLabel(c, t("tl.fail_axis"), L, failTop + (compact ? 10 : 12));

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
      const tm = tOf(b);
      if (v === null) { prevT = null; continue; }
      const px = x(tm) + colWidth / 2, py = yf(v);
      if (prevT === null || tm - prevT > 120e3) c.moveTo(px, py); else c.lineTo(px, py);
      prevT = tm;
    }
    c.stroke();
  };
  line("gw_rtt_avg", cssVar("--gw"), yR);
  line("net_rtt_avg", cssVar("--net"), yR);
  if (hasWifi) {
    const yS = (v: number): number => wTop + wH - ((Math.max(-90, Math.min(-30, v)) + 90) / 60) * wH;
    line("signal_dbm", cssVar("--sig"), yS);
  }

  if (mode === "sessions") {
    drawBrushBand(c, x, L, W, R, failTop, H - 14);
    drawHighlight(c, x, start, end, L, W, R, failTop, H - 14, pulseProgress);
  }
  if (hoverT !== null) {
    const hx = x(hoverT) + colWidth / 2;
    drawCrosshair(c, hx, L, W, R, failTop, H - 14);
    const hovered = buckets.find((b) => tOf(b) === hoverT);
    if (hovered) drawValueBubble(c, W, H, L, R, hx, bucketBubbleLines(hovered));
  }
  views.set(canvas, { mode, name, infoId, start, end, hours, L, pw, buckets, hoverT });
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
  const spanMin = Math.max(1, (end - start) / 60e3);
  const colWidth = Math.max(1.5, pw / spanMin);

  const x = drawTimeGrid(c, W, H, L, pw, start, end, hours, chartTop);
  axisLabel(c, t("tl.fail_axis"), L, failTop + 10);

  const failFrac = new Map<number, number>();
  for (const b of allBuckets) {
    const f = Math.max(b.gw_fail, b.net_fail);
    if (!f || !b.ticks) continue;
    const tm = tOf(b);
    if (tm < start || tm > end) continue;
    failFrac.set(tm, Math.max(failFrac.get(tm) ?? 0, Math.min(1, f / b.ticks)));
  }
  c.fillStyle = cssVar("--bad");
  for (const [tm, frac] of failFrac) {
    const h = Math.max(4, frac * failH);
    c.fillRect(x(tm), failTop + failH - h, Math.max(1.5, colWidth), h);
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

  drawBrushBand(c, x, L, W, R, failTop, H - 14);
  drawHighlight(c, x, start, end, L, W, R, failTop, H - 14, pulseProgress);
  if (hoverT !== null) {
    const hx = x(hoverT);
    drawCrosshair(c, hx, L, W, R, failTop, H - 14);
    const hovered = pts.find((p) => pOf(p) === hoverT);
    if (hovered) {
      drawValueBubble(c, W, H, L, R, hx, [
        { text: fmtTimeShort(hovered.t), color: cssVar("--fg"), bold: true },
        { text: "ARP " + hovered.arp_alive + " · ping " + hovered.ping_alive, color: cssVar("--info") },
      ]);
    }
  }
  lanViews.set(canvas, { infoId: "tl-info", start, end, hours, L, pw, points: pts, allBuckets, hoverT });
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

function redrawTimelineCanvas(cv: HTMLCanvasElement): void {
  const g = views.get(cv);
  if (!g) return;
  drawTimeline(cv, g.mode, g.name, g.infoId, g.buckets, g.hours, g.start, g.end);
}

function redrawLanCanvas(cv: HTMLCanvasElement): void {
  const g = lanViews.get(cv);
  if (!g) return;
  drawLanTimeline(cv, g.points, g.allBuckets, g.hours, g.start, g.end);
}

function redrawAllSessionCanvases(): void {
  const allBuckets = Object.values(state.minutes).flat();
  const [start, end] = sessionTimeWindow(state.minutes, state.lanSeries, state.hours);
  const hours = (end - start) / 3600e3;
  for (const item of sessionCanvases) {
    if (item.isLan) drawLanTimeline(item.cv, state.lanSeries, allBuckets, hours, start, end);
    else drawTimeline(item.cv, "sessions", item.name, "tl-info", state.minutes[item.name] ?? [], hours, start, end);
  }
}

function clearInfoText(infoId: string): void {
  byId(infoId).textContent = state.tlInspected ? "" : t("live.tl_hint");
}

function syncZoomBar(): void {
  const bar = byId("tl-zoom-bar");
  const br = state.brushRange;
  if (!br) {
    bar.hidden = true;
    byId("tl-zoom-label").textContent = "";
    return;
  }
  bar.hidden = false;
  byId("tl-zoom-label").textContent = t("tl.zoom_range", {
    from: fmtTimeShort(new Date(br[0]).toISOString()),
    to: fmtTimeShort(new Date(br[1]).toISOString()),
  });
}

/** Clears active brush-zoom on the Sessions timeline and optionally redraws + notifies listeners. */
export function resetBrushZoom(redraw = true): void {
  const had = state.brushRange !== null;
  state.brushRange = null;
  dragBand = null;
  syncZoomBar();
  if (had) {
    if (redraw) renderTimelines();
    bus.dispatchEvent(new Event("brush-change"));
  }
}

function attachTimelineHandlers(cv: HTMLCanvasElement, mode: TimelineMode, name: string, infoId: string): void {
  let drag: { id: number; x: number; t: number; active: boolean } | null = null;

  const clientToT = (clientX: number, g: TimelineView): number => {
    const r = cv.getBoundingClientRect();
    const frac = Math.max(0, Math.min(1, (clientX - r.left - g.L) / Math.max(1, g.pw)));
    return g.start + frac * (g.end - g.start);
  };

  const inspectAtX = (clientX: number): void => {
    const g = views.get(cv);
    if (!g || !g.buckets.length) return;
    const tm = clientToT(clientX, g);
    let best: MinuteBucket | null = null, bd = Infinity;
    for (const b of g.buckets) {
      const d = Math.abs(tOf(b) + 30e3 - tm);
      if (d < bd) { bd = d; best = b; }
    }
    const maxSnap = Math.max(5 * 60e3, (g.end - g.start) / 40);
    if (best && bd < maxSnap) {
      state.tlInspected = true;
      g.hoverT = tOf(best);
      redrawTimelineCanvas(cv);
      byId(infoId).textContent = bucketInfo(name, best);
    }
  };

  cv.addEventListener("pointerdown", (ev) => {
    const g = views.get(cv);
    if (!g) return;
    if (mode === "sessions" && ev.button === 0 && g.buckets.length) {
      drag = { id: ev.pointerId, x: ev.clientX, t: clientToT(ev.clientX, g), active: false };
      try { cv.setPointerCapture(ev.pointerId); } catch { /* ignore */ }
    }
    inspectAtX(ev.clientX);
  });

  cv.addEventListener("pointermove", (ev) => {
    const g = views.get(cv);
    if (!g) return;
    if (drag && drag.id === ev.pointerId && Math.abs(ev.clientX - drag.x) >= 6) {
      drag.active = true;
      const curT = clientToT(ev.clientX, g);
      dragBand = [Math.min(drag.t, curT), Math.max(drag.t, curT)];
      g.hoverT = null;
      redrawAllSessionCanvases();
      byId(infoId).textContent = fmtTimeShort(new Date(dragBand[0]).toISOString()) + " – " + fmtTimeShort(new Date(dragBand[1]).toISOString());
      return;
    }
    if (!drag) inspectAtX(ev.clientX);
  });

  const endDrag = (ev: PointerEvent): void => {
    if (!drag || drag.id !== ev.pointerId) return;
    const d = drag;
    drag = null;
    try { if (cv.hasPointerCapture(ev.pointerId)) cv.releasePointerCapture(ev.pointerId); } catch { /* ignore */ }
    const g = views.get(cv);
    if (d.active && g) {
      const curT = clientToT(ev.clientX, g);
      const t0 = Math.min(d.t, curT);
      const t1 = Math.max(d.t, curT);
      dragBand = null;
      if (t1 - t0 >= 2 * 60e3) {
        state.brushRange = [t0, t1];
        syncZoomBar();
        renderTimelines();
        bus.dispatchEvent(new Event("brush-change"));
        return;
      }
      redrawAllSessionCanvases();
      clearInfoText(infoId);
    }
  };
  cv.addEventListener("pointerup", endDrag);
  cv.addEventListener("pointercancel", endDrag);

  cv.addEventListener("pointerleave", () => {
    if (drag) return;
    const g = views.get(cv);
    if (g?.hoverT) {
      g.hoverT = null;
      redrawTimelineCanvas(cv);
      clearInfoText(infoId);
    }
  });

  cv.addEventListener("keydown", (ev) => {
    const g = views.get(cv);
    if (!g) return;
    if (ev.key === "Escape") {
      if (g.hoverT !== null) {
        g.hoverT = null;
        redrawTimelineCanvas(cv);
        clearInfoText(infoId);
      } else if (mode === "sessions" && state.brushRange) {
        resetBrushZoom();
      }
      return;
    }
    if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
    if (!g.buckets.length) return;
    ev.preventDefault();
    const step = ev.shiftKey ? 10 : 1;
    const dir = ev.key === "ArrowLeft" ? -step : step;
    let idx = g.hoverT !== null ? g.buckets.findIndex((b) => tOf(b) === g.hoverT) : -1;
    if (idx < 0) idx = dir < 0 ? g.buckets.length - 1 : 0;
    else idx = Math.max(0, Math.min(g.buckets.length - 1, idx + dir));
    const chosen = g.buckets[idx];
    if (!chosen) return;
    state.tlInspected = true;
    g.hoverT = tOf(chosen);
    redrawTimelineCanvas(cv);
    byId(infoId).textContent = bucketInfo(name, chosen);
  });
}

function attachLanHandlers(cv: HTMLCanvasElement): void {
  const inspectAtX = (clientX: number): void => {
    const g = lanViews.get(cv);
    if (!g || !g.points.length) return;
    const r = cv.getBoundingClientRect();
    const tm = g.start + ((clientX - r.left - g.L) / Math.max(1, g.pw)) * (g.end - g.start);
    let best: LanPoint | null = null, bd = Infinity;
    for (const p of g.points) {
      const d = Math.abs(pOf(p) - tm);
      if (d < bd) { bd = d; best = p; }
    }
    const maxSnap = Math.max(10 * 60e3, (g.end - g.start) / 25);
    if (best && bd < maxSnap) {
      state.tlInspected = true;
      g.hoverT = pOf(best);
      redrawLanCanvas(cv);
      byId("tl-info").textContent =
        t("tl.lan_info", { t: fmtTime(best.t), arp: best.arp_alive, ping: best.ping_alive, seen: best.unique_seen });
    }
  };

  cv.addEventListener("pointermove", (ev) => inspectAtX(ev.clientX));
  cv.addEventListener("pointerdown", (ev) => inspectAtX(ev.clientX));
  cv.addEventListener("pointerleave", () => {
    const g = lanViews.get(cv);
    if (g?.hoverT) {
      g.hoverT = null;
      redrawLanCanvas(cv);
      clearInfoText("tl-info");
    }
  });
  cv.addEventListener("keydown", (ev) => {
    const g = lanViews.get(cv);
    if (!g) return;
    if (ev.key === "Escape") {
      if (g.hoverT !== null) {
        g.hoverT = null;
        redrawLanCanvas(cv);
        clearInfoText("tl-info");
      } else if (state.brushRange) {
        resetBrushZoom();
      }
      return;
    }
    if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
    if (!g.points.length) return;
    ev.preventDefault();
    const dir = ev.key === "ArrowLeft" ? -1 : 1;
    let idx = g.hoverT !== null ? g.points.findIndex((p) => pOf(p) === g.hoverT) : -1;
    if (idx < 0) idx = dir < 0 ? g.points.length - 1 : 0;
    else idx = Math.max(0, Math.min(g.points.length - 1, idx + dir));
    const chosen = g.points[idx];
    if (!chosen) return;
    state.tlInspected = true;
    g.hoverT = pOf(chosen);
    redrawLanCanvas(cv);
    byId("tl-info").textContent =
      t("tl.lan_info", { t: fmtTime(chosen.t), arp: chosen.arp_alive, ping: chosen.ping_alive, seen: chosen.unique_seen });
  });
}

export function renderTimelines(): void {
  const box = byId("timelines");
  syncZoomBar();
  const names = Object.keys(state.minutes);
  const lan = state.lanSeries;
  if (!names.length && !lan.length) {
    sessionCanvases = [];
    box.replaceChildren(el("div", { class: "empty", text: t("tl.no_data") }));
    return;
  }
  const [start, end] = sessionTimeWindow(state.minutes, lan, state.hours);
  const hours = (end - start) / 3600e3;
  const canvases: { cv: HTMLCanvasElement; name: string; isLan: boolean }[] = names.map((name) => {
    const cv = el("canvas", {
      tabindex: 0,
      "data-iface": name,
      "aria-label": t("tl.aria", { n: name }) + ". " + t("tl.aria_keys"),
      role: "img",
    });
    attachTimelineHandlers(cv, "sessions", name, "tl-info");
    return { cv, name, isLan: false };
  });
  const nodes: HTMLElement[] = canvases.map(({ cv, name }) =>
    el("div", { class: "tl" }, el("div", { class: "tl-title", text: name }), cv),
  );
  if (lan.length) {
    const lanCv = el("canvas", {
      tabindex: 0,
      "aria-label": t("tl.lan_title") + ". " + t("tl.aria_keys"),
      role: "img",
    });
    attachLanHandlers(lanCv);
    canvases.push({ cv: lanCv, name: "", isLan: true });
    nodes.push(el("div", { class: "tl tl-lan" }, el("div", { class: "tl-title", text: t("tl.lan_title") }), lanCv));
  }
  sessionCanvases = canvases;
  box.replaceChildren(...nodes);
  const allBuckets = Object.values(state.minutes).flat();
  for (const item of canvases) {
    if (item.isLan) drawLanTimeline(item.cv, lan, allBuckets, hours, start, end);
    else drawTimeline(item.cv, "sessions", item.name, "tl-info", state.minutes[item.name] ?? [], hours, start, end);
  }
}

/** Compact 1-hour timeline rendered on the Now view. */
export function renderNowTimeline(): void {
  const box = byId("now-timelines");
  const names = Object.keys(state.liveMinutes);
  if (!names.length) {
    nowCanvases = [];
    box.replaceChildren(el("div", { class: "empty small", text: t("tl.no_data") }));
    return;
  }
  const [start, end] = nowTimeWindow();
  nowCanvases = names.map((name) => {
    const cv = el("canvas", {
      tabindex: 0,
      "data-iface": name,
      "aria-label": t("tl.aria", { n: name }) + ". " + t("tl.aria_keys"),
      role: "img",
    });
    attachTimelineHandlers(cv, "now", name, "now-tl-info");
    return { cv, name };
  });
  box.replaceChildren(...nowCanvases.map(({ cv, name }) =>
    el("div", { class: "tl tl-compact" }, el("div", { class: "tl-title", text: name }), cv),
  ));
  for (const { cv, name } of nowCanvases) {
    drawTimeline(cv, "now", name, "now-tl-info", state.liveMinutes[name] ?? [], 1, start, end);
  }
}

export function focusTimestamp(iso: string): void {
  const tm = new Date(iso).getTime();
  if (!isFinite(tm)) return;
  state.highlightTs = tm;
  if (state.brushRange && (tm < state.brushRange[0] || tm > state.brushRange[1])) {
    resetBrushZoom(false);
  }
  if (pulseRaf !== null) { cancelAnimationFrame(pulseRaf); pulseRaf = null; }
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    pulseProgress = null;
    renderTimelines();
  } else {
    renderTimelines();
    const t0 = performance.now();
    const step = (now: number): void => {
      const p = Math.min(1, (now - t0) / 600);
      pulseProgress = p;
      redrawAllSessionCanvases();
      if (p < 1) {
        pulseRaf = requestAnimationFrame(step);
      } else {
        pulseRaf = null;
        pulseProgress = null;
        redrawAllSessionCanvases();
      }
    };
    pulseRaf = requestAnimationFrame(step);
  }
  byId("tl-info").textContent = t("tl.focused", { t: fmtTime(iso) });
  byId("h-timeline").scrollIntoView({ behavior: "smooth", block: "start" });
}

export async function loadMinutes(): Promise<void> {
  const r = await fetchMinutes(state.selectedSession, state.hours);
  if (!r) {
    if (!Object.keys(state.minutes).length) {
      byId("timelines").replaceChildren(errorState(t("tl.load_err"), () => void loadMinutes()));
    }
    return;
  }
  state.minutes = r.ifaces;
  state.lanSeries = r.lan;
  renderTimelines();
  if (state.selectedSession === LIVE && state.hours === 1) {
    state.liveMinutes = r.ifaces;
    renderNowTimeline();
  }
}

/** Loads the last hour of minute buckets for the Now view. */
export async function loadLiveMinutes(): Promise<void> {
  const r = await fetchMinutes(LIVE, 1);
  if (!r) {
    if (!Object.keys(state.liveMinutes).length) {
      byId("now-timelines").replaceChildren(errorState(t("tl.load_err"), () => void loadLiveMinutes()));
    }
    return;
  }
  state.liveMinutes = r.ifaces;
  renderNowTimeline();
}
