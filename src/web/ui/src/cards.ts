// App bar (context chip, verdict, menu facts) and the per-interface path rows of the Now view.

import type { IfaceStatus } from "./api/IfaceStatus.js";
import type { Sample } from "./api/Sample.js";
import { byId, cssVar, el, prepareCanvas } from "./dom.js";
import { band, fmtDur, fmtTimeShort, ms, secsSince, sigPct, stateLabel, verdictLabel } from "./format.js";
import { t } from "./i18n.js";
import { pointLabel } from "./points.js";
import { type LivePoint, state } from "./state.js";
import { busyTone, sigTone } from "./status.js";
import { type TipKey, tip } from "./tips.js";
import { renderTopology } from "./wifi.js";

/** Seconds kept in the per-interface sparkline. */
const RING_SECS = 60;

export function renderHeader(): void {
  const s = state.status;
  if (!s) return;
  const [label, cls] = verdictLabel(s.verdict);
  const v = byId("verdict");
  v.textContent = label;
  v.className = "pill " + cls;
  v.title = s.verdict_since ? t("hero.since", { t: fmtTimeShort(s.verdict_since) }) : "";
  const m = s.session;
  const parts: string[] = [];
  parts.push(m?.point ? pointLabel(m.point) : t("ctx.no_point"));
  if (s.started) parts.push(fmtDur(secsSince(s.started)));
  byId("session").textContent = parts.join(" · ");
  const canSwitch = Boolean(state.control?.enabled);
  byId("switch-pt-btn").hidden = !canSwitch;

  const foot: string[] = [];
  if (m?.version) foot.push("linkwatch " + m.version);
  if (m?.session) foot.push(t("menu.session", { id: m.session }));
  if (s.isp_hop) foot.push(t("menu.isp", { ip: s.isp_hop }));
  byId("foot").textContent = foot.join(" · ");
  const c = state.control;
  byId("menu-access").textContent = !c
    ? ""
    : c.enabled
      ? t("menu.control_on")
      : t("menu.read_only");
}

function kv(dl: HTMLDListElement, k: string, v: string, cls?: string, tkey?: TipKey): void {
  dl.append(
    tkey ? el("dt", { class: "tip-dt" }, k, tip(tkey)) : el("dt", { text: k }),
    el("dd", { text: v, class: cls }),
  );
}

/** Adds one sample to the interface's sparkline ring. */
export function recordSamplePoint(sample: Sample): void {
  const name = sample.iface;
  if (!name) return;
  const ring = state.liveRing.get(name) ?? [];
  ring.push({
    gw: sample.gw && sample.gw.ok ? (sample.gw.rtt_ms ?? null) : null,
    net: sample.net.rtt_ms ?? null,
    state: sample.state,
  });
  if (ring.length > RING_SECS) ring.shift();
  state.liveRing.set(name, ring);
}

function drawSparkline(canvas: HTMLCanvasElement, pts: readonly LivePoint[]): void {
  const cv = prepareCanvas(canvas);
  if (!cv || !pts.length) return;
  const { c, W, H } = cv;
  const vals: number[] = [];
  for (const p of pts) {
    if (p.gw !== null) vals.push(p.gw);
    if (p.net !== null) vals.push(p.net);
  }
  const maxV = Math.min(800, Math.max(20, vals.length ? Math.max(...vals) * 1.15 : 50));
  const N = Math.max(pts.length, 20);
  const stepX = W / Math.max(1, N - 1);
  const x0 = W - (pts.length - 1) * stepX;
  c.fillStyle = cssVar("--bad-bg");
  pts.forEach((p, idx) => {
    if (p.state !== "ok" && p.state !== "degraded" && p.state !== "unknown") {
      c.fillRect(x0 + idx * stepX - Math.max(1, stepX / 2), 0, Math.max(2, stepX), H);
    }
  });
  const drawSeries = (key: "gw" | "net", color: string): void => {
    c.strokeStyle = color;
    c.lineWidth = 1.5;
    c.beginPath();
    let started = false;
    pts.forEach((p, idx) => {
      const v = p[key];
      if (v === null) { started = false; return; }
      const px = x0 + idx * stepX;
      const py = H - 3 - (Math.min(v, maxV) / maxV) * (H - 6);
      if (!started) { c.moveTo(px, py); started = true; } else c.lineTo(px, py);
    });
    c.stroke();
  };
  drawSeries("gw", cssVar("--gw"));
  drawSeries("net", cssVar("--net"));
}

function metric(label: string, tkey: TipKey | null, value: string, cls: string): HTMLElement {
  return el("div", { class: "metric" },
    el("span", { class: "lbl" }, label, tkey ? tip(tkey) : null),
    el("span", { class: "val " + cls, text: value }));
}

function roleText(role: IfaceStatus["role"]): string {
  return role === "wifi" ? "Wi-Fi" : role === "ethernet" ? t("role.ethernet") : role ?? "";
}

function pathRow(name: string, i: IfaceStatus, sparks: [HTMLCanvasElement, string][]): HTMLElement {
  const last: Partial<Sample> = i.last ?? {};
  if (!state.liveRing.has(name) && i.last) recordSamplePoint(i.last);
  const [label, cls] = stateLabel(i.state ?? last.state);
  const stateBad = cls === "bad";

  // Numbers come from the last sample; while the debounced state says the path is down they
  // are shown muted, so a green number never sits next to a red state.
  const gwTxt = last.gw ? (last.gw.ok ? ms(last.gw.rtt_ms) : t("now.fail")) : "–";
  const gwCls = !last.gw ? "" : !last.gw.ok ? "err" : stateBad ? "stale" : "gw";
  const net = last.net;
  const netTxt = net && net.of ? (net.rtt_ms !== undefined ? ms(net.rtt_ms) : t("now.down")) : "–";
  const netCls = !net || !net.of ? "" : !net.ok ? "err" : stateBad ? "stale" : "net";
  const metrics = el("div", { class: "path-metrics" },
    metric(t("now.router_rtt"), "router_rtt", gwTxt, gwCls),
    metric(t("now.internet_rtt"), "net_rtt", netTxt, netCls));
  const w = i.wifi;
  if (w?.connected) {
    const sig = w.signal_avg_dbm ?? w.signal_dbm;
    if (sig !== undefined) metrics.append(metric(t("now.signal"), "signal", sig + " dBm", sigTone(sig) === "bad" ? "err" : ""));
  }

  const canvas = el("canvas", { class: "spark", role: "img", "aria-label": t("now.spark_aria", { iface: name }) });
  sparks.push([canvas, name]);

  const notes: string[] = [];
  if (i.state_since) notes.push(t("now.state_since", { t: fmtTimeShort(i.state_since), d: fmtDur(secsSince(i.state_since)) }));
  if (stateBad && last.gw?.ok) notes.push(t("now.last_probe_ok"));
  if (last.dns && !last.dns.ok) notes.push(t("now.dns_fail", { err: last.dns.err || "?" }));
  if (w && !w.connected) notes.push(t("now.not_assoc"));

  const moreDl = el("dl", { class: "kv" });
  if (last.link) kv(moreDl, t("now.address"), last.link.ipv4 ? last.link.ipv4 + "/" + (last.link.prefix_len ?? "") : t("now.none"));
  if (last.isp) kv(moreDl, t("now.isp_hop"), last.isp.ok ? ms(last.isp.rtt_ms) : (last.isp.err || t("now.no_reply")));
  if (last.dns?.ok) kv(moreDl, "DNS", ms(last.dns.rtt_ms));
  if (net && net.of) kv(moreDl, t("now.internet_ok"), net.ok + " / " + net.of);
  if (w?.connected) {
    const sig = w.signal_avg_dbm ?? w.signal_dbm;
    if (sig !== undefined) {
      moreDl.append(
        el("dt", { class: "tip-dt" }, t("now.signal"), tip("signal")),
        el("dd", null, el("span", { class: "sig-cell" },
          el("progress", { class: "sig-prog", max: 100, value: sigPct(sig) }),
          el("span", { text: sig + " dBm" }))));
    }
    const chParts: (string | number)[] = [w.channel ?? "?"];
    if (w.width_mhz) chParts.push(w.width_mhz + " MHz");
    if (w.freq_mhz) chParts.push(band(w.freq_mhz));
    kv(moreDl, t("now.channel"), chParts.join(" · "));
    if (w.ssid) kv(moreDl, "SSID", w.ssid);
    if (w.tx_bitrate_mbps) kv(moreDl, t("now.bitrate"), Math.round(w.tx_bitrate_mbps) + " / " + Math.round(w.rx_bitrate_mbps || 0) + " Mbit/s");
    if (w.tx_retries || w.tx_failed) kv(moreDl, t("now.retries"), String(w.tx_retries || 0) + (w.tx_failed ? " (" + t("now.failed_n", { n: w.tx_failed }) + ")" : ""), undefined, "tx_retries");
    if (w.power_save === true) kv(moreDl, t("now.power_save"), t("now.ps_on"), "err", "power_save");
    else if (w.power_save === false) kv(moreDl, t("now.power_save"), t("now.off"), "ok", "power_save");
  }
  if (i.channel_load) {
    const b = i.channel_load.busy_pct;
    kv(moreDl, t("now.busy"), b.toFixed(1) + " %", busyTone(b) === "bad" ? "err" : "", "channel_busy");
  }
  if (i.ticks) {
    kv(moreDl, t("now.failures"), t("now.failures_val", { gw: i.gw_fail, net: i.net_fail, n: i.ticks }), undefined, "failures");
    kv(moreDl, t("now.down_total"), fmtDur(i.down_s));
  }
  const more = el("details", {
    class: "card-more",
    open: state.openCardDetails.has(name),
    ontoggle: (ev: Event) => {
      const det = ev.currentTarget;
      if (det instanceof HTMLDetailsElement) {
        if (det.open) state.openCardDetails.add(name);
        else state.openCardDetails.delete(name);
      }
    },
  }, el("summary", { text: t("now.details") }), moreDl);

  return el("article", { class: "path " + cls },
    el("div", { class: "path-head" },
      el("span", { class: "path-name" },
        el("span", { class: "name", text: name }),
        el("span", { class: "muted small", text: roleText(i.role) })),
      el("span", { class: "pill small " + cls, text: label })),
    metrics,
    canvas,
    notes.length ? el("div", { class: "path-note", text: notes.join(" · ") }) : null,
    more);
}

export function renderCards(): void {
  const s = state.status;
  const box = byId("ifaces");
  if (!s) return;
  renderTopology();
  const names = Object.keys(s.ifaces);
  if (!names.length) {
    box.replaceChildren(el("div", { class: "empty-state" },
      el("strong", { text: t("now.no_ifaces") }),
      el("span", { text: t("now.no_ifaces_hint") })));
    return;
  }
  const sparks: [HTMLCanvasElement, string][] = [];
  const rows = names.flatMap((name) => {
    const i = s.ifaces[name];
    return i ? [pathRow(name, i, sparks)] : [];
  });
  box.replaceChildren(...rows);
  for (const [cv, name] of sparks) drawSparkline(cv, state.liveRing.get(name) ?? []);
}
