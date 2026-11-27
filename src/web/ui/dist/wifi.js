// Network path topology, neighbour networks and channel spectrum.
import { fetchScan } from "./client.js";
import { byId, cssVar, el, patch, prepareCanvas } from "./dom.js";
import { band, classifyBss, fmtDur, freqToChannel, ms, sigPct, stateLabel, } from "./format.js";
import { renderSite } from "./site.js";
import { state } from "./state.js";
import { t } from "./i18n.js";
import { tip } from "./tips.js";
import { busyTone, sigTone } from "./status.js";
import { kv } from "./ui.js";
// ---------- path strip (Now view) ----------
function routerRateText(r) {
    if (!r)
        return "";
    if (typeof r.wan_rx_mbps === "number" || typeof r.wan_tx_mbps === "number") {
        return (r.wan_rx_mbps ?? 0).toFixed(1) + "↓ / " + (r.wan_tx_mbps ?? 0).toFixed(1) + "↑ Mbit/s";
    }
    if (typeof r.wan_rx_pps === "number" || typeof r.wan_tx_pps === "number") {
        return Math.round(r.wan_rx_pps ?? 0) + "↓ / " + Math.round(r.wan_tx_pps ?? 0) + "↑ pps";
    }
    if (r.link_down_mbps)
        return "WAN " + Math.round(r.link_down_mbps) + " Mbit/s";
    return "";
}
function linkTone(st, gw) {
    if (!st || st === "unknown")
        return "neutral";
    if (st === "link_down" || st === "no_ip" || st === "lan_down")
        return "bad";
    if (st === "degraded")
        return "warn";
    if (gw && !gw.ok)
        return "warn";
    return "ok";
}
/** Best state of one hop over all interfaces that have a link. */
function aggHopStatus(ifaces, pick) {
    let anyOk = false, anyFail = false, bestRtt = null;
    for (const i of ifaces) {
        const l = i.last;
        if (!l || !l.link.carrier)
            continue;
        const h = pick(l);
        if (!h)
            continue;
        if (h.ok) {
            anyOk = true;
            if (typeof h.rtt_ms === "number" && (bestRtt === null || h.rtt_ms < bestRtt))
                bestRtt = h.rtt_ms;
        }
        else if (h.failed) {
            anyFail = true;
        }
    }
    const cls = anyOk ? (anyFail ? "warn" : "ok") : anyFail ? "bad" : "neutral";
    return { cls, rtt: bestRtt };
}
function hopBox(tone, name, sub, extra) {
    return el("div", { class: "hop-box " + tone, role: "listitem" }, el("span", { class: "hop-name" }, el("span", { class: "dot " + tone }), name), sub ? el("span", { class: "hop-sub", text: sub }) : null, extra ?? null);
}
function edge(tone) {
    return el("span", { class: "edge " + tone, "aria-hidden": "true" });
}
/** This device → one tag per interface → router → provider → internet, as wrapping HTML. */
export function renderTopology() {
    const box = byId("topo");
    const s = state.status;
    if (!s)
        return;
    const names = Object.keys(s.ifaces);
    const rtr = s.router;
    const lan = s.lan;
    const meta = [];
    if (rtr) {
        for (const part of [rtr.model, rtr.wan_status, rtr.uptime_s !== undefined ? t("now.uptime", { d: fmtDur(rtr.uptime_s) }) : null, routerRateText(rtr)]) {
            if (part)
                meta.push(part);
        }
    }
    if (lan)
        meta.push(t("now.lan_devices", { n: lan.arp_alive, seen: lan.unique_seen }));
    byId("topo-router-meta").textContent = meta.join(" · ");
    if (!names.length) {
        box.replaceChildren(el("div", { class: "empty", text: t("now.waiting_samples") }));
        return;
    }
    const ifObjs = names.flatMap((n) => s.ifaces[n] ?? []);
    const h = s.host;
    const psOn = Object.values(h?.wifi_power_save ?? {}).some(Boolean);
    const hostTone = h?.throttled ? "bad" : psOn ? "warn" : "info";
    const hostSub = h
        ? [h.cpu_pct !== undefined ? "CPU " + Math.round(h.cpu_pct) + "%" : null, h.temp_c !== undefined ? Math.round(h.temp_c) + "°C" : null]
            .filter(Boolean).join(" · ")
        : null;
    // Interfaces: one tag per path, worst tone colours the edge into the router.
    const order = ["neutral", "ok", "info", "warn", "bad"];
    const tones = [];
    const tags = names.map((name) => {
        const il = s.ifaces[name];
        const last = il?.last ?? {};
        const st = il?.state ?? last.state;
        const tone = linkTone(st, last.gw);
        tones.push(tone);
        let txt = name;
        if (st === "link_down")
            txt += " · " + t("pstate.link_down");
        else if (st === "no_ip")
            txt += " · " + t("pstate.no_ip");
        else if (last.gw && !last.gw.ok)
            txt += " · " + t("now.router_timeout");
        else if (last.gw?.ok)
            txt += " · " + ms(last.gw.rtt_ms);
        const w = il?.wifi;
        if (w?.connected) {
            const sig = w.signal_avg_dbm ?? w.signal_dbm;
            txt += " · " + [w.freq_mhz ? band(w.freq_mhz) : "", sig !== undefined ? sig + " dBm" : ""].filter(Boolean).join(" ");
        }
        return el("span", { class: "link-tag " + tone }, el("span", { class: "dot " + tone }), txt);
    });
    const worst = tones.reduce((w, x) => (order.indexOf(x) > order.indexOf(w) ? x : w), "ok");
    const isp = aggHopStatus(ifObjs, (l) => (l.isp ? { ok: l.isp.ok, failed: !l.isp.ok, rtt_ms: l.isp.rtt_ms } : null));
    const net = aggHopStatus(ifObjs, (l) => (l.net.of ? { ok: l.net.ok > 0, failed: l.net.ok === 0, rtt_ms: l.net.rtt_ms } : null));
    const dns = aggHopStatus(ifObjs, (l) => (l.dns ? { ok: l.dns.ok, failed: !l.dns.ok, rtt_ms: l.dns.rtt_ms } : null));
    const gwIp = ifObjs.find((il) => il.last?.link.gateway)?.last?.link.gateway ?? null;
    const rtrBad = s.verdict === "router_problem" || Boolean(rtr?.wan_status && rtr.wan_status.toLowerCase() !== "connected");
    const rtrTone = rtrBad ? "bad" : worst === "bad" && names.length === 1 ? "warn" : "ok";
    const netTone = net.cls === "ok" && dns.cls === "bad" ? "warn" : net.cls;
    const netSub = [net.rtt !== null ? ms(net.rtt) : null, dns.cls === "bad" ? t("now.dns_fail_short") : null].filter(Boolean).join(" · ");
    patch(box, el("div", { class: "hop" }, hopBox(hostTone, s.session?.host || t("now.this_device"), hostSub || null), edge(worst)), el("div", { class: "hop" }, el("div", { class: "hop-links", role: "listitem" }, ...tags), edge(worst)), el("div", { class: "hop" }, hopBox(rtrTone, t("now.router"), gwIp), edge(isp.cls)), el("div", { class: "hop" }, hopBox(isp.cls, t("now.provider"), s.isp_hop ? (isp.rtt !== null ? ms(isp.rtt) : s.isp_hop) : t("now.discovering")), edge(netTone)), el("div", { class: "hop" }, hopBox(netTone, t("now.internet"), netSub || null)));
}
const CENTER_CH_5GHZ_40 = {
    36: 38, 40: 38, 44: 46, 48: 46, 52: 54, 56: 54, 60: 62, 64: 62,
    100: 102, 104: 102, 108: 110, 112: 110, 116: 118, 120: 118,
    124: 126, 128: 126, 132: 134, 136: 134, 140: 142, 144: 142,
    149: 151, 153: 151, 157: 159, 161: 159,
};
const CENTER_CH_5GHZ_80 = {
    36: 42, 40: 42, 44: 42, 48: 42, 52: 58, 56: 58, 60: 58, 64: 58,
    100: 106, 104: 106, 108: 106, 112: 106, 116: 122, 120: 122, 124: 122, 128: 122,
    132: 138, 136: 138, 140: 138, 144: 138, 149: 155, 153: 155, 157: 155, 161: 155,
};
const CENTER_CH_5GHZ_160 = {
    36: 50, 40: 50, 44: 50, 48: 50, 52: 50, 56: 50, 60: 50, 64: 50,
    100: 114, 104: 114, 108: 114, 112: 114, 116: 114, 120: 114, 124: 114, 128: 114,
};
/** Channels covered by a network of the given primary channel and width. */
function spectrumSpan(ch, widthMhz, bBand) {
    const w = widthMhz || 20;
    let center = ch;
    if (bBand === "5 GHz") {
        const c160 = CENTER_CH_5GHZ_160[ch], c80 = CENTER_CH_5GHZ_80[ch], c40 = CENTER_CH_5GHZ_40[ch];
        if (w >= 160 && c160)
            center = c160;
        else if (w >= 80 && c80)
            center = c80;
        else if (w >= 40 && c40)
            center = c40;
    }
    const half = Math.max(2, Math.round(w / 10));
    return { center, lo: center - half, hi: center + half, w };
}
function roleColorVar(metaId) {
    if (metaId === "connected")
        return "--ok";
    if (metaId === "same_router_band" || metaId === "same_router_vap")
        return "--info";
    if (metaId === "same_ssid_other" || metaId === "adjacent")
        return "--warn";
    if (metaId === "co_channel")
        return "--bad";
    return "--muted";
}
const specViews = new WeakMap();
function hasSignal(x) {
    return x.b.signal_dbm !== undefined;
}
function drawSpectrum(canvas, cfg) {
    const hoverCh = specViews.get(canvas)?.hoverCh ?? null;
    const cv = prepareCanvas(canvas);
    if (!cv)
        return;
    const { c, W, H } = cv;
    const L = 32, R = 10, T = 10, B = 20;
    const pw = W - L - R, ph = H - T - B;
    const xOf = (ch) => L + ((ch - cfg.minCh) / (cfg.maxCh - cfg.minCh)) * pw;
    const yOf = (dbm) => T + ph - ((Math.max(-95, Math.min(-30, dbm)) + 95) / 65) * ph;
    c.font = "10px " + cssVar("--mono");
    c.strokeStyle = cssVar("--grid");
    c.fillStyle = cssVar("--muted");
    c.lineWidth = 1;
    for (const dbm of [-40, -60, -80]) {
        const py = Math.round(yOf(dbm)) + 0.5;
        c.beginPath();
        c.moveTo(L, py);
        c.lineTo(W - R, py);
        c.stroke();
        c.fillText(String(dbm), 2, py + 3);
    }
    for (const ch of cfg.ticks) {
        const px = Math.round(xOf(ch)) + 0.5;
        c.beginPath();
        c.moveTo(px, T);
        c.lineTo(px, T + ph);
        c.stroke();
        c.fillText(String(ch), px - c.measureText(String(ch)).width / 2, H - 5);
    }
    c.beginPath();
    c.moveTo(L, T + ph + 0.5);
    c.lineTo(W - R, T + ph + 0.5);
    c.stroke();
    const prio = (x) => x.meta.id === "connected" ? 4 : x.meta.group === "ours" ? 3 : x.meta.group === "interfering" ? 2 : 1;
    const ordered = [...cfg.items].sort((a, b) => prio(a) - prio(b) || (a.b.signal_dbm ?? -100) - (b.b.signal_dbm ?? -100));
    const drawn = [];
    for (const item of ordered) {
        const ch = item.meta.ch;
        if (!ch || !hasSignal(item))
            continue;
        const sp = spectrumSpan(ch, item.b.width_mhz, cfg.bandName);
        const x1 = Math.max(L, xOf(sp.lo)), x2 = Math.min(W - R, xOf(sp.hi));
        if (x2 <= x1)
            continue;
        const yPeak = yOf(item.b.signal_dbm);
        const yBase = T + ph;
        const inset = Math.min(10, (x2 - x1) * 0.16);
        const col = cssVar(roleColorVar(item.meta.id));
        c.save();
        c.beginPath();
        c.moveTo(x1, yBase);
        c.lineTo(x1 + inset, yPeak);
        c.lineTo(x2 - inset, yPeak);
        c.lineTo(x2, yBase);
        c.closePath();
        c.globalAlpha = item.meta.id === "connected" ? 0.24 : item.meta.group === "neighbour" ? 0.08 : 0.16;
        c.fillStyle = col;
        c.fill();
        c.globalAlpha = item.meta.id === "connected" ? 1 : item.meta.group === "neighbour" ? 0.65 : 0.92;
        c.strokeStyle = col;
        c.lineWidth = item.meta.id === "connected" ? 2.4 : 1.5;
        c.stroke();
        c.restore();
        drawn.push({ item, ch, sp, cx: (x1 + x2) / 2, yPeak });
    }
    // Labels for own / top APs (avoid crowding)
    const placed = [];
    for (const d of [...drawn].reverse()) {
        if (placed.length >= 7)
            break;
        const name = d.item.b.ssid || ("(" + d.item.b.bssid.slice(-5) + ")");
        const lbl = name.length > 14 ? name.slice(0, 13) + "…" : name;
        const tw = c.measureText(lbl).width + 6;
        const lx = Math.max(L + tw / 2, Math.min(W - R - tw / 2, d.cx));
        const ly = Math.max(T + 10, d.yPeak - 4);
        if (placed.some((p) => Math.abs(p.x - lx) < (p.w + tw) * 0.45 && Math.abs(p.y - ly) < 12))
            continue;
        c.fillStyle = cssVar(roleColorVar(d.item.meta.id));
        c.fillText(lbl, lx - tw / 2 + 3, ly);
        placed.push({ x: lx, y: ly, w: tw });
    }
    if (hoverCh !== null) {
        const hx = xOf(hoverCh);
        if (hx >= L && hx <= W - R) {
            c.save();
            c.strokeStyle = cssVar("--crosshair");
            c.setLineDash([3, 3]);
            c.beginPath();
            c.moveTo(hx, T);
            c.lineTo(hx, T + ph);
            c.stroke();
            c.restore();
        }
    }
    specViews.set(canvas, { cfg, L, pw, drawn, hoverCh });
}
function onSpecPointer(cv, ev) {
    const g = specViews.get(cv);
    if (!g)
        return;
    const r = cv.getBoundingClientRect();
    const ch = Math.round(g.cfg.minCh + ((ev.clientX - r.left - g.L) / g.pw) * (g.cfg.maxCh - g.cfg.minCh));
    if (ch < g.cfg.minCh || ch > g.cfg.maxCh)
        return;
    g.hoverCh = ch;
    drawSpectrum(cv, g.cfg);
    const hits = (specViews.get(cv)?.drawn ?? g.drawn)
        .filter((d) => ch >= d.sp.lo && ch <= d.sp.hi)
        .sort((a, b) => b.item.b.signal_dbm - a.item.b.signal_dbm);
    const txt = hits.length
        ? g.cfg.bandName + " ch " + ch + ": " + hits.slice(0, 4).map((d) => (d.item.b.ssid || t("wifi.hidden")) + " ch " + d.ch + "/" + d.sp.w + " MHz " +
            Math.round(d.item.b.signal_dbm) + " dBm [" + d.item.meta.label + "]").join(" · ") + (hits.length > 4 ? " " + t("wifi.more", { n: hits.length - 4 }) : "")
        : g.cfg.bandName + " ch " + ch + ": " + t("wifi.clear");
    byId("scan-spec-info").textContent = txt;
}
function onSpecLeave(cv) {
    const g = specViews.get(cv);
    if (g && g.hoverCh !== null) {
        g.hoverCh = null;
        drawSpectrum(cv, g.cfg);
    }
}
function renderSpectrum(allClassified) {
    const box = byId("scan-spectrum");
    const b24 = allClassified.filter((x) => x.meta.bBand === "2.4 GHz");
    const b5 = allClassified.filter((x) => x.meta.bBand === "5 GHz");
    const panels = [];
    if (state.scanFilter !== "5" && b24.length) {
        panels.push({
            bandName: "2.4 GHz",
            minCh: -1,
            maxCh: 15,
            ticks: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            items: b24,
        });
    }
    if (state.scanFilter !== "2.4" && b5.length) {
        panels.push({
            bandName: "5 GHz",
            minCh: 30,
            maxCh: 170,
            ticks: [36, 52, 64, 100, 116, 132, 149, 165],
            items: b5,
        });
    }
    box.className = "spec-grid" + (panels.length >= 2 ? " two" : "");
    const canvases = panels.map((cfg) => {
        const cv = el("canvas", { role: "img", "aria-label": t("wifi.spectrum", { band: cfg.bandName }) });
        cv.addEventListener("pointermove", (ev) => onSpecPointer(cv, ev));
        cv.addEventListener("pointerdown", (ev) => onSpecPointer(cv, ev));
        cv.addEventListener("pointerleave", () => onSpecLeave(cv));
        return [cv, cfg];
    });
    box.replaceChildren(...canvases.map(([cv, cfg]) => el("div", { class: "spec-card" }, el("div", { class: "spec-title" }, el("span", { text: t("wifi.spectrum", { band: cfg.bandName }) }), el("span", { text: t("wifi.n_aps", { n: cfg.items.length }) })), cv)));
    for (const [cv, cfg] of canvases)
        drawSpectrum(cv, cfg);
}
// ---------- neighbour networks ----------
/**
 * A MAC/BSSID shown as its last three octets (enough to tell radios apart, safer on a shared
 * screen); a click shows the full value.
 */
/** Addresses the user chose to show in full (survives the live re-render). */
const revealed = new Set();
export function maskedMac(mac) {
    const parts = mac.split(":");
    const short = parts.length === 6 ? "…:" + parts.slice(3).join(":") : mac;
    const b = el("button", {
        type: "button",
        class: "mac-btn mono small",
        "data-key": "mac:" + mac,
        "aria-pressed": revealed.has(mac) ? "true" : "false",
        text: revealed.has(mac) ? mac : short,
        "aria-label": t("wifi.reveal"),
    });
    b.addEventListener("click", () => {
        if (revealed.has(mac))
            revealed.delete(mac);
        else
            revealed.add(mac);
        b.textContent = revealed.has(mac) ? mac : short;
        b.setAttribute("aria-pressed", revealed.has(mac) ? "true" : "false");
    });
    return b;
}
const groupOrder = (m) => (m.group === "ours" ? 0 : m.group === "interfering" ? 1 : 2);
export function renderScan() {
    const box = byId("scan");
    const sumBox = byId("scan-summary");
    const ifaces = Object.keys(state.scan);
    if (!ifaces.length) {
        sumBox.replaceChildren();
        byId("scan-spectrum").replaceChildren();
        box.replaceChildren(el("div", { class: "empty", text: t("wifi.no_scan") }));
        return;
    }
    let totalBss = 0, routerBss = 0, coCh = 0, adjCh = 0, sameSsidOther = 0;
    const allForSpec = [];
    const chunks = [];
    for (const iface of ifaces) {
        const s = state.scan[iface];
        if (!s)
            continue;
        const rep = s.report;
        const oursCh = s.our_channel ?? freqToChannel(s.our_freq_mhz);
        const classified = rep.bss.map((b) => ({ b, meta: classifyBss(b, s) }));
        totalBss += classified.length;
        for (const c of classified) {
            const id = c.meta.id;
            if (id === "connected" || id === "same_router_band" || id === "same_router_vap")
                routerBss += 1;
            else if (id === "same_ssid_other")
                sameSsidOther += 1;
            else if (id === "co_channel")
                coCh += 1;
            else if (id === "adjacent")
                adjCh += 1;
        }
        const filtered = classified.filter(({ meta }) => {
            if (state.scanFilter === "ours")
                return meta.group === "ours";
            if (state.scanFilter === "interfering")
                return meta.group === "interfering";
            if (state.scanFilter === "2.4")
                return meta.bBand === "2.4 GHz";
            if (state.scanFilter === "5")
                return meta.bBand === "5 GHz";
            return true;
        });
        allForSpec.push(...filtered);
        filtered.sort((a, b) => {
            const ga = groupOrder(a.meta);
            const gb = groupOrder(b.meta);
            if (ga !== gb)
                return ga - gb;
            if (a.meta.rank !== b.meta.rank && ga === 0)
                return a.meta.rank - b.meta.rank;
            return (b.b.signal_dbm ?? -200) - (a.b.signal_dbm ?? -200);
        });
        const otherSameCh = classified.filter(({ meta }) => oursCh && meta.ch === oursCh && meta.id !== "connected").length;
        chunks.push(el("div", { class: "scan-head" }, iface + (s.our_ssid ? " (" + s.our_ssid + ")" : "") +
            " · " + t("wifi.showing", { a: filtered.length, b: classified.length }) +
            (oursCh ? " · " + t("wifi.our_ch", { ch: oursCh, n: otherSameCh }) : "") +
            " · " + t(rep.fresh ? "wifi.active_scan" : "wifi.cached_scan")));
        const securityCell = (b) => {
            const sec = b.security;
            const cls = sec === "Open" || sec === "WEP" ? "bad"
                : sec === "WPA" || sec === "WPA2-TKIP" ? "warn"
                    : sec && sec.includes("WPA3") ? "ok"
                        : "neutral";
            const children = [
                sec ? el("span", { class: "pill small " + cls, text: sec }) : "–",
            ];
            if (b.wps)
                children.push(" ", el("span", { class: "sec-wps", text: "WPS" }));
            return el("td", { title: b.pmf ? "PMF: " + b.pmf : null }, ...children);
        };
        const rows = filtered.map(({ b, meta }) => {
            const sig = b.signal_dbm;
            return el("tr", { class: meta.rowCls || null }, el("td", { text: b.ssid || t("wifi.hidden") }), el("td", null, el("span", { class: "pill small " + meta.cls, text: meta.label })), el("td", { class: "num", text: meta.ch ?? "?" }), el("td", { class: "num", text: b.width_mhz ? b.width_mhz + " MHz" : "–" }), el("td", { text: meta.bBand || "–" }), securityCell(b), el("td", { class: "num" }, sig !== undefined
                ? el("span", { class: "sig-cell" }, el("progress", { class: "sig-prog", max: 100, value: sigPct(sig) }), el("span", { text: Math.round(sig) + " dBm" }))
                : "–"), el("td", { class: "mono small" }, maskedMac(b.bssid)));
        });
        if (!rows.length)
            rows.push(el("tr", null, el("td", { colspan: 8, class: "empty", text: t("wifi.empty") })));
        chunks.push(el("div", { class: "scroll" }, el("table", null, el("thead", null, el("tr", null, el("th", { text: t("wifi.th_ssid") }), el("th", { text: t("wifi.th_role") }), el("th", { class: "num", text: t("wifi.th_ch") }), el("th", { class: "num", text: t("wifi.th_width") }), el("th", { text: t("wifi.th_band") }), el("th", null, t("wifi.th_sec") + " ", tip("wifi_sec")), el("th", { class: "num", text: t("wifi.th_sig") }), el("th", { text: t("wifi.th_bssid") }))), el("tbody", null, ...rows))));
    }
    const chips = [
        el("span", { class: "host-chip", text: t("wifi.chip_seen", { n: totalBss }) }),
        el("span", { class: "host-chip ok", text: t("wifi.chip_router", { n: routerBss }) }),
    ];
    if (sameSsidOther)
        chips.push(el("span", { class: "host-chip warn", text: t("wifi.chip_same_ssid", { n: sameSsidOther }) }));
    chips.push(el("span", { class: "host-chip " + (coCh ? "bad" : "ok"), text: t("wifi.chip_cochannel", { n: coCh }) }));
    if (adjCh)
        chips.push(el("span", { class: "host-chip warn", text: t("wifi.chip_adjacent", { n: adjCh }) }));
    sumBox.replaceChildren(...chips);
    renderSpectrum(allForSpec);
    patch(box, ...chunks);
}
export function renderWifiLink() {
    const box = byId("wifi-link");
    const s = state.status;
    if (!s) {
        box.replaceChildren();
        return;
    }
    const wifiIfaces = Object.entries(s.ifaces).filter(([, st]) => st.role === "wifi" || (st.wifi !== null && st.wifi !== undefined));
    if (!wifiIfaces.length) {
        box.replaceChildren(el("div", { class: "empty small", text: t("wifi.no_ifaces") }));
        return;
    }
    const cards = wifiIfaces.map(([name, st]) => {
        const [lbl, tone] = stateLabel(st.state ?? st.last?.state);
        const w = st.wifi;
        const cl = st.channel_load;
        const dl = el("dl", { class: "kv" });
        if (!w) {
            kv(dl, t("wifi.k_status"), t("wifi.waiting_station"));
        }
        else if (!w.connected) {
            kv(dl, t("wifi.k_assoc"), t("now.not_assoc"), "err");
        }
        else {
            if (w.ssid)
                kv(dl, "SSID", w.ssid);
            if (w.bssid)
                dl.append(el("dt", { text: "BSSID" }), el("dd", null, maskedMac(w.bssid)));
            const chParts = [w.channel ?? "?"];
            if (w.width_mhz)
                chParts.push(w.width_mhz + " MHz");
            if (w.freq_mhz)
                chParts.push(band(w.freq_mhz) + " (" + w.freq_mhz + " MHz)");
            kv(dl, t("now.channel"), chParts.join(" · "));
            const sig = w.signal_avg_dbm ?? w.signal_dbm;
            if (sig !== undefined) {
                const sigText = sig + " dBm" + (w.signal_dbm !== undefined && w.signal_avg_dbm !== undefined && w.signal_dbm !== w.signal_avg_dbm ? " (" + t("wifi.inst", { v: w.signal_dbm }) + ")" : "");
                dl.append(el("dt", { class: "tip-dt" }, t("now.signal"), tip("signal")), el("dd", { class: sigTone(sig) === "bad" ? "err" : "" }, el("span", { class: "sig-cell" }, el("progress", { class: "sig-prog", max: 100, value: sigPct(sig) }), el("span", { text: sigText }))));
            }
            if (cl?.noise_dbm !== undefined)
                kv(dl, t("wifi.noise"), cl.noise_dbm + " dBm");
            if (cl) {
                kv(dl, t("now.busy"), cl.busy_pct.toFixed(1) + "% (rx " + cl.rx_pct.toFixed(1) + "% · tx " + cl.tx_pct.toFixed(1) + "%)", busyTone(cl.busy_pct) === "bad" ? "err" : undefined, "channel_busy");
            }
            if (w.tx_bitrate_mbps !== undefined || w.rx_bitrate_mbps !== undefined) {
                kv(dl, t("now.bitrate"), (w.tx_bitrate_mbps !== undefined ? Math.round(w.tx_bitrate_mbps) : "–") + " / " + (w.rx_bitrate_mbps !== undefined ? Math.round(w.rx_bitrate_mbps) : "–") + " Mbit/s");
            }
            if (w.tx_retries !== undefined || w.tx_failed !== undefined) {
                kv(dl, t("now.retries"), String(w.tx_retries ?? 0) + (w.tx_failed ? " (" + t("now.failed_n", { n: w.tx_failed }) + ")" : ""), undefined, "tx_retries");
            }
            if (w.beacon_loss !== undefined && w.beacon_loss > 0) {
                kv(dl, t("wifi.beacon_loss"), String(w.beacon_loss), "warn");
            }
            if (w.connected_s !== undefined)
                kv(dl, t("wifi.connected_for"), fmtDur(w.connected_s));
            if (w.power_save === true)
                kv(dl, t("now.power_save"), t("now.ps_on"), "err", "power_save");
            else if (w.power_save === false)
                kv(dl, t("now.power_save"), t("now.off"), "ok", "power_save");
        }
        if (st.last?.link.gateway)
            kv(dl, t("wifi.gateway"), st.last.link.gateway);
        return el("article", { class: "wifi-card" }, el("div", { class: "path-head" }, el("span", { class: "path-name" }, el("span", { class: "name", text: name })), el("span", { class: "pill small " + tone, text: lbl })), dl);
    });
    patch(box, ...cards);
}
export async function loadScan() {
    const r = await fetchScan();
    if (r) {
        state.scan = r.scan;
        renderScan();
        if (state.site)
            renderSite();
    }
}
