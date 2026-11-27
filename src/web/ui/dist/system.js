// Conditional alert banner, System tab (host, session, router, LAN sweep, observer/security events).
import { byId, el, patch } from "./dom.js";
import { fillEventList, makeEventItem } from "./events.js";
import { fmtDur, fmtTime, secsSince } from "./format.js";
import { t } from "./i18n.js";
import { bus, state } from "./state.js";
import { kv } from "./ui.js";
import { maskedMac } from "./wifi.js";
function collectAlerts() {
    const s = state.status;
    if (!s)
        return [];
    const alerts = [];
    const h = s.host;
    if (h) {
        if (h.throttled)
            alerts.push({ tone: "bad", text: t("alert.throttled") });
        if (h.clock_synced === false)
            alerts.push({ tone: "warn", text: t("alert.ntp") });
        const psOn = Object.entries(h.wifi_power_save ?? {}).filter(([, on]) => on).map(([k]) => k);
        if (psOn.length)
            alerts.push({ tone: "warn", text: t("alert.ps", { ifs: psOn.join(", ") }) });
        if (h.temp_c !== undefined && h.temp_c >= 75) {
            alerts.push({ tone: h.temp_c >= 85 ? "bad" : "warn", text: t("alert.temp", { v: h.temp_c.toFixed(1) }) });
        }
        if (h.cpu_pct !== undefined && h.cpu_pct >= 85) {
            alerts.push({ tone: "warn", text: t("alert.cpu", { v: Math.round(h.cpu_pct) }) });
        }
        if (h.mem_used_pct !== undefined && h.mem_used_pct >= 90) {
            alerts.push({ tone: "warn", text: t("alert.ram", { v: Math.round(h.mem_used_pct) }) });
        }
    }
    if (s.dropped_records > 0) {
        alerts.push({ tone: "warn", text: t("alert.dropped", { n: s.dropped_records }) });
    }
    if (s.router?.last_error) {
        alerts.push({ tone: "warn", text: t("alert.upnp", { e: s.router.last_error }) });
    }
    // Security and configuration findings only: the network verdict already has the hero.
    const advCrit = (state.advice?.items ?? []).filter((a) => a.severity === "critical" && (a.category === "security" || a.category === "router"));
    if (advCrit.length)
        alerts.push({ tone: "bad", text: t("alert.critical", { n: advCrit.length }) });
    return alerts;
}
export function renderAlertBar() {
    const bar = byId("alert-bar");
    const dot = byId("tab-sys-dot");
    const alerts = collectAlerts();
    if (!alerts.length) {
        bar.hidden = true;
        bar.replaceChildren();
        dot.hidden = true;
        return;
    }
    const hasBad = alerts.some((a) => a.tone === "bad");
    bar.hidden = false;
    bar.className = "alert-bar small " + (hasBad ? "bad" : "warn");
    patch(bar, el("span", { class: "muted small", text: t("alert.attention") }), ...alerts.map((a) => el("span", { class: "host-chip " + a.tone, text: a.text })), el("button", {
        type: "button",
        class: "ctrl alert-act",
        text: t("alert.open_sys"),
        onclick: () => bus.dispatchEvent(new CustomEvent("switch-tab", { detail: "diag" })),
    }));
    dot.hidden = false;
    dot.className = "tab-dot" + (hasBad ? " bad" : "");
}
function renderHostSection() {
    const target = byId("sys-host", HTMLDListElement);
    const s = state.status;
    if (!s) {
        target.replaceChildren();
        return;
    }
    const m = s.session;
    const h = s.host;
    const dl = el("dl");
    if (m?.host)
        kv(dl, t("k.host"), m.host);
    if (m?.version)
        kv(dl, t("k.version"), "linkwatch " + m.version);
    if (m?.session)
        kv(dl, t("k.session"), m.session);
    if (s.started)
        kv(dl, t("k.started"), fmtTime(s.started) + " (" + fmtDur(secsSince(s.started)) + ")");
    if (m?.point)
        kv(dl, t("k.point"), m.point);
    if (m?.label)
        kv(dl, t("k.label"), m.label);
    if (m?.note)
        kv(dl, t("k.note"), m.note);
    if (s.isp_hop)
        kv(dl, t("k.isp_hop"), s.isp_hop);
    if (s.dropped_records > 0)
        kv(dl, t("k.dropped_records"), String(s.dropped_records), "warn");
    if (h) {
        if (h.cpu_pct !== undefined)
            kv(dl, t("k.cpu"), Math.round(h.cpu_pct) + "%", h.cpu_pct >= 85 ? "warn" : undefined);
        if (h.load1 !== undefined)
            kv(dl, t("k.load_1m"), h.load1.toFixed(2));
        if (h.mem_used_pct !== undefined) {
            const avail = h.mem_avail_mb !== undefined ? " (" + Math.round(h.mem_avail_mb) + " " + t("sys.mb_free") + ")" : "";
            kv(dl, t("k.memory"), Math.round(h.mem_used_pct) + "%" + avail, h.mem_used_pct >= 90 ? "warn" : undefined);
        }
        if (h.disk_free_bytes !== undefined) {
            kv(dl, t("k.disk_free"), (h.disk_free_bytes / 1073741824).toFixed(1) + " GB");
        }
        if (h.temp_c !== undefined) {
            kv(dl, t("k.temperature"), h.temp_c.toFixed(1) + " °C", h.temp_c >= 85 ? "err" : h.temp_c >= 75 ? "warn" : undefined);
        }
        if (h.clock_synced === true)
            kv(dl, t("k.ntp_clock"), t("sys.synced"), "ok");
        else if (h.clock_synced === false)
            kv(dl, t("k.ntp_clock"), t("sys.not_synced"), "warn");
        if (h.throttled)
            kv(dl, t("k.power_throttle"), t("alert.throttled"), "err");
        for (const [iface, on] of Object.entries(h.wifi_power_save ?? {})) {
            kv(dl, t("now.power_save") + " (" + iface + ")", on ? t("now.ps_on") : t("now.off"), on ? "warn" : "ok", "power_save");
        }
    }
    const net = m?.network;
    if (net) {
        if (net.subnet)
            kv(dl, t("k.subnet"), net.subnet);
        if (net.gateway_ip)
            kv(dl, t("k.gateway_ip"), net.gateway_ip);
        if (net.gateway_mac)
            kv(dl, t("k.gateway_mac"), maskedMac(net.gateway_mac));
        if (net.bssids?.length)
            kv(dl, t("k.known_bssids"), String(net.bssids.length));
    }
    patch(target, ...dl.childNodes);
}
function renderRouterSection() {
    const box = byId("sys-router");
    const r = state.status?.router;
    if (!r) {
        box.replaceChildren(el("div", { class: "empty small", text: t("sys.upnp_off") }));
        return;
    }
    const dl = el("dl", { class: "kv" });
    if (r.model)
        kv(dl, t("k.model"), r.model);
    if (r.source)
        kv(dl, t("k.source"), r.source);
    if (r.wan_access)
        kv(dl, t("k.wan_access"), r.wan_access);
    if (r.phy_status)
        kv(dl, t("k.physical_link"), r.phy_status);
    if (r.wan_status) {
        const ok = r.wan_status.toLowerCase() === "connected";
        kv(dl, t("k.wan_status"), r.wan_status, ok ? "ok" : "err");
    }
    if (r.uptime_s !== undefined)
        kv(dl, t("k.router_uptime"), fmtDur(r.uptime_s));
    if (typeof r.link_down_mbps === "number" || typeof r.link_up_mbps === "number") {
        kv(dl, t("k.link_rate"), (r.link_down_mbps ?? "–") + "↓ / " + (r.link_up_mbps ?? "–") + "↑ Mbit/s");
    }
    if (typeof r.wan_rx_mbps === "number" || typeof r.wan_tx_mbps === "number") {
        kv(dl, t("k.wan_traffic"), (r.wan_rx_mbps ?? 0).toFixed(2) + "↓ / " + (r.wan_tx_mbps ?? 0).toFixed(2) + "↑ Mbit/s", undefined, "wan_traffic");
    }
    if (typeof r.wan_rx_pps === "number" || typeof r.wan_tx_pps === "number") {
        kv(dl, t("k.wan_packets_s"), Math.round(r.wan_rx_pps ?? 0) + "↓ / " + Math.round(r.wan_tx_pps ?? 0) + "↑ pps");
    }
    if (r.bytes_saturated)
        kv(dl, t("k.byte_counter"), t("sys.counter_sat"), "warn");
    if (r.last_error)
        kv(dl, t("k.last_error"), r.last_error, "err");
    if (!dl.childElementCount) {
        box.replaceChildren(el("div", { class: "empty small", text: t("sys.upnp_wait") }));
        return;
    }
    patch(box, dl);
}
function renderLanSection() {
    const box = byId("sys-lan");
    const lan = state.status?.lan;
    if (!lan) {
        box.replaceChildren(el("div", { class: "empty small", text: t("sys.lan_none") }));
        return;
    }
    const dl = el("dl", { class: "kv" });
    kv(dl, t("k.interface"), lan.iface + (lan.prefix_len !== undefined ? " (/" + lan.prefix_len + ")" : ""));
    kv(dl, t("k.arp_alive"), String(lan.arp_alive), undefined, "lan_devices");
    kv(dl, t("k.ping_alive"), String(lan.ping_alive));
    kv(dl, t("k.unique_seen_session"), String(lan.unique_seen));
    kv(dl, t("k.hosts_probed"), String(lan.probed));
    patch(box, dl);
}
export function renderSystemEvents() {
    const items = [];
    for (const env of state.events) {
        const { item, cat } = makeEventItem(env);
        if (cat === "observer" || cat === "security") {
            items.push(item);
            if (items.length >= 200)
                break;
        }
    }
    fillEventList(byId("sys-events"), byId("sys-ev-count"), items, t("sys.events_empty"));
}
export function renderSystem() {
    renderAlertBar();
    renderHostSection();
    renderRouterSection();
    renderLanSection();
    renderSystemEvents();
}
