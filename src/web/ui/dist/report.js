// Session report (Sessions view): verdict sentence, KPIs, hourly profile, incidents, findings,
// and the per-point table of the Map view. Also the shared incident row and verdict sentence.
import { fetchReport } from "./client.js";
import { byId, el } from "./dom.js";
import { fmtDur, fmtTime, fmtTimeShort, ms, secsSince, stateLabel, verdictLabel } from "./format.js";
import { t, tDyn, tMsg } from "./i18n.js";
import { availTone, dropsTone, pointLabel, progressText, statusChip } from "./points.js";
import { LIVE, bus, state } from "./state.js";
import { incidentsTone, sigTone } from "./status.js";
import { tip } from "./tips.js";
import { emptyState, errorState } from "./ui.js";
const HOURS = Array.from({ length: 24 }, (_, h) => h);
/** True when a non-observer episode happened during the monitor's own speed test and was short (<= 45 s). */
export function isLoadProvoked(ep) {
    return ep.origin !== "observer" && ep.speedtest_active && ep.duration_s <= 45.0;
}
/** Translated verdict sentence of a report (server code + args), English text as fallback. */
export function verdictSentence(rep) {
    return tDyn("vc." + rep.verdict_code, rep.verdict_summary, rep.verdict_args);
}
/** The path that sets the headline numbers: the one with the lowest availability. */
function worstIface(ifaces) {
    return [...ifaces].sort((a, b) => a.availability_pct - b.availability_pct)[0] ?? null;
}
function kpi(label, tkey, value, unit, sub, tone, onclick) {
    const children = [
        el("span", { class: "lbl" }, label, tkey ? tip(tkey) : null),
        el("span", { class: "val " + tone }, value, unit ? el("span", { class: "unit", text: unit }) : null),
        sub ? el("span", { class: "sub", text: sub }) : null,
    ];
    if (!onclick)
        return el("div", { class: "kpi" }, ...children);
    // A button may not contain the ⓘ button, so the whole tile is covered by a separate
    // transparent button and the tip sits above it.
    return el("div", { class: "kpi kpi-link" }, el("button", { type: "button", class: "kpi-hit", "aria-label": label + ": " + value + (unit ? " " + unit : ""), onclick }), ...children);
}
const TRUST_KEY = {
    clean: "report.trust.clean",
    caution: "report.trust.caution",
    polluted: "report.trust.polluted",
};
const ATTR_KEY = {
    network: "report.attr.network",
    network_despite_host: "report.attr.network_despite_host",
    mixed: "report.attr.mixed",
    observer_likely: "report.attr.observer_likely",
    observer_confirmed: "report.attr.observer_confirmed",
    inconclusive: "report.attr.inconclusive",
};
const CONF_KEY = {
    low: "report.conf.low",
    medium: "report.conf.medium",
    high: "report.conf.high",
};
const NCAUSE_KEY = {
    router_reboot: "report.ncause.router_reboot",
    router_wan_down: "report.ncause.router_wan_down",
    router_log: "report.ncause.router_log",
    ap_disconnect: "report.ncause.ap_disconnect",
    channel_switch: "report.ncause.channel_switch",
    carrier_loss: "report.ncause.carrier_loss",
    roam: "report.ncause.roam",
    dhcp: "report.ncause.dhcp",
    weak_signal: "report.ncause.weak_signal",
    busy_channel: "report.ncause.busy_channel",
};
const scrollTo = (id) => () => byId(id).scrollIntoView({ behavior: "smooth", block: "start" });
function renderKpis(rep) {
    const box = byId("report-kpis");
    if (!rep.ifaces.length) {
        box.replaceChildren(emptyState(t("report.no_data"), t("report.no_data_hint")));
        return;
    }
    const net = worstIface(rep.ifaces);
    const wifi = rep.ifaces.find((i) => i.role === "wifi") ?? null;
    const micro = rep.ifaces.reduce((a, i) => a + i.micro_drops, 0);
    const netSub = [
        net?.peak_net_rtt_p95 !== null && net?.peak_net_rtt_p95 !== undefined ? t("report.p95", { v: ms(net.peak_net_rtt_p95) }) : null,
        net?.loaded_net_rtt_med !== null && net?.loaded_net_rtt_med !== undefined ? t("report.loaded_rtt", { v: ms(net.loaded_net_rtt_med) }) : null,
    ].filter(Boolean).join(" · ") || null;
    const cards = [
        kpi(t("report.avail"), "availability", net ? net.availability_pct.toFixed(2) : "–", net ? "%" : "", net && rep.ifaces.length > 1 ? t("report.worst_path", { iface: net.iface }) : null, availTone(net?.availability_pct) ?? "", scrollTo("h-timeline")),
        kpi(t("report.net_inc"), "micro_drops", String(rep.network_incidents), "", micro ? t("report.micro_n", { n: micro }) : null, incidentsTone(rep.network_incidents, micro), scrollTo("h-incidents")),
        kpi(t("report.gw_med"), "router_rtt", net?.gw_rtt_med !== null && net?.gw_rtt_med !== undefined ? ms(net.gw_rtt_med) : "–", "", null, ""),
        kpi(t("report.net_med"), "net_rtt", net?.net_rtt_med !== null && net?.net_rtt_med !== undefined ? ms(net.net_rtt_med) : "–", "", netSub, ""),
    ];
    if (wifi && wifi.signal_med !== null) {
        cards.push(kpi(t("report.wifi_med"), "signal", String(Math.round(wifi.signal_med)), "dBm", wifi.busy_med !== null ? t("report.busy_n", { n: Math.round(wifi.busy_med) }) : null, sigTone(wifi.signal_med) === "bad" ? "bad" : ""));
    }
    if (rep.load_incidents) {
        cards.push(kpi(t("report.load_inc"), null, String(rep.load_incidents), "", t("report.load_excluded"), ""));
    }
    if (rep.observer_incidents) {
        cards.push(kpi(t("report.obs_inc"), null, String(rep.observer_incidents), "", t("report.obs_excluded"), ""));
    }
    const trust = rep.observer_trust;
    if (trust) {
        const first = trust.reasons[0];
        const more = trust.reasons.length > 1 ? " (+" + String(trust.reasons.length - 1) + ")" : "";
        const sub = first ? tMsg(first) + more : t("report.trust_clean_sub");
        const tone = trust.level === "polluted" ? "bad" : trust.level === "caution" ? "warn" : "ok";
        cards.push(kpi(t("report.trust"), null, t(TRUST_KEY[trust.level]), "", sub, tone));
    }
    if (rep.router && rep.router.wan_rx_mbps_med !== null) {
        cards.push(kpi(t("report.wan_med"), "wan_traffic", rep.router.wan_rx_mbps_med.toFixed(1), "Mbit/s", rep.router.wan_rx_mbps_p95 !== null ? t("report.p95", { v: rep.router.wan_rx_mbps_p95.toFixed(1) }) : null, ""));
    }
    box.replaceChildren(...cards);
}
/** Session-wide limits (masking): what this session cannot prove, listed once. */
function renderBlinds(rep) {
    const box = byId("report-blinds");
    const blinds = rep.session_blinds;
    box.hidden = blinds.length === 0;
    if (!blinds.length) {
        box.replaceChildren();
        return;
    }
    box.replaceChildren(el("p", { class: "blind-title", text: t("report.blinds") }), el("ul", null, ...blinds.map((b) => el("li", { text: tMsg(b.msg) }))));
}
function renderHourly(rep) {
    const box = byId("hourly-bars");
    const wrap = byId("hourly-wrap");
    const byHour = new Map();
    for (const iface of rep.ifaces) {
        for (const h of iface.hours) {
            if (!h.ticks)
                continue;
            const cur = byHour.get(h.hour) ?? { ticks: 0, bad: 0, ep: 0, micro: 0 };
            cur.ticks += h.ticks;
            cur.bad += Math.round((h.loss_pct / 100) * h.ticks);
            cur.ep += h.episodes;
            cur.micro += h.micro_drops;
            byHour.set(h.hour, cur);
        }
    }
    if (!byHour.size) {
        wrap.hidden = true;
        box.replaceChildren();
        return;
    }
    wrap.hidden = false;
    const hh = (hr) => String(hr).padStart(2, "0");
    const cells = HOURS.map((hr) => {
        const d = byHour.get(hr);
        if (!d || !d.ticks) {
            return el("div", { class: "hr-cell empty", title: hh(hr) + ":00 · " + t("report.no_data_short") }, el("span", { class: "hr-bar lv-0" }), el("span", { class: "hr-lbl", text: hr % 3 === 0 ? hh(hr) : "" }));
        }
        const lossPct = (d.bad / d.ticks) * 100;
        const tone = d.ep > 0 || lossPct >= 1 ? "bad" : lossPct > 0 || d.micro > 0 ? "warn" : "ok";
        const lv = lossPct >= 5 || d.ep >= 3 ? "lv-5"
            : lossPct >= 1 || d.ep >= 1 ? "lv-4"
                : lossPct >= 0.2 || d.micro >= 2 ? "lv-3"
                    : lossPct > 0 || d.micro > 0 ? "lv-2"
                        : "lv-1";
        const tipTxt = hh(hr) + ":00 · " + t("report.hour_tip", { loss: lossPct.toFixed(2), ep: d.ep, micro: d.micro });
        return el("div", { class: "hr-cell", title: tipTxt }, el("span", { class: "hr-bar " + tone + " " + lv }), el("span", { class: "hr-lbl", text: hr % 3 === 0 ? hh(hr) : "" }));
    });
    box.replaceChildren(...cells);
}
/** One incident: time, path, duration, cause; a click marks it on the timeline. */
export function episodeRow(ep, withContext = true, live = false) {
    const isObs = ep.origin === "observer";
    const isLoad = isLoadProvoked(ep);
    const [cLbl, cTone] = isObs
        ? [t("report.observer"), "neutral"]
        : isLoad
            ? [t("report.load_badge"), "warn"]
            : ep.cause
                ? verdictLabel(ep.cause)
                : stateLabel(ep.state);
    const fin = ep.finding; // old saved reports have none
    const attr = fin?.attribution;
    const attrBadge = fin && attr && attr !== "network"
        ? el("span", {
            class: "badge badge-attr",
            text: attr === "mixed"
                ? t(ATTR_KEY[attr]) + " · " + t("report.attr.split", { host: fmtDur(fin.host_s), net: fmtDur(fin.network_s) })
                : t(ATTR_KEY[attr]),
            title: t(CONF_KEY[fin.confidence]),
        })
        : null;
    const ctx = withContext ? ep.context.slice(0, 4).map((c) => el("span", { class: "inc-ctx", text: tMsg(c) })) : [];
    if (withContext && fin) {
        const cause = fin.network_causes?.[0];
        if (cause)
            ctx.push(el("span", { class: "inc-ctx inc-cause", text: t(NCAUSE_KEY[cause]) }));
        for (const b of fin.blinded?.slice(0, 1) ?? [])
            ctx.push(el("span", { class: "inc-ctx inc-blind", text: tMsg(b.msg) }));
        for (const e of fin.evidence.slice(0, 3))
            ctx.push(el("span", { class: "inc-ctx inc-evid", text: tMsg(e.msg) }));
        if (fin.flip)
            ctx.push(el("span", { class: "inc-ctx inc-flip", text: tMsg(fin.flip) }));
    }
    return el("li", null, el("button", {
        type: "button",
        class: "inc-item " + cTone,
        onclick: () => bus.dispatchEvent(new CustomEvent(live ? "focus-live-time" : "focus-time", { detail: ep.start })),
    }, el("div", { class: "inc-top" }, el("span", { class: "inc-meta" }, el("span", { class: "mono small", text: fmtTime(ep.start) }), el("span", { class: "mono small inc-iface", text: ep.iface }), ep.band ? el("span", { class: "badge", text: ep.band }) : null, ep.speedtest_active ? el("span", { class: "badge badge-warn", text: t("report.load_tag") }) : null, attrBadge, el("strong", { class: "small", text: fmtDur(ep.duration_s) })), el("span", { class: "pill small " + cTone, text: cLbl })), ctx.length ? el("div", { class: "inc-ctxs" }, ...ctx) : null));
}
function renderIncidents(rep) {
    const list = byId("incidents");
    const br = state.brushRange;
    const shown = br
        ? rep.episodes.filter((e) => {
            const s = new Date(e.start).getTime();
            const end = s + e.duration_s * 1000;
            return isFinite(s) && s <= br[1] && end >= br[0];
        })
        : rep.episodes;
    byId("inc-count").textContent = br ? `${shown.length} / ${rep.episodes.length}` : String(rep.episodes.length);
    if (!shown.length) {
        list.replaceChildren(el("li", { class: "empty small", text: t("report.inc_empty") }));
        return;
    }
    list.replaceChildren(...shown.slice(0, 60).map((e) => episodeRow(e)));
}
/** Updates the incidents list for the active brush zoom range. */
export function renderIncidentsForCurrentReport() {
    if (state.report)
        renderIncidents(state.report);
}
function renderFindings(rep) {
    const box = byId("report-findings");
    // Observer notes are already part of the findings (the analyzer adds them there).
    const lines = [
        ...rep.findings.map((f) => (f.code.startsWith("o_") ? t("report.obs_finding", { o: tMsg(f) }) : tMsg(f))),
        ...rep.patterns.map((p) => t("report.pattern", { p: tMsg(p) })),
    ];
    byId("findings-disc").hidden = lines.length === 0;
    box.replaceChildren(...lines.map((x) => el("li", { text: x })));
}
function sessionTitle() {
    if (state.selectedSession === LIVE) {
        const m = state.status?.session;
        return {
            title: t("report.title_live"),
            sub: [m?.point ? pointLabel(m.point) : null, m?.label, state.status?.started ? t("hero.since", { t: fmtTimeShort(state.status.started) }) : null]
                .filter(Boolean).join(" · "),
        };
    }
    const e = state.sessions.find((s) => s.id === state.selectedSession);
    if (!e)
        return { title: state.selectedSession, sub: "" };
    return {
        title: e.label || (e.point ? pointLabel(e.point) : e.id),
        sub: [e.label && e.point ? pointLabel(e.point) : null, fmtTime(e.started), e.duration_s !== null ? fmtDur(e.duration_s) : null, e.note]
            .filter(Boolean).join(" · "),
    };
}
export function renderReport() {
    const rep = state.report;
    const sessQ = state.selectedSession === LIVE ? "" : "&session=" + encodeURIComponent(state.selectedSession);
    const startedS = state.status?.started ? secsSince(state.status.started) : 0;
    const maxTicks = rep ? rep.ifaces.reduce((m, i) => Math.max(m, i.ticks), 0) : 0;
    const tooShort = state.selectedSession === LIVE && startedS < 60 && maxTicks < 60;
    const mdLink = byId("report-export-md", HTMLAnchorElement);
    const jsonLink = byId("report-export-json", HTMLAnchorElement);
    mdLink.href = "/api/report/export?format=md" + sessQ;
    jsonLink.href = "/api/report/export?format=json" + sessQ;
    for (const link of [mdLink, jsonLink]) {
        if (tooShort)
            link.setAttribute("aria-disabled", "true");
        else
            link.removeAttribute("aria-disabled");
    }
    byId("report-export-note").hidden = !tooShort;
    const { title, sub } = sessionTitle();
    byId("h-report").textContent = title;
    byId("rep-sub").textContent = sub;
    const vEl = byId("rep-verdict");
    if (!rep) {
        vEl.hidden = true;
        byId("report-kpis").replaceChildren(el("div", { class: "empty", text: t("report.analyzing") }));
        byId("hourly-wrap").hidden = true;
        byId("inc-count").textContent = "0";
        byId("incidents").replaceChildren(el("li", { class: "empty small", text: t("report.analyzing") }));
        byId("findings-disc").hidden = true;
        return;
    }
    vEl.hidden = false;
    vEl.textContent = verdictSentence(rep);
    vEl.className = "verdict-explain " + verdictLabel(rep.verdict)[1];
    renderKpis(rep);
    renderBlinds(rep);
    renderHourly(rep);
    renderIncidents(rep);
    renderFindings(rep);
}
/** The report request failed: say so and offer a retry, instead of "Analysing…" forever. */
function reportFailed() {
    byId("report-kpis").replaceChildren(errorState(t("err.report"), () => void loadReport()));
    byId("incidents").replaceChildren(el("li", { class: "empty small", text: t("err.report") }));
}
export async function loadReport() {
    const r = await fetchReport(state.selectedSession);
    if (!r) {
        if (!state.report)
            reportFailed();
        return;
    }
    state.report = r;
    if (state.selectedSession === LIVE) {
        state.liveReport = r;
        bus.dispatchEvent(new Event("live-report"));
    }
    renderReport();
}
/** Report of the running session for the Now view (also when Sessions shows another one). */
export async function loadLiveReport() {
    if (state.selectedSession === LIVE)
        return loadReport();
    const r = await fetchReport(LIVE);
    if (!r)
        return;
    state.liveReport = r;
    bus.dispatchEvent(new Event("live-report"));
}
export function renderPointsCompare() {
    const panel = byId("points-compare-panel");
    const tbody = byId("points-compare", HTMLTableElement).tBodies.item(0);
    if (!tbody)
        return;
    const rows = (state.plan?.items ?? []).filter((i) => i.sessions > 0 || i.planned);
    panel.hidden = rows.length === 0;
    if (!rows.length) {
        tbody.replaceChildren();
        return;
    }
    const trs = rows.map((it) => {
        const aTone = availTone(it.availability_pct);
        const dTone = dropsTone(it.drops_per_h);
        return el("tr", {
            class: "cmp-row",
            tabindex: 0,
            onclick: () => bus.dispatchEvent(new CustomEvent("focus-point", { detail: it.point })),
            onkeydown: (ev) => {
                if (ev instanceof KeyboardEvent && ev.key === "Enter")
                    bus.dispatchEvent(new CustomEvent("focus-point", { detail: it.point }));
            },
        }, el("td", null, el("div", { class: "cmp-name", text: pointLabel(it.point) }), it.note ? el("div", { class: "small muted", text: it.note }) : null), el("td", null, statusChip(it.status)), el("td", { class: "num", text: progressText(it) }), el("td", { class: "num " + (aTone === "bad" ? "err" : aTone === "ok" ? "ok" : ""), text: it.availability_pct !== null ? it.availability_pct.toFixed(2) + "%" : "–" }), el("td", { class: "num " + (dTone === "bad" ? "err" : ""), text: it.drops_per_h !== null ? it.drops_per_h.toFixed(1) : "–" }), el("td", { class: "num col-wide", text: String(it.sessions) }));
    });
    tbody.replaceChildren(...trs);
}
