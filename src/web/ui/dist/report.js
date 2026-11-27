// Session report (Sessions view): verdict sentence, KPIs, hourly profile, incidents, findings,
// and the per-point table of the Map view. Also the shared incident row and verdict sentence.
import { fetchReport } from "./client.js";
import { byId, el } from "./dom.js";
import { fmtDur, fmtTime, fmtTimeShort, ms, stateLabel, verdictLabel } from "./format.js";
import { t, tDyn, tMsg } from "./i18n.js";
import { availTone, dropsTone, pointLabel, progressText, statusChip } from "./points.js";
import { LIVE, bus, state } from "./state.js";
import { incidentsTone, sigTone } from "./status.js";
import { tip } from "./tips.js";
const HOURS = Array.from({ length: 24 }, (_, h) => h);
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
    return onclick ? el("button", { type: "button", class: "kpi", onclick }, ...children) : el("div", { class: "kpi" }, ...children);
}
const scrollTo = (id) => () => byId(id).scrollIntoView({ behavior: "smooth", block: "start" });
function renderKpis(rep) {
    const box = byId("report-kpis");
    if (!rep.ifaces.length) {
        box.replaceChildren(el("div", { class: "empty-state" }, el("strong", { text: t("report.no_data") }), el("span", { text: t("report.no_data_hint") })));
        return;
    }
    const net = worstIface(rep.ifaces);
    const wifi = rep.ifaces.find((i) => i.role === "wifi") ?? null;
    const micro = rep.ifaces.reduce((a, i) => a + i.micro_drops, 0);
    const cards = [
        kpi(t("report.avail"), "availability", net ? net.availability_pct.toFixed(2) : "–", net ? "%" : "", net && rep.ifaces.length > 1 ? t("report.worst_path", { iface: net.iface }) : null, availTone(net?.availability_pct) ?? "", scrollTo("h-timeline")),
        kpi(t("report.net_inc"), "micro_drops", String(rep.network_incidents), "", micro ? t("report.micro_n", { n: micro }) : null, incidentsTone(rep.network_incidents, micro), scrollTo("h-incidents")),
        kpi(t("report.gw_med"), "router_rtt", net?.gw_rtt_med !== null && net?.gw_rtt_med !== undefined ? ms(net.gw_rtt_med) : "–", "", null, ""),
        kpi(t("report.net_med"), "net_rtt", net?.net_rtt_med !== null && net?.net_rtt_med !== undefined ? ms(net.net_rtt_med) : "–", "", net?.peak_net_rtt_p95 !== null && net?.peak_net_rtt_p95 !== undefined ? t("report.p95", { v: ms(net.peak_net_rtt_p95) }) : null, ""),
    ];
    if (wifi && wifi.signal_med !== null) {
        cards.push(kpi(t("report.wifi_med"), "signal", String(Math.round(wifi.signal_med)), "dBm", wifi.busy_med !== null ? t("report.busy_n", { n: Math.round(wifi.busy_med) }) : null, sigTone(wifi.signal_med) === "bad" ? "bad" : ""));
    }
    if (rep.observer_incidents) {
        cards.push(kpi(t("report.obs_inc"), null, String(rep.observer_incidents), "", t("report.obs_excluded"), ""));
    }
    if (rep.router && rep.router.wan_rx_mbps_med !== null) {
        cards.push(kpi(t("report.wan_med"), "wan_traffic", rep.router.wan_rx_mbps_med.toFixed(1), "Mbit/s", rep.router.wan_rx_mbps_p95 !== null ? t("report.p95", { v: rep.router.wan_rx_mbps_p95.toFixed(1) }) : null, ""));
    }
    box.replaceChildren(...cards);
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
    const [cLbl, cTone] = isObs
        ? [t("report.observer"), "neutral"]
        : ep.cause
            ? verdictLabel(ep.cause)
            : stateLabel(ep.state);
    const ctx = withContext ? ep.context.slice(0, 4).map((c) => el("span", { class: "inc-ctx", text: tMsg(c) })) : [];
    return el("li", null, el("button", {
        type: "button",
        class: "inc-item " + cTone,
        onclick: () => bus.dispatchEvent(new CustomEvent(live ? "focus-live-time" : "focus-time", { detail: ep.start })),
    }, el("div", { class: "inc-top" }, el("span", { class: "inc-meta" }, el("span", { class: "mono small", text: fmtTime(ep.start) }), el("span", { class: "mono small inc-iface", text: ep.iface }), ep.band ? el("span", { class: "badge", text: ep.band }) : null, el("strong", { class: "small", text: fmtDur(ep.duration_s) })), el("span", { class: "pill small " + cTone, text: cLbl })), ctx.length ? el("div", { class: "inc-ctxs" }, ...ctx) : null));
}
function renderIncidents(rep) {
    const list = byId("incidents");
    byId("inc-count").textContent = String(rep.episodes.length);
    if (!rep.episodes.length) {
        list.replaceChildren(el("li", { class: "empty small", text: t("report.inc_empty") }));
        return;
    }
    list.replaceChildren(...rep.episodes.slice(0, 60).map((e) => episodeRow(e)));
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
    const sessQ = state.selectedSession === LIVE ? "" : "&session=" + encodeURIComponent(state.selectedSession);
    byId("report-export-md", HTMLAnchorElement).href = "/api/report/export?format=md" + sessQ;
    byId("report-export-json", HTMLAnchorElement).href = "/api/report/export?format=json" + sessQ;
    const { title, sub } = sessionTitle();
    byId("h-report").textContent = title;
    byId("rep-sub").textContent = sub;
    const rep = state.report;
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
    renderHourly(rep);
    renderIncidents(rep);
    renderFindings(rep);
}
export async function loadReport() {
    const r = await fetchReport(state.selectedSession);
    if (!r)
        return;
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
