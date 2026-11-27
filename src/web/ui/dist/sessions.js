// Sessions view: the session list (replaces the old selector), selection and comparison of
// 2..=8 sessions through /api/compare.
import { compareUrl, fetchCompare } from "./client.js";
import { byId, el } from "./dom.js";
import { fmtDur, fmtTime, fmtTimeShort, ms, verdictLabel } from "./format.js";
import { t, tMsg } from "./i18n.js";
import { pointLabel } from "./points.js";
import { LIVE, bus, state } from "./state.js";
import { availTone } from "./status.js";
import { errorState } from "./ui.js";
const MAX_COMPARE = 8;
/** Controls list vs detail view on mobile/tablet (< 960 px). */
export function setSessionDetailOpen(open) {
    const layout = byId("tab-sessions").querySelector(".sess-layout");
    if (layout)
        layout.classList.toggle("sess-detail-open", open);
}
function toggleCompare(id, on) {
    const sel = state.compareSel.filter((x) => x !== id);
    if (on && sel.length < MAX_COMPARE)
        sel.push(id);
    state.compareSel = sel;
    syncCompareButton();
}
function syncCompareButton() {
    const n = state.compareSel.length;
    const btn = byId("cmp-btn", HTMLButtonElement);
    btn.disabled = n < 2;
    btn.textContent = n ? t("sess.compare_n", { n }) : t("sess.compare");
}
function item(id, title, sub, facts, cmpId) {
    const sel = state.selectedSession === id;
    const box = cmpId
        ? el("input", {
            type: "checkbox",
            "aria-label": t("sess.tick", { s: title }),
            checked: state.compareSel.includes(cmpId),
            onchange: (ev) => {
                if (ev.currentTarget instanceof HTMLInputElement)
                    toggleCompare(cmpId, ev.currentTarget.checked);
            },
        })
        : el("span");
    return el("li", { class: "sess-item" + (sel ? " sel" : "") }, box, el("button", {
        type: "button",
        class: "sess-btn",
        "aria-current": sel ? "true" : null,
        onclick: () => selectSession(id),
    }, el("span", { class: "t", text: title }), el("span", { class: "s", text: sub }), facts.length ? el("span", { class: "r" }, ...facts) : null));
}
/** Session list, newest first; the running session on top as "Live". */
export function renderSessionList() {
    const list = byId("session-list");
    const cur = state.sessions.find((s) => s.current);
    const st = state.status;
    const liveTitle = t("sess.live") + (st?.session?.point ? " · " + pointLabel(st.session.point) : "");
    const [vLbl, vTone] = verdictLabel(st?.verdict);
    const rows = [
        item(LIVE, liveTitle, st?.started ? t("hero.since", { t: fmtTimeShort(st.started) }) : "", [el("span", { class: "pill small " + vTone, text: vLbl })], cur?.id ?? null),
    ];
    for (const s of state.sessions) {
        if (s.current)
            continue;
        const facts = [];
        if (s.verdict) {
            const [l, tone] = verdictLabel(s.verdict);
            facts.push(el("span", { class: "pill small " + tone, text: l }));
        }
        if (s.availability_pct !== null) {
            const a = availTone(s.availability_pct);
            facts.push(el("span", { class: a === "bad" ? "pill small bad" : "muted", text: s.availability_pct.toFixed(2) + "%" }));
        }
        const title = s.label || (s.point ? pointLabel(s.point) : s.id);
        const sub = [s.label && s.point ? pointLabel(s.point) : null, fmtTime(s.started), s.duration_s !== null ? fmtDur(s.duration_s) : null]
            .filter(Boolean).join(" · ");
        rows.push(item(s.id, title, sub, facts, s.id));
    }
    // A session that disappeared (deleted, or hidden because it is too short) is unselected.
    if (state.sessionsLoaded && state.selectedSession !== LIVE && !state.sessions.some((s) => s.id === state.selectedSession)) {
        state.selectedSession = LIVE;
    }
    state.compareSel = state.compareSel.filter((id) => state.sessions.some((s) => s.id === id));
    list.replaceChildren(...rows);
    syncCompareButton();
}
export function selectSession(id) {
    setSessionDetailOpen(true);
    if (state.selectedSession === id)
        return;
    state.selectedSession = id;
    state.rangeUserSet = true;
    state.highlightTs = null;
    state.brushRange = null;
    renderSessionList();
    bus.dispatchEvent(new Event("session-selected"));
}
// ---------- comparison ----------
const KIND_KEY = {
    shared_outage: ["cmp.k_shared", "bad"],
    wifi_only_outage: ["cmp.k_wifi_only", "warn"],
    local_only: ["cmp.k_local", "warn"],
    band_specific: ["cmp.k_band", "warn"],
    partial_overlap: ["cmp.k_partial", "info"],
};
function renderCompare(rep) {
    const body = byId("compare-body");
    const head = el("tr", null, el("th", { text: t("cmp.metric") }), ...rep.sessions.map((s) => el("th", { class: "num", text: s.label || s.id })));
    // A session without samples in the compared window has no rates: show a dash, not 0.00 %.
    const has = rep.sessions.map((s) => s.hours > 0);
    const val = (i, v) => (has[i] ? v : "–");
    const row = (label, cells, tones) => el("tr", null, el("td", { text: label }), ...cells.map((c, i) => el("td", { class: "num " + (tones?.[i] === "bad" ? "err" : tones?.[i] === "ok" ? "ok" : ""), text: c })));
    const table = el("table", { class: "tbl cmp-table" }, el("thead", null, head), el("tbody", null, row(t("cmp.iface"), rep.sessions.map((s) => s.iface + (s.bands.length ? " (" + s.bands.join("/") + ")" : ""))), row(t("cmp.hours"), rep.sessions.map((s) => s.hours.toFixed(1) + " h")), row(t("report.avail"), rep.sessions.map((s, i) => val(i, s.availability_pct.toFixed(2) + "%")), rep.sessions.map((s, i) => (has[i] ? availTone(s.availability_pct) : null))), row(t("cmp.outages_h"), rep.sessions.map((s, i) => val(i, s.outages_per_h.toFixed(2)))), row(t("cmp.micro_h"), rep.sessions.map((s, i) => val(i, s.micro_per_h.toFixed(2)))), row(t("report.gw_med"), rep.sessions.map((s) => ms(s.gw_rtt_med))), row(t("report.net_med"), rep.sessions.map((s) => ms(s.net_rtt_med))), rep.sessions.some((s) => s.loaded_net_rtt_med !== null) ? row(t("cmp.loaded_net"), rep.sessions.map((s) => ms(s.loaded_net_rtt_med))) : null, row(t("report.wifi_med"), rep.sessions.map((s) => (s.signal_med !== null ? Math.round(s.signal_med) + " dBm" : "–"))), rep.sessions.some((s) => s.retry_rate_per_min !== null)
        ? row(t("cmp.retries"), rep.sessions.map((s) => (s.retry_rate_per_min !== null ? t("cmp.retries_val", { v: s.retry_rate_per_min.toFixed(0) }) : "–")))
        : null, rep.sessions.some((s) => s.rf !== null)
        ? row(t("cmp.rf_path"), rep.sessions.map((s) => (s.rf ? t("cmp.rf_val", { m: s.rf.distance_m.toFixed(1), w: s.rf.walls_crossed, db: s.rf.obstacle_loss_db.toFixed(0) }) : "–")))
        : null, row(t("cmp.speed"), rep.sessions.map((s) => (s.speed_med_mbps !== null ? s.speed_med_mbps.toFixed(0) + " Mbit/s" : "–"))), row(t("report.obs_inc"), rep.sessions.map((s, i) => val(i, String(s.observer_incidents))))));
    const corr = rep.correlated.slice(0, 30).map((c) => {
        const [k, tone] = KIND_KEY[c.kind] ?? ["cmp.k_partial", "info"];
        return el("li", null, el("span", { class: "pill small " + tone, text: t(k) }), " ", el("span", { class: "mono small", text: fmtTime(c.start) }), " · ", el("span", { text: c.affected.join(", ") + (c.unaffected.length ? " — " + t("cmp.ok_at", { s: c.unaffected.join(", ") }) : "") }));
    });
    const notes = [
        ...rep.clock_warnings_msg.map(tMsg),
        ...rep.network_matches.filter((m) => m.match_kind !== "same").map((m) => m.a + " / " + m.b + ": " + tMsg(m.reason_msg)),
    ];
    const parts = [
        el("p", { class: "small muted", text: t("cmp.overlap", { h: rep.overlap_hours.toFixed(1), tol: rep.tolerance_s }) }),
        el("div", { class: "scroll" }, table),
        el("div", { class: "cmp-sec" }, el("h3", { class: "sub", text: t("cmp.correlated", { n: rep.correlated.length }) }), corr.length ? el("ul", null, ...corr) : el("p", { class: "small muted", text: t("cmp.no_corr") })),
        rep.findings_msg.length ? el("div", { class: "cmp-sec" }, el("h3", { class: "sub", text: t("report.findings") }), el("ul", null, ...rep.findings_msg.map((f) => el("li", { text: tMsg(f) })))) : null,
        notes.length ? el("div", { class: "cmp-sec" }, el("h3", { class: "sub", text: t("cmp.notes") }), el("ul", null, ...notes.map((f) => el("li", { text: f })))) : null,
    ];
    body.replaceChildren(...parts.filter((x) => x !== null));
}
function readTolerance() {
    const inp = byId("cmp-tol", HTMLInputElement);
    const raw = Number(inp.value);
    const clamped = isFinite(raw) ? Math.min(60, Math.max(0, Math.round(raw))) : 2;
    inp.value = String(clamped);
    state.compareTol = clamped;
    return clamped;
}
async function runCompare() {
    const ids = [...state.compareSel];
    if (ids.length < 2)
        return;
    setSessionDetailOpen(true);
    const tol = readTolerance();
    const panel = byId("compare-panel");
    panel.hidden = false;
    byId("cmp-export", HTMLAnchorElement).href = compareUrl(ids, "md", tol);
    byId("compare-body").replaceChildren(el("div", { class: "empty", text: t("cmp.loading") }));
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    const r = await fetchCompare(ids, tol);
    state.compare = r;
    if (r)
        renderCompare(r);
    else
        byId("compare-body").replaceChildren(errorState(t("cmp.failed"), () => void runCompare()));
}
/** Re-draws the open comparison (after a language change). */
export function refreshCompare() {
    if (state.compare && !byId("compare-panel").hidden)
        renderCompare(state.compare);
}
export function initSessions() {
    byId("cmp-btn").addEventListener("click", () => void runCompare());
    byId("cmp-close").addEventListener("click", () => { byId("compare-panel").hidden = true; });
    byId("cmp-apply").addEventListener("click", () => void runCompare());
    byId("cmp-tol", HTMLInputElement).addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") {
            ev.preventDefault();
            void runCompare();
        }
    });
    byId("sess-back").addEventListener("click", () => {
        setSessionDetailOpen(false);
        window.scrollTo({ top: 0 });
    });
}
