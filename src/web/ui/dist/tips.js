// Metric info popovers (hover on desktop, tap on phone, Esc/outside-click closes).
import { el } from "./dom.js";
import { t } from "./i18n.js";
const TIP_KEYS = {
    verdict: ["tip.verdict.title", "tip.verdict.what", "tip.verdict.norm", "tip.verdict.bad"],
    router_rtt: ["tip.router_rtt.title", "tip.router_rtt.what", "tip.router_rtt.norm", "tip.router_rtt.bad"],
    net_rtt: ["tip.net_rtt.title", "tip.net_rtt.what", "tip.net_rtt.norm", "tip.net_rtt.bad"],
    signal: ["tip.signal.title", "tip.signal.what", "tip.signal.norm", "tip.signal.bad"],
    channel_busy: ["tip.channel_busy.title", "tip.channel_busy.what", "tip.channel_busy.norm", "tip.channel_busy.bad"],
    tx_retries: ["tip.tx_retries.title", "tip.tx_retries.what", "tip.tx_retries.norm", "tip.tx_retries.bad"],
    power_save: ["tip.power_save.title", "tip.power_save.what", "tip.power_save.norm", "tip.power_save.bad"],
    failures: ["tip.failures.title", "tip.failures.what", "tip.failures.norm", "tip.failures.bad"],
    availability: ["tip.availability.title", "tip.availability.what", "tip.availability.norm", "tip.availability.bad"],
    drops_h: ["tip.drops_h.title", "tip.drops_h.what", "tip.drops_h.norm", "tip.drops_h.bad"],
    micro_drops: ["tip.micro_drops.title", "tip.micro_drops.what", "tip.micro_drops.norm", "tip.micro_drops.bad"],
    lan_devices: ["tip.lan_devices.title", "tip.lan_devices.what", "tip.lan_devices.norm", "tip.lan_devices.bad"],
    wan_traffic: ["tip.wan_traffic.title", "tip.wan_traffic.what", "tip.wan_traffic.norm", "tip.wan_traffic.bad"],
    walls: ["tip.walls.title", "tip.walls.what", "tip.walls.norm", "tip.walls.bad"],
    hourly: ["tip.hourly.title", "tip.hourly.what", "tip.hourly.norm", "tip.hourly.bad"],
    wifi_sec: ["tip.wifi_sec.title", "tip.wifi_sec.what", "tip.wifi_sec.norm", "tip.wifi_sec.bad"],
    router_audit: ["tip.router_audit.title", "tip.router_audit.what", "tip.router_audit.norm", "tip.router_audit.bad"],
};
export function tip(key) {
    const [tk, wk, nk, bk] = TIP_KEYS[key];
    const title = t(tk);
    return el("span", { class: "tip-wrap" }, el("button", {
        type: "button",
        class: "tip-btn",
        "aria-label": t("tip.aria", { t: title }),
        text: "i",
    }), el("span", { class: "tip-box", role: "tooltip" }, el("strong", { class: "tip-title", text: title }), el("span", { class: "tip-line", text: t(wk) }), el("span", { class: "tip-line tip-norm", text: t("tip.norm", { text: t(nk) }) }), el("span", { class: "tip-line tip-bad", text: t("tip.bad", { text: t(bk) }) })));
}
function positionTip(wrap) {
    wrap.classList.remove("tip-align-right", "tip-below");
    if (window.innerWidth < 600)
        return;
    const box = wrap.querySelector(".tip-box");
    if (!(box instanceof HTMLElement))
        return;
    const r = box.getBoundingClientRect();
    if (r.right > window.innerWidth - 12)
        wrap.classList.add("tip-align-right");
    if (r.top < 56)
        wrap.classList.add("tip-below");
}
function closeAllTips(except) {
    for (const w of document.querySelectorAll(".tip-wrap.open")) {
        if (w !== except)
            w.classList.remove("open");
    }
}
export function initTips() {
    document.addEventListener("click", (ev) => {
        const t = ev.target;
        if (!(t instanceof Element)) {
            closeAllTips();
            return;
        }
        const btn = t.closest(".tip-btn");
        if (btn instanceof HTMLElement) {
            const wrap = btn.closest(".tip-wrap");
            if (wrap instanceof HTMLElement) {
                ev.stopPropagation();
                const willOpen = !wrap.classList.contains("open");
                closeAllTips(wrap);
                wrap.classList.toggle("open", willOpen);
                if (willOpen)
                    positionTip(wrap);
                return;
            }
        }
        if (!t.closest(".tip-wrap"))
            closeAllTips();
    });
    document.addEventListener("mouseenter", (ev) => {
        if (ev.target instanceof Element) {
            const wrap = ev.target.closest(".tip-wrap");
            if (wrap instanceof HTMLElement)
                positionTip(wrap);
        }
    }, true);
    document.addEventListener("focusin", (ev) => {
        if (ev.target instanceof Element) {
            const wrap = ev.target.closest(".tip-wrap");
            if (wrap instanceof HTMLElement)
                positionTip(wrap);
        }
    });
    document.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape")
            closeAllTips();
    });
}
