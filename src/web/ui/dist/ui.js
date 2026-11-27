// Small shared UI primitives used across multiple views.
import { byId, el } from "./dom.js";
import { t } from "./i18n.js";
import { tip } from "./tips.js";
/** One key/value row of a <dl class="kv">, with an optional ⓘ tip and a tone class on the value. */
export function kv(dl, k, v, cls, tkey) {
    dl.append(tkey ? el("dt", { class: "tip-dt" }, k, tip(tkey)) : el("dt", { text: k }), el("dd", { class: cls }, v));
}
/** Uniform empty state: always explains what is missing and why/what next. */
export function emptyState(title, hint, action) {
    return el("div", { class: "empty-state" }, el("strong", { text: title }), hint ? el("span", { text: hint }) : null, action ?? null);
}
/** Inline error banner with a translated Retry button. */
export function errorState(message, onRetry) {
    return el("div", { class: "msg bad small err-row" }, el("span", { text: message }), el("button", { type: "button", class: "ctrl", text: t("err.retry"), onclick: onRetry }));
}
/** Remembers a <details id="..."> open state across reloads. */
export function initDisclosurePersistence(id) {
    const det = byId(id);
    if (!(det instanceof HTMLDetailsElement))
        return;
    const key = "lw-disc:" + id;
    try {
        const saved = localStorage.getItem(key);
        if (saved === "1")
            det.open = true;
        else if (saved === "0")
            det.open = false;
    }
    catch { /* storage may be unavailable */ }
    det.addEventListener("toggle", () => {
        try {
            localStorage.setItem(key, det.open ? "1" : "0");
        }
        catch { /* ignore */ }
    });
}
/** Wires a native modal <dialog>: backdrop click closes it and focus returns to the trigger. */
export function wireDialog(dlg, onClose) {
    let opener = null;
    dlg.addEventListener("click", (ev) => {
        if (ev.target === dlg)
            dlg.close();
    });
    dlg.addEventListener("close", () => {
        onClose?.();
        if (opener && opener.isConnected)
            opener.focus();
        opener = null;
    });
    return {
        open(focusEl) {
            if (!dlg.open) {
                opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
                dlg.showModal();
            }
            focusEl?.focus();
        },
        close() {
            if (dlg.open)
                dlg.close();
        },
    };
}
