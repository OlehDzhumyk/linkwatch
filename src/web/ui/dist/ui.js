// Small shared UI pieces used by several views.
import { el } from "./dom.js";
import { tip } from "./tips.js";
/** One key/value row of a <dl class="kv">, with an optional ⓘ tip and a tone class on the value. */
export function kv(dl, k, v, cls, tkey) {
    dl.append(tkey ? el("dt", { class: "tip-dt" }, k, tip(tkey)) : el("dt", { text: k }), el("dd", { class: cls }, v));
}
