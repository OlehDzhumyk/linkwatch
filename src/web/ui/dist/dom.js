// DOM helpers. Security rule for the whole UI: dynamic data goes into the page only through
// textContent and attributes (el/sv below), never as HTML markup to parse.
const SVGNS = "http://www.w3.org/2000/svg";
export function byId(id, ctor = HTMLElement) {
    const e = document.getElementById(id);
    if (!(e instanceof ctor)) {
        throw new Error("index.html: #" + id + (e ? " is not a " + ctor.name : " is missing"));
    }
    return e;
}
function setAttrs(e, attrs, html) {
    if (!attrs)
        return;
    for (const [k, v] of Object.entries(attrs)) {
        if (v === undefined || v === null || (html && v === false))
            continue;
        if (typeof v === "function") {
            if (k.startsWith("on"))
                e.addEventListener(k.slice(2), v);
        }
        else if (html && k === "class") {
            e.className = String(v);
        }
        else if (k === "text") {
            e.textContent = String(v);
        }
        else {
            e.setAttribute(k, html && v === true ? "" : String(v));
        }
    }
}
/** HTML element with attributes and children (strings become text nodes). */
export function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    setAttrs(e, attrs, true);
    for (const c of children) {
        if (c === null || c === undefined || c === false)
            continue;
        e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return e;
}
/** SVG element with attributes. */
export function sv(tag, attrs) {
    const e = document.createElementNS(SVGNS, tag);
    setAttrs(e, attrs, false);
    return e;
}
/** Whether the page renders dark: a forced theme, else the system preference. */
export function isDark() {
    const forced = document.documentElement.dataset["theme"];
    if (forced === "dark")
        return true;
    if (forced === "light")
        return false;
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
}
/** The two top-level arguments of `light-dark(a, b)`, or null for any other value. */
function lightDarkArgs(v) {
    const m = /^light-dark\((.*)\)$/s.exec(v);
    const inner = m?.[1];
    if (inner === undefined)
        return null;
    let depth = 0;
    for (let i = 0; i < inner.length; i++) {
        const ch = inner[i];
        if (ch === "(")
            depth++;
        else if (ch === ")")
            depth--;
        else if (ch === "," && depth === 0)
            return [inner.slice(0, i).trim(), inner.slice(i + 1).trim()];
    }
    return null;
}
/**
 * Value of a CSS custom property on the root element (theme colours, fonts). Custom
 * properties are not computed, so `light-dark(a, b)` tokens are resolved here for canvas use.
 */
export function cssVar(name) {
    const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const ld = lightDarkArgs(raw);
    return ld ? (isDark() ? ld[1] : ld[0]) : raw;
}
/** Canvas sized to its CSS box at device resolution, cleared; null when it has no size or no 2D context. */
export function prepareCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth;
    const H = canvas.clientHeight;
    if (!W || !H)
        return null;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    const c = canvas.getContext("2d");
    if (!c)
        return null;
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.clearRect(0, 0, W, H);
    return { c, W, H };
}
/**
 * Updates `old` in place so it looks like `neu`, keeping the existing elements (and with
 * them keyboard focus, scroll position, open <details> and listeners) wherever the tag at the
 * same position is the same. Live panels re-render every second through this instead of
 * replaceChildren(), so a tooltip or a focused button survives the update.
 * A tooltip the user has open (or points at) is left as it is.
 */
function morph(old, neu) {
    if (old.nodeType !== neu.nodeType || old.nodeName !== neu.nodeName) {
        old.parentNode?.replaceChild(neu, old);
        return neu;
    }
    if (old.nodeType === Node.TEXT_NODE) {
        if (old.nodeValue !== neu.nodeValue)
            old.nodeValue = neu.nodeValue;
        return old;
    }
    if (!(old instanceof Element) || !(neu instanceof Element))
        return old;
    // Elements with handlers bound to one record carry data-key: another record means a new node.
    if (old.getAttribute("data-key") !== neu.getAttribute("data-key")) {
        old.replaceWith(neu);
        return neu;
    }
    if (old.classList.contains("tip-wrap") && (old.classList.contains("open") || old.matches(":hover, :focus-within"))) {
        return old;
    }
    // A canvas keeps its own size attributes (set when drawing); everything else follows `neu`.
    const keep = old instanceof HTMLCanvasElement ? new Set(["width", "height"]) : null;
    for (const a of [...old.attributes]) {
        if (!neu.hasAttribute(a.name) && !keep?.has(a.name))
            old.removeAttribute(a.name);
    }
    for (const a of [...neu.attributes]) {
        if (old.getAttribute(a.name) !== a.value)
            old.setAttribute(a.name, a.value);
    }
    if (old instanceof HTMLInputElement && neu instanceof HTMLInputElement && old !== document.activeElement) {
        old.checked = neu.checked;
        old.value = neu.value;
    }
    patchChildren(old, [...neu.childNodes]);
    return old;
}
function patchChildren(parent, next) {
    const cur = [...parent.childNodes];
    next.forEach((n, i) => {
        const o = cur[i];
        if (o)
            morph(o, n);
        else
            parent.appendChild(n);
    });
    for (let i = next.length; i < cur.length; i++)
        cur[i]?.remove();
}
/** Like `box.replaceChildren(...children)`, but keeps the elements that stay the same kind. */
export function patch(box, ...children) {
    const nodes = [];
    for (const c of children) {
        if (c === null || c === undefined || c === false)
            continue;
        nodes.push(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    patchChildren(box, nodes);
}
