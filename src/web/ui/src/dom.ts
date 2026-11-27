// DOM helpers. Security rule for the whole UI: dynamic data goes into the page only through
// textContent and attributes (el/sv below), never as HTML markup to parse.

const SVGNS = "http://www.w3.org/2000/svg";

/** Attribute values for el()/sv(). `class` and `text` are special; `on<event>` adds a listener. */
export type AttrValue = string | number | boolean | null | undefined | ((ev: Event) => void);
export interface Attrs {
  readonly [name: string]: AttrValue;
}
export type Child = Node | string | number | null | undefined | false;

/**
 * Element with the given id, checked against the expected class. The ids are a contract with
 * index.html: a missing element is a bug, so this throws with a clear message.
 */
export function byId(id: string): HTMLElement;
export function byId<T extends Element>(id: string, ctor: abstract new () => T): T;
export function byId(id: string, ctor: abstract new () => Element = HTMLElement): Element {
  const e = document.getElementById(id);
  if (!(e instanceof ctor)) {
    throw new Error("index.html: #" + id + (e ? " is not a " + ctor.name : " is missing"));
  }
  return e;
}

function setAttrs(e: Element, attrs: Attrs | null | undefined, html: boolean): void {
  if (!attrs) return;
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || (html && v === false)) continue;
    if (typeof v === "function") {
      if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    } else if (html && k === "class") {
      e.className = String(v);
    } else if (k === "text") {
      e.textContent = String(v);
    } else {
      e.setAttribute(k, html && v === true ? "" : String(v));
    }
  }
}

/** HTML element with attributes and children (strings become text nodes). */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs?: Attrs | null,
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  setAttrs(e, attrs, true);
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

/** SVG element with attributes. */
export function sv<K extends keyof SVGElementTagNameMap>(tag: K, attrs?: Attrs): SVGElementTagNameMap[K] {
  const e = document.createElementNS(SVGNS, tag);
  setAttrs(e, attrs, false);
  return e;
}

/** Whether the page renders dark: a forced theme, else the system preference. */
export function isDark(): boolean {
  const forced = document.documentElement.dataset["theme"];
  if (forced === "dark") return true;
  if (forced === "light") return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** The two top-level arguments of `light-dark(a, b)`, or null for any other value. */
function lightDarkArgs(v: string): [string, string] | null {
  const m = /^light-dark\((.*)\)$/s.exec(v);
  const inner = m?.[1];
  if (inner === undefined) return null;
  let depth = 0;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (ch === "," && depth === 0) return [inner.slice(0, i).trim(), inner.slice(i + 1).trim()];
  }
  return null;
}

/**
 * Value of a CSS custom property on the root element (theme colours, fonts). Custom
 * properties are not computed, so `light-dark(a, b)` tokens are resolved here for canvas use.
 */
export function cssVar(name: string): string {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const ld = lightDarkArgs(raw);
  return ld ? (isDark() ? ld[1] : ld[0]) : raw;
}

/** Canvas sized to its CSS box at device resolution, cleared; null when it has no size or no 2D context. */
export function prepareCanvas(canvas: HTMLCanvasElement): { c: CanvasRenderingContext2D; W: number; H: number } | null {
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth;
  const H = canvas.clientHeight;
  if (!W || !H) return null;
  canvas.width = Math.round(W * dpr);
  canvas.height = Math.round(H * dpr);
  const c = canvas.getContext("2d");
  if (!c) return null;
  c.setTransform(dpr, 0, 0, dpr, 0, 0);
  c.clearRect(0, 0, W, H);
  return { c, W, H };
}
