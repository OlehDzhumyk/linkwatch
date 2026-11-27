// Extensible UI translation registry.
// To add a new language: add src/locale_<code>.ts and register it in LOCALES below.
import { EN } from "./locale_en.js";
import { UK } from "./locale_uk.js";
export const LOCALES = [
    { code: "en", label: "EN", messages: EN },
    { code: "uk", label: "UA", messages: UK },
];
const LANG_STORAGE_KEY = "lw-lang";
let current = "en";
function hasKey(k) {
    return k !== undefined && Object.prototype.hasOwnProperty.call(EN, k);
}
function findLocale(code) {
    if (!code)
        return undefined;
    const norm = code.trim().toLowerCase().split(/[-_]/)[0];
    return LOCALES.find((l) => l.code === norm);
}
export function getLang() {
    return current;
}
export function setLang(code) {
    const def = findLocale(code);
    if (!def)
        return false;
    current = def.code;
    document.documentElement.lang = current;
    try {
        localStorage.setItem(LANG_STORAGE_KEY, current);
    }
    catch {
        /* storage may be unavailable */
    }
    return true;
}
export function initI18n() {
    let saved = null;
    try {
        saved = localStorage.getItem(LANG_STORAGE_KEY);
    }
    catch {
        /* storage may be unavailable */
    }
    const fromSaved = findLocale(saved);
    if (fromSaved) {
        current = fromSaved.code;
    }
    else {
        const langs = navigator.languages?.length ? navigator.languages : [navigator.language];
        for (const lang of langs) {
            const hit = findLocale(lang);
            if (hit) {
                current = hit.code;
                break;
            }
        }
    }
    document.documentElement.lang = current;
    return current;
}
export function t(key, vars) {
    const def = findLocale(current);
    const raw = def?.messages[key] ?? EN[key];
    if (!vars)
        return raw;
    return raw.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, k) => Object.prototype.hasOwnProperty.call(vars, k) ? String(vars[k]) : "{" + k + "}");
}
/** Updates all static DOM elements annotated with data-i18n* attributes via textContent/setAttribute. */
export function applyStaticI18n() {
    for (const node of document.querySelectorAll("[data-i18n]")) {
        const k = node.dataset["i18n"];
        if (hasKey(k))
            node.textContent = t(k);
    }
    for (const node of document.querySelectorAll("[data-i18n-ph]")) {
        const k = node.dataset["i18nPh"];
        if (hasKey(k))
            node.setAttribute("placeholder", t(k));
    }
    for (const node of document.querySelectorAll("[data-i18n-title]")) {
        const k = node.dataset["i18nTitle"];
        if (hasKey(k))
            node.setAttribute("title", t(k));
    }
    for (const node of document.querySelectorAll("[data-i18n-aria]")) {
        const k = node.dataset["i18nAria"];
        if (hasKey(k))
            node.setAttribute("aria-label", t(k));
    }
}
/**
 * Translation of a key built at run time (server message codes such as `advice.<code>.title`).
 * Falls back to the server's English text when no locale defines the key.
 */
export function tDyn(key, fallback, vars) {
    return hasKey(key) ? t(key, vars) : fallback;
}
/** `one` or `other` form by the plural rules of the current language (`{n}` is filled in). */
export function tPlural(one, other, n, vars) {
    const rule = new Intl.PluralRules(current).select(n);
    return t(rule === "one" ? one : other, { n, ...vars });
}
/** A server message (`code` + `args`, English `text`) in the current language. */
export function tMsg(m) {
    const vars = {};
    for (const [k, v] of Object.entries(m.args))
        if (v !== undefined)
            vars[k] = v;
    return tDyn("m." + m.code, m.text, vars);
}
