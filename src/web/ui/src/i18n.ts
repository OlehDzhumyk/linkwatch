// Extensible UI translation registry.
// To add a new language: add src/locale_<code>.ts and register it in LOCALES below.

import { EN, type MsgKey } from "./locale_en.js";
import { UK } from "./locale_uk.js";

export type { MsgKey };
export type LocaleMessages = Partial<Record<MsgKey, string>>;

export interface LocaleDef {
  readonly code: string;
  readonly label: string;
  readonly messages: LocaleMessages;
}

export const LOCALES: readonly LocaleDef[] = [
  { code: "en", label: "EN", messages: EN },
  { code: "uk", label: "UA", messages: UK },
] as const;

const LANG_STORAGE_KEY = "lw-lang";
let current = "en";

function hasKey(k: string | undefined): k is MsgKey {
  return k !== undefined && Object.prototype.hasOwnProperty.call(EN, k);
}

function findLocale(code: string | null | undefined): LocaleDef | undefined {
  if (!code) return undefined;
  const norm = code.trim().toLowerCase().split(/[-_]/)[0];
  return LOCALES.find((l) => l.code === norm);
}

export function getLang(): string {
  return current;
}

export function setLang(code: string): boolean {
  const def = findLocale(code);
  if (!def) return false;
  current = def.code;
  document.documentElement.lang = current;
  try {
    localStorage.setItem(LANG_STORAGE_KEY, current);
  } catch {
    /* storage may be unavailable */
  }
  return true;
}

export function initI18n(): string {
  let saved: string | null = null;
  try {
    saved = localStorage.getItem(LANG_STORAGE_KEY);
  } catch {
    /* storage may be unavailable */
  }
  const fromSaved = findLocale(saved);
  if (fromSaved) {
    current = fromSaved.code;
  } else {
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

export function t(key: MsgKey, vars?: Readonly<Record<string, string | number>>): string {
  const def = findLocale(current);
  const raw = def?.messages[key] ?? EN[key];
  if (!vars) return raw;
  return raw.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, k: string) =>
    Object.prototype.hasOwnProperty.call(vars, k) ? String(vars[k]) : "{" + k + "}",
  );
}

/** Updates all static DOM elements annotated with data-i18n* attributes via textContent/setAttribute. */
export function applyStaticI18n(): void {
  for (const node of document.querySelectorAll<HTMLElement>("[data-i18n]")) {
    const k = node.dataset["i18n"];
    if (hasKey(k)) node.textContent = t(k);
  }
  for (const node of document.querySelectorAll<HTMLElement>("[data-i18n-ph]")) {
    const k = node.dataset["i18nPh"];
    if (hasKey(k)) node.setAttribute("placeholder", t(k));
  }
  for (const node of document.querySelectorAll<HTMLElement>("[data-i18n-title]")) {
    const k = node.dataset["i18nTitle"];
    if (hasKey(k)) node.setAttribute("title", t(k));
  }
  for (const node of document.querySelectorAll<HTMLElement>("[data-i18n-aria]")) {
    const k = node.dataset["i18nAria"];
    if (hasKey(k)) node.setAttribute("aria-label", t(k));
  }
}

/**
 * Translation of a key built at run time (server message codes such as `advice.<code>.title`).
 * Falls back to the server's English text when no locale defines the key.
 */
export function tDyn(key: string, fallback: string, vars?: Readonly<Record<string, string | number>>): string {
  return hasKey(key) ? t(key, vars) : fallback;
}

/** `one` or `other` form by the plural rules of the current language (`{n}` is filled in). */
export function tPlural(one: MsgKey, other: MsgKey, n: number, vars?: Readonly<Record<string, string | number>>): string {
  const rule = new Intl.PluralRules(current).select(n);
  return t(rule === "one" ? one : other, { n, ...vars });
}

/** A server message (`code` + `args`, English `text`) in the current language. */
export function tMsg(m: { readonly code: string; readonly args: { readonly [k: string]: string | undefined }; readonly text: string }): string {
  const vars: Record<string, string> = {};
  for (const [k, v] of Object.entries(m.args)) if (v !== undefined) vars[k] = v;
  return tDyn("m." + m.code, m.text, vars);
}
