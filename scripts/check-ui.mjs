// UI automated checks: CSP hygiene, WCAG AA contrast + light-dark() parity,
// EN/UK i18n parity & hygiene, and UI_MODULES table parity.
// Zero external dependencies (runs under Node >= 20).

import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const UI_SRC = path.join(ROOT, "src/web/ui/src");
const INDEX_HTML = path.join(ROOT, "src/web/ui/index.html");
const STYLE_CSS = path.join(ROOT, "src/web/ui/style.css");
const MOD_RS = path.join(ROOT, "src/web/mod.rs");

let failures = 0;
function fail(msg) {
  console.error("FAIL:", msg);
  failures++;
}

function read(p) {
  return fs.readFileSync(p, "utf8");
}

function topLevelTsFiles() {
  return fs
    .readdirSync(UI_SRC, { withFileTypes: true })
    .filter((d) => d.isFile() && d.name.endsWith(".ts"))
    .map((d) => d.name)
    .sort();
}

// 1. CSP policy audit
function checkCsp() {
  const forbidden = /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|style=|\.style\./;
  const targets = [INDEX_HTML, ...topLevelTsFiles().map((n) => path.join(UI_SRC, n))];
  for (const file of targets) {
    const lines = read(file).split(/\r?\n/);
    lines.forEach((line, idx) => {
      const m = forbidden.exec(line);
      if (m) fail(`CSP pattern "${m[0]}" found in ${path.relative(ROOT, file)}:${idx + 1}`);
    });
  }

  const html = read(INDEX_HTML).replace(/<!--[\s\S]*?-->/g, "");
  const handlerMatch = /<[^>]*\bon[a-z]+\s*=/i.exec(html);
  if (handlerMatch) fail(`Inline event handler in index.html: ${handlerMatch[0]}`);
  const inlineScriptRe = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let sm;
  while ((sm = inlineScriptRe.exec(html)) !== null) {
    if (sm[1].trim().length > 0) fail("Non-empty inline <script> block in index.html");
  }
}

// 2. WCAG AA contrast & light-dark() fallback parity
function parseHex(hex) {
  const s = hex.trim().replace(/^#/, "");
  if (!/^[0-9a-f]{6}$/i.test(s)) return null;
  return [
    parseInt(s.slice(0, 2), 16),
    parseInt(s.slice(2, 4), 16),
    parseInt(s.slice(4, 6), 16),
  ];
}

function relLuminance([r, g, b]) {
  const c = [r, g, b].map((v) => {
    const s = v / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}

function contrastRatio(hexA, hexB) {
  const a = parseHex(hexA);
  const b = parseHex(hexB);
  if (!a || !b) return null;
  const la = relLuminance(a);
  const lb = relLuminance(b);
  const [hi, lo] = la >= lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

function splitTopLevelComma(inner) {
  let depth = 0;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i];
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    else if (ch === "," && depth === 0) return [inner.slice(0, i).trim(), inner.slice(i + 1).trim()];
  }
  return null;
}

function checkContrastAndFallbacks() {
  const css = read(STYLE_CSS);
  const rootMatch = /:root\s*\{([\s\S]*?)\n\}/.exec(css);
  if (!rootMatch) {
    fail("Could not locate :root token block in style.css");
    return;
  }
  const supMatch = /@supports\s+not\s*\(color:\s*light-dark\(#000,\s*#fff\)\)\s*\{\s*:root\s*\{([\s\S]*?)\n\s*\}\s*\}/.exec(css);
  if (!supMatch) {
    fail("Could not locate @supports not (color: light-dark(...)) fallback block in style.css");
    return;
  }

  const light = new Map();
  const dark = new Map();
  const ldRe = /(--[a-z0-9-]+)\s*:\s*light-dark\(([\s\S]*?)\)\s*;/g;
  let m;
  while ((m = ldRe.exec(rootMatch[1])) !== null) {
    const parts = splitTopLevelComma(m[2]);
    if (!parts) {
      fail(`Malformed light-dark() for ${m[1]}`);
      continue;
    }
    light.set(m[1], parts[0]);
    dark.set(m[1], parts[1]);
  }

  const fallback = new Map();
  const fbRe = /(--[a-z0-9-]+)\s*:\s*([^;]+);/g;
  while ((m = fbRe.exec(supMatch[1])) !== null) {
    fallback.set(m[1], m[2].trim());
  }

  for (const [tok, val] of light.entries()) {
    const fb = fallback.get(tok);
    if (!fb) {
      fail(`Missing fallback for ${tok} in @supports not`);
    } else if (fb !== val) {
      fail(`Fallback mismatch for ${tok}: :root light is ${val}, @supports not has ${fb}`);
    }
  }

  const pairs = [
    ["--fg", "--bg"],
    ["--fg", "--panel"],
    ["--fg", "--panel-alt"],
    ["--fg", "--neutral-bg"],
    ["--fg", "--warn-bg"],
    ["--fg", "--info-bg"],
    ["--muted", "--bg"],
    ["--muted", "--panel"],
    ["--muted", "--panel-alt"],
    ["--muted", "--neutral-bg"],
    ["--ok", "--panel"],
    ["--ok", "--panel-alt"],
    ["--ok", "--ok-bg"],
    ["--warn", "--panel"],
    ["--warn", "--panel-alt"],
    ["--warn", "--warn-bg"],
    ["--bad", "--panel"],
    ["--bad", "--panel-alt"],
    ["--bad", "--bad-bg"],
    ["--info", "--panel"],
    ["--info", "--panel-alt"],
    ["--info", "--info-bg"],
    ["--gw", "--panel"],
    ["--gw", "--panel-alt"],
    ["--net", "--panel"],
    ["--net", "--panel-alt"],
    ["--sig", "--panel"],
    ["--sig", "--panel-alt"],
    ["--accent", "--panel"],
    ["--accent", "--panel-alt"],
    ["--on-accent", "--accent"],
  ];

  for (const [themeName, map] of [["light", light], ["dark", dark]]) {
    for (const [fgTok, bgTok] of pairs) {
      const fgHex = map.get(fgTok);
      const bgHex = map.get(bgTok);
      if (!fgHex || !bgHex) {
        fail(`Missing color token in ${themeName}: ${fgTok} or ${bgTok}`);
        continue;
      }
      const ratio = contrastRatio(fgHex, bgHex);
      if (ratio === null) {
        fail(`Expected hex colors for ${themeName} contrast pair ${fgTok} (${fgHex}) / ${bgTok} (${bgHex})`);
      } else if (ratio < 4.5) {
        fail(`WCAG AA (< 4.5:1) failed in ${themeName}: ${fgTok} (${fgHex}) on ${bgTok} (${bgHex}) = ${ratio.toFixed(2)}:1`);
      }
    }
  }
}

// 3. i18n parity & hygiene
function extractLocaleDict(src) {
  const dict = new Map();
  // Match object property `"key": "value"` handling escaped characters cleanly.
  const entryRe = /"((?:[^"\\]|\\.)+)"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,/g;
  let m;
  while ((m = entryRe.exec(src)) !== null) {
    const key = m[1];
    const val = JSON.parse(`"${m[2]}"`);
    if (dict.has(key)) fail(`Duplicate locale key "${key}"`);
    dict.set(key, val);
  }
  return dict;
}

function placeholdersOf(s) {
  const out = new Set();
  const re = /\{([a-zA-Z0-9_]+)\}/g;
  let m;
  while ((m = re.exec(s)) !== null) out.add(m[1]);
  return [...out].sort();
}

function checkI18n() {
  const files = topLevelTsFiles();
  if (files.some((f) => /^locale_ru\./i.test(f))) {
    fail("Forbidden locale_ru file detected");
  }
  const i18nSrc = read(path.join(UI_SRC, "i18n.ts"));
  if (/code:\s*"ru"/.test(i18nSrc)) {
    fail('Forbidden "ru" locale registered in i18n.ts');
  }

  const en = extractLocaleDict(read(path.join(UI_SRC, "locale_en.ts")));
  const uk = extractLocaleDict(read(path.join(UI_SRC, "locale_uk.ts")));
  if (en.size < 100) fail(`Unexpectedly small EN dictionary (${en.size} keys)`);

  // Allowed intentional alternate placeholders (e.g. floor numbering from 0 in EN vs 1 in UK).
  const ALLOWED_PLACEHOLDERS = {
    "map.floor_n": new Set(["n", "n1"]),
  };

  for (const k of en.keys()) {
    if (!uk.has(k)) fail(`Missing UK translation for key "${k}"`);
    else {
      const ep = placeholdersOf(en.get(k));
      const up = placeholdersOf(uk.get(k));
      const allowed = ALLOWED_PLACEHOLDERS[k];
      if (allowed ? up.some((p) => !allowed.has(p)) : ep.join(",") !== up.join(",")) {
        fail(`Placeholder mismatch for "${k}": EN={${ep.join(",")}} UK={${up.join(",")}}`);
      }
    }
  }
  for (const k of uk.keys()) {
    if (!en.has(k)) fail(`Extra UK translation key not in EN: "${k}"`);
  }

  // index.html data-i18n* attributes
  const html = read(INDEX_HTML);
  const attrRe = /data-i18n(?:-[a-z]+)?="([^"]+)"/g;
  let m;
  while ((m = attrRe.exec(html)) !== null) {
    if (!en.has(m[1])) fail(`index.html references missing i18n key "${m[1]}"`);
  }

  // Literal keys & untranslated literal text in el(..., { text: "..." })
  const TEXT_ALLOWLIST = new Set([
    "Wi-Fi", "DNS", "SSID", "BSSID", "WPS", "CISA KEV", "i", "–", "5 GHz", "2.4 GHz",
    "linkwatch", "OK", "ARP", "UPnP", "15 m", "1 h", "3 h", "6 h", "24 h", "72 h",
  ]);
  for (const f of files) {
    if (f.startsWith("locale_")) continue;
    const fp = path.join(UI_SRC, f);
    const src = read(fp);

    const tCallRe = /\bt\(\s*"([^"]+)"/g;
    while ((m = tCallRe.exec(src)) !== null) {
      if (!en.has(m[1])) fail(`${f}: t("${m[1]}") references unknown EN key`);
    }
    const tPlurRe = /\btPlural\(\s*"([^"]+)"\s*,\s*"([^"]+)"/g;
    while ((m = tPlurRe.exec(src)) !== null) {
      if (!en.has(m[1])) fail(`${f}: tPlural key "${m[1]}" missing from EN`);
      if (!en.has(m[2])) fail(`${f}: tPlural key "${m[2]}" missing from EN`);
    }

    const elTextRe = /\b(?:el|sv)\(\s*"[^"]+"\s*,\s*\{[^}]*\btext\s*:\s*"([^"]+)"/g;
    while ((m = elTextRe.exec(src)) !== null) {
      const lit = m[1].trim();
      if (TEXT_ALLOWLIST.has(lit)) continue;
      if (/[A-Za-z]{2,}/.test(lit)) {
        fail(`${f}: untranslated literal text in element helper: text: "${lit}"`);
      }
    }
  }
}

// 4. UI_MODULES parity with src/*.ts
function checkUiModulesTable() {
  const tsBases = new Set(topLevelTsFiles().map((n) => n.replace(/\.ts$/, ".js")));
  const modSrc = read(MOD_RS);
  const blockMatch = /const UI_MODULES:[^=]*=\s*&\[([\s\S]*?)\];/.exec(modSrc);
  if (!blockMatch) {
    fail("Could not locate UI_MODULES table in src/web/mod.rs");
    return;
  }
  const served = new Set();
  const entryRe = /\("([a-z0-9_.-]+\.js)",\s*include_str!/g;
  let m;
  while ((m = entryRe.exec(blockMatch[1])) !== null) served.add(m[1]);

  for (const js of tsBases) {
    if (!served.has(js)) fail(`src/web/mod.rs UI_MODULES is missing "${js}"`);
  }
  for (const js of served) {
    if (!tsBases.has(js)) fail(`src/web/mod.rs UI_MODULES has stale entry "${js}"`);
  }
}

checkCsp();
checkContrastAndFallbacks();
checkI18n();
checkUiModulesTable();

if (failures > 0) {
  console.error(`\nUI checks failed with ${failures} error(s).`);
  process.exit(1);
} else {
  console.log("UI checks passed: CSP, WCAG AA contrast + fallback parity, EN/UK i18n parity, UI_MODULES.");
}
