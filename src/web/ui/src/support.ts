// Support & Escalation Report Pack dialog (Sessions view): audience/language/redaction
// controls, readiness & negative-gating warning, already-ruled-out checklist, asks, and export.

import type { ReadinessLevel } from "./api/ReadinessLevel.js";
import type { RedactionLevel } from "./api/RedactionLevel.js";
import type { SupportAudience } from "./api/SupportAudience.js";
import type { SupportLang } from "./api/SupportLang.js";
import type { SupportPack } from "./api/SupportPack.js";
import { fetchSupportReport, supportReportUrl } from "./client.js";
import { byId, el } from "./dom.js";
import { getLang, t } from "./i18n.js";
import { LIVE, state } from "./state.js";
import { type DialogHandle, wireDialog } from "./ui.js";

let dlg: DialogHandle | null = null;
let targetSessions: string[] = [];
let seq = 0;

function readAudience(): SupportAudience {
  const v = byId("sup-audience", HTMLSelectElement).value;
  return v === "landlord" || v === "admin" ? v : "isp";
}

function readLang(): SupportLang {
  return byId("sup-lang", HTMLSelectElement).value === "uk" ? "uk" : "en";
}

function readRedact(): RedactionLevel {
  const sel = byId("sup-redact", HTMLSelectElement);
  const canUnredact = Boolean(state.control?.enabled);
  const noneOpt = sel.querySelector<HTMLOptionElement>('option[value="none"]');
  if (noneOpt) noneOpt.disabled = !canUnredact;
  if (!canUnredact && sel.value === "none") sel.value = "standard";
  const v = sel.value;
  return v === "strict" || (v === "none" && canUnredact) ? v : "standard";
}

function currentOpts(): { audience: SupportAudience; lang: SupportLang; redact: RedactionLevel; toleranceS: number } {
  return { audience: readAudience(), lang: readLang(), redact: readRedact(), toleranceS: state.compareTol };
}

function readinessPill(lv: ReadinessLevel): [string, string] {
  if (lv === "high") return [t("sup.ready_high"), "ok"];
  if (lv === "medium") return [t("sup.ready_med"), "warn"];
  return [t("sup.ready_low"), "bad"];
}

function audLabel(aud: SupportAudience): string {
  if (aud === "landlord") return t("sup.aud_landlord");
  if (aud === "admin") return t("sup.aud_admin");
  return t("sup.aud_isp");
}

function showMsg(text: string, tone: "ok" | "bad" | "info" | ""): void {
  const m = byId("sup-msg");
  m.textContent = text;
  m.className = "msg small " + (tone || "info");
  m.hidden = text === "";
}

function updateDownloadLinks(): void {
  const opts = currentOpts();
  byId("sup-dl-md", HTMLAnchorElement).href = supportReportUrl(targetSessions, opts, "md");
  byId("sup-dl-html", HTMLAnchorElement).href = supportReportUrl(targetSessions, opts, "html");
}

function renderPack(pack: SupportPack): void {
  const [rTxt, rTone] = readinessPill(pack.readiness.level);
  const pill = byId("sup-readiness-pill");
  pill.textContent = rTxt;
  pill.className = "pill small " + rTone;

  const vEl = byId("sup-verdict");
  vEl.textContent = pack.verdict_headline;
  vEl.className = "verdict-explain " + (pack.readiness.do_not_file_isp_line_ticket ? "warn" : "info");
  vEl.hidden = false;

  const wBox = byId("sup-warnings");
  const wItems = pack.readiness.warnings.map((w) => el("p", { class: "small", text: w }));
  const sug = pack.readiness.suggested_audience;
  if (sug && sug !== pack.audience) {
    wItems.push(el("div", { class: "sup-warn-row" },
      el("span", { class: "small muted", text: t("sup.switch_hint", { aud: audLabel(sug) }) }),
      el("button", {
        type: "button",
        class: "ctrl primary",
        text: t("sup.switch_btn", { aud: audLabel(sug) }),
        onclick: () => {
          byId("sup-audience", HTMLSelectElement).value = sug;
          void loadPack();
        },
      })));
  }
  wBox.hidden = wItems.length === 0;
  wBox.replaceChildren(...wItems);

  const ruledBox = byId("sup-ruled-box");
  byId("sup-ruled-list").replaceChildren(...pack.ruled_out.items.map((x) => el("li", { text: x })));
  ruledBox.hidden = pack.ruled_out.items.length === 0;

  const asksBox = byId("sup-asks-box");
  byId("sup-asks-list").replaceChildren(...pack.asks.map((a) =>
    el("li", null,
      el("strong", { text: a.summary }),
      el("div", { class: "small muted", text: a.rationale }))));
  asksBox.hidden = pack.asks.length === 0;

  const notesBox = byId("sup-notes-box");
  if (pack.free_text_notes.length) {
    notesBox.textContent = t("sup.free_notes_warn", { n: pack.free_text_notes.length, notes: pack.free_text_notes.join(" · ") });
    notesBox.hidden = false;
  } else {
    notesBox.hidden = true;
    notesBox.textContent = "";
  }

  const ta = byId("sup-text", HTMLTextAreaElement);
  ta.value = pack.short_text;
  byId("sup-char-count").textContent = t("sup.chars", { n: pack.short_text.length });
  updateDownloadLinks();
  showMsg("", "");
}

async function loadPack(): Promise<void> {
  const mySeq = ++seq;
  updateDownloadLinks();
  byId("sup-text", HTMLTextAreaElement).value = "";
  byId("sup-char-count").textContent = t("sup.loading");
  showMsg("", "");

  const pack = await fetchSupportReport(targetSessions, currentOpts());
  if (mySeq !== seq) return;
  if (!pack) {
    byId("sup-char-count").textContent = "";
    showMsg(t("sup.load_err"), "bad");
    return;
  }
  renderPack(pack);
}

async function copyShortText(): Promise<void> {
  const ta = byId("sup-text", HTMLTextAreaElement);
  if (!ta.value) return;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(ta.value);
      showMsg(t("sup.copied"), "ok");
      return;
    }
  } catch { /* fall through to select fallback in non-HTTPS LAN tabs */ }
  ta.focus();
  ta.select();
  showMsg(t("sup.copy_fallback"), "info");
}

export function openSupportDialog(sessions?: readonly string[]): void {
  if (!dlg) return;
  if (sessions && sessions.length > 0) targetSessions = [...sessions];
  else if (state.selectedSession !== LIVE) targetSessions = [state.selectedSession];
  else targetSessions = [];

  const langSel = byId("sup-lang", HTMLSelectElement);
  langSel.value = getLang() === "uk" ? "uk" : "en";
  dlg.open(byId("sup-audience"));
  void loadPack();
}

export function initSupportDialog(): void {
  dlg = wireDialog(byId("support-dialog", HTMLDialogElement));
  byId("sup-close").addEventListener("click", () => dlg?.close());
  byId("sup-copy").addEventListener("click", () => void copyShortText());
  for (const id of ["sup-audience", "sup-lang", "sup-redact"] as const) {
    byId(id).addEventListener("change", () => void loadPack());
  }
  byId("support-open-btn").addEventListener("click", () => openSupportDialog());
}
