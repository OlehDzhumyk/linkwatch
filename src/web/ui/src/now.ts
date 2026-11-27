// Now view: the verdict hero (one sentence + path strip), the current measurement and the
// latest network incidents of the running session.

import { byId, el, patch } from "./dom.js";
import { fmtDur, fmtTimeShort, secsSince, verdictLabel } from "./format.js";
import { t, tDyn, tPlural } from "./i18n.js";
import { planItem, pointLabel, progressText, statusChip } from "./points.js";
import { episodeRow, verdictSentence } from "./report.js";
import { state } from "./state.js";

/** Short live explanation while no report exists yet (first minute of a session). */
function liveSentence(): string {
  const v = state.status?.verdict;
  return v ? tDyn("hero.live." + v, t("hero.waiting")) : t("hero.waiting");
}

export function renderHero(): void {
  const s = state.status;
  const hero = byId("hero");
  if (!s) return;
  const [label, tone] = verdictLabel(s.verdict);
  hero.className = "hero " + tone;
  byId("hero-title").textContent = label;
  byId("hero-since").textContent = s.verdict_since ? t("hero.since", { t: fmtTimeShort(s.verdict_since) }) : "";
  const rep = state.liveReport;
  // The report sentence describes the whole session; it is only used when it agrees with the
  // live verdict, so the hero never shows two different stories.
  byId("verdict-explain").textContent = rep && rep.verdict === s.verdict ? verdictSentence(rep) : liveSentence();
}

export function renderNowMeasure(): void {
  const box = byId("now-meas-body");
  const c = state.control;
  const m = state.status?.session;
  const point = c?.point ?? m?.point ?? null;
  const started = c?.started ?? m?.started ?? null;
  const label = c?.label ?? m?.label ?? null;
  const it = point ? planItem(point) : undefined;
  const rows: HTMLElement[] = [
    el("div", { class: "point", text: point ? pointLabel(point) : t("ctx.no_point") }),
  ];
  const facts = [label, started ? t("now.running_for", { d: fmtDur(secsSince(started)) }) : null].filter(Boolean).join(" · ");
  if (facts) rows.push(el("div", { class: "small muted", text: facts }));
  if (it) {
    rows.push(el("div", { class: "row-wrap" }, statusChip(it.status), el("span", { class: "small", text: progressText(it) })));
    rows.push(el("progress", {
      class: "plan-prog " + it.status,
      max: it.target_s ?? Math.max(it.measured_s, 1),
      value: Math.min(it.measured_s, it.target_s ?? it.measured_s),
      "aria-label": progressText(it),
    }));
  }
  if (c && !c.enabled) rows.push(el("div", { class: "small muted", text: t("now.read_only") }));
  patch(box, el("div", { class: "meas-sum" }, ...rows));
}

export function renderNowIncidents(): void {
  const list = byId("now-incidents");
  const rep = state.liveReport;
  const obs = byId("now-obs");
  if (!rep) {
    list.replaceChildren(el("li", { class: "empty small", text: t("report.analyzing") }));
    byId("now-inc-count").textContent = "0";
    obs.hidden = true;
    return;
  }
  const net = rep.episodes.filter((e) => e.origin !== "observer");
  byId("now-inc-count").textContent = String(net.length);
  list.replaceChildren(...(net.length
    ? net.slice(0, 5).map((e) => episodeRow(e, false, true))
    : [el("li", { class: "empty small", text: t("now.no_incidents") })]));
  obs.hidden = rep.observer_incidents === 0;
  obs.textContent = tPlural("now.obs_one", "now.obs_other", rep.observer_incidents);
}

export function renderNow(): void {
  renderHero();
  renderNowMeasure();
  renderNowIncidents();
}
