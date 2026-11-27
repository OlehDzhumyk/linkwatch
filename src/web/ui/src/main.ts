// linkwatch web UI: entry module (loaded by index.html as /js/main.js).

import { initAudit, loadAdvice, loadAudit, renderAdvice, renderAudit } from "./audit.js";
import { renderCards, renderHeader } from "./cards.js";
import { byId, el } from "./dom.js";
import { loadEvents, loadSpeed, renderEvents, renderSpeed } from "./events.js";
import { LOCALES, applyStaticI18n, getLang, initI18n, setLang } from "./i18n.js";
import { connect, loadStatus, syncRangeButtons, updateStaleState } from "./live.js";
import { initMeasure, loadControl, loadPlan, openMeasureDialog, renderMeasure, renderMeasureCurrent, renderPlan } from "./measure.js";
import { renderNow, renderNowIncidents, renderNowMeasure } from "./now.js";
import { loadLiveReport, loadReport, renderIncidentsForCurrentReport, renderPointsCompare, renderReport } from "./report.js";
import { initSessions, refreshCompare, renderSessionList, setSessionDetailOpen } from "./sessions.js";
import { focusPoint, initSiteControls, loadSessions, loadSite, refreshSelection, renderSite } from "./site.js";
import { EVENT_FILTERS, LIVE, SCAN_FILTERS, TABS, THEMES, type Tab, type Theme, bus, oneOf, state } from "./state.js";
import { renderAlertBar, renderSystem } from "./system.js";
import { focusTimestamp, loadLiveMinutes, loadMinutes, renderNowTimeline, renderTimelines, resetBrushZoom } from "./timeline.js";
import { initTips, tip } from "./tips.js";
import { initDisclosurePersistence } from "./ui.js";
import { loadScan, renderScan, renderTopology, renderWifiLink } from "./wifi.js";

const THEME_KEY = "lw-theme";
/** Hashes of the old four-tab layout, so bookmarks keep working. */
const LEGACY_TABS: { readonly [k: string]: Tab } = { live: "now", wifi: "diag", system: "diag" };
const SESSION_ID_RE = /^[A-Za-z0-9_.-]+$/;

function parseHash(): { tab: Tab; sessionId: string | null } {
  const raw = window.location.hash.replace(/^#/, "");
  if (raw.startsWith("sessions/")) {
    try {
      const id = decodeURIComponent(raw.slice("sessions/".length));
      if (SESSION_ID_RE.test(id)) return { tab: "sessions", sessionId: id === "live" ? LIVE : id };
    } catch { /* ignore malformed percent-encoding */ }
    return { tab: "sessions", sessionId: null };
  }
  if (oneOf(TABS, raw)) return { tab: raw, sessionId: null };
  return { tab: LEGACY_TABS[raw] ?? "now", sessionId: null };
}

function syncHash(): void {
  const target = state.tab === "sessions" && state.selectedSession !== LIVE
    ? "#sessions/" + encodeURIComponent(state.selectedSession)
    : "#" + state.tab;
  if (window.location.hash !== target) history.replaceState(null, "", target);
}

function redrawActiveTab(): void {
  if (state.tab === "now") {
    renderTopology();
    renderCards();
    renderNowTimeline();
    renderNow();
  } else if (state.tab === "sessions") {
    renderSessionList();
    renderTimelines();
    renderReport();
  } else if (state.tab === "map") {
    renderMeasureCurrent();
    renderPlan();
    if (state.site) renderSite();
    renderPointsCompare();
  } else {
    renderAdvice();
    renderWifiLink();
    renderScan();
    renderSystem();
    renderAudit();
  }
}

export function setTab(tab: Tab, updateHash = true): void {
  state.tab = tab;
  for (const b of byId("tabs").querySelectorAll<HTMLButtonElement>("button[data-tab]")) {
    const active = b.dataset["tab"] === tab;
    b.classList.toggle("on", active);
    b.setAttribute("aria-selected", active ? "true" : "false");
    b.tabIndex = active ? 0 : -1;
  }
  for (const name of TABS) byId("tab-" + name).hidden = name !== tab;
  if (updateHash) syncHash();
  window.scrollTo({ top: 0 });
  requestAnimationFrame(redrawActiveTab);
}

function applyTheme(theme: Theme): void {
  state.theme = theme;
  if (theme === "dark" || theme === "light") document.documentElement.dataset["theme"] = theme;
  else delete document.documentElement.dataset["theme"];
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* storage may be unavailable */ }
  for (const b of byId("theme-seg").querySelectorAll<HTMLButtonElement>("button[data-theme-opt]")) {
    b.setAttribute("aria-checked", b.dataset["themeOpt"] === theme ? "true" : "false");
  }
}

function rebuildStaticTips(): void {
  const vw = byId("verdict-wrap");
  vw.querySelector(".tip-wrap")?.remove();
  vw.append(tip("verdict"));
  byId("hourly-tip").replaceChildren(tip("hourly"));
  byId("audit-tip").replaceChildren(tip("router_audit"));
}

/** Makes `on` the only selected button of a segmented control. */
function selectButton(group: HTMLElement, on: HTMLButtonElement): void {
  for (const x of group.querySelectorAll<HTMLButtonElement>("button")) x.classList.toggle("on", x === on);
}

/** A popup menu opened by `btn`: Esc, a click outside or a choice closes it. */
function initMenu(btnId: string, menuId: string): void {
  const btn = byId(btnId);
  const menu = byId(menuId);
  const close = (): void => {
    menu.hidden = true;
    btn.setAttribute("aria-expanded", "false");
  };
  btn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const open = menu.hidden;
    menu.hidden = !open;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  });
  document.addEventListener("click", (ev) => {
    if (!menu.hidden && ev.target instanceof Node && !menu.contains(ev.target) && ev.target !== btn) close();
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && !menu.hidden) { close(); btn.focus(); }
  });
  for (const a of menu.querySelectorAll("a")) {
    a.addEventListener("click", (ev) => {
      if (a.getAttribute("aria-disabled") === "true") {
        ev.preventDefault();
        return;
      }
      close();
    });
  }
}

function applyHashRoute(first = false): void {
  const { tab, sessionId } = parseHash();
  if (sessionId) {
    const changed = state.selectedSession !== sessionId;
    state.selectedSession = sessionId;
    state.rangeUserSet = true;
    state.highlightTs = null;
    state.brushRange = null;
    setSessionDetailOpen(true);
    setTab(tab, false);
    if (!first && changed) bus.dispatchEvent(new Event("session-selected"));
    return;
  }
  setTab(tab, false);
}

function initTabs(): void {
  const nav = byId("tabs");
  const btns = [...nav.querySelectorAll<HTMLButtonElement>("button[data-tab]")];
  for (const b of btns) {
    b.addEventListener("click", () => {
      const tab = b.dataset["tab"];
      if (oneOf(TABS, tab)) setTab(tab);
    });
    b.addEventListener("keydown", (ev) => {
      const idx = btns.indexOf(b);
      let next = -1;
      if (ev.key === "ArrowRight") next = (idx + 1) % btns.length;
      else if (ev.key === "ArrowLeft") next = (idx - 1 + btns.length) % btns.length;
      else if (ev.key === "Home") next = 0;
      else if (ev.key === "End") next = btns.length - 1;
      const target = btns[next];
      const tab = target?.dataset["tab"];
      if (target && oneOf(TABS, tab)) {
        ev.preventDefault();
        setTab(tab);
        target.focus();
      }
    });
  }
  window.addEventListener("hashchange", () => applyHashRoute(false));
  bus.addEventListener("switch-tab", (ev) => {
    if (ev instanceof CustomEvent && typeof ev.detail === "string" && oneOf(TABS, ev.detail)) setTab(ev.detail);
  });
  applyHashRoute(true);
}

function initControls(): void {
  initI18n();
  const langSel = byId("lang-sel", HTMLSelectElement);
  langSel.replaceChildren(...LOCALES.map((l) => el("option", { value: l.code, text: l.label })));
  langSel.value = getLang();
  applyStaticI18n();

  let saved: string | null = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch { /* storage may be unavailable */ }
  applyTheme(oneOf(THEMES, saved) ? saved : "auto");
  for (const b of byId("theme-seg").querySelectorAll<HTMLButtonElement>("button[data-theme-opt]")) {
    b.addEventListener("click", () => {
      const th = b.dataset["themeOpt"];
      if (!oneOf(THEMES, th)) return;
      applyTheme(th);
      redrawActiveTab();
    });
  }

  initMenu("menu-btn", "menu");
  initMenu("export-btn", "export-menu");
  initTips();
  initAudit();
  initSessions();
  for (const id of ["findings-disc", "events-disc", "points-compare-panel", "router-audit-panel"]) {
    initDisclosurePersistence(id);
  }
  rebuildStaticTips();
  langSel.addEventListener("change", () => {
    if (!setLang(langSel.value)) return;
    applyStaticI18n();
    rebuildStaticTips();
    renderHeader();
    renderAlertBar();
    updateStaleState();
    renderSpeed();
    renderEvents();
    renderMeasure();
    renderSessionList();
    refreshCompare();
    refreshSelection();
    renderReport();
    renderNowTimeline();
    redrawActiveTab();
  });
  initTabs();

  byId("ctx-chip").addEventListener("click", () => {
    const p = state.status?.session?.point;
    setTab("map");
    if (p) requestAnimationFrame(() => focusPoint(p));
  });
  byId("switch-pt-btn").addEventListener("click", () => openMeasureDialog());

  for (const chip of byId("diag-nav").querySelectorAll<HTMLButtonElement>("button[data-target]")) {
    chip.addEventListener("click", () => {
      const id = chip.dataset["target"];
      if (!id) return;
      const target = byId(id);
      if (target instanceof HTMLDetailsElement) target.open = true;
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  for (const b of byId("range").querySelectorAll<HTMLButtonElement>("button")) {
    b.addEventListener("click", () => {
      state.rangeUserSet = true;
      state.hours = Number(b.dataset["h"]);
      resetBrushZoom(false);
      syncRangeButtons();
      void loadMinutes();
    });
  }
  byId("tl-zoom-reset").addEventListener("click", () => resetBrushZoom());

  const evFilter = byId("ev-filter");
  for (const b of evFilter.querySelectorAll<HTMLButtonElement>("button")) {
    b.addEventListener("click", () => {
      const f = b.dataset["f"];
      if (!oneOf(EVENT_FILTERS, f)) return;
      state.evFilter = f;
      selectButton(evFilter, b);
      renderEvents();
    });
  }

  const scanFilter = byId("scan-filter");
  for (const b of scanFilter.querySelectorAll<HTMLButtonElement>("button")) {
    b.addEventListener("click", () => {
      const f = b.dataset["sf"];
      if (!oneOf(SCAN_FILTERS, f)) return;
      state.scanFilter = f;
      selectButton(scanFilter, b);
      renderScan();
    });
  }

  const evAll = byId("ev-all", HTMLInputElement);
  evAll.addEventListener("change", () => { state.showAll = evAll.checked; renderEvents(); });

  bus.addEventListener("events-change", () => renderSystem());
  bus.addEventListener("live-report", () => { renderNowIncidents(); renderNow(); });
  bus.addEventListener("brush-change", () => renderIncidentsForCurrentReport());
  bus.addEventListener("session-selected", () => {
    resetBrushZoom(false);
    syncHash();
    renderSessionList();
    state.report = null;
    renderReport();
    void Promise.all([loadMinutes(), loadEvents(), loadReport()]);
  });
  bus.addEventListener("focus-time", (ev) => {
    if (!(ev instanceof CustomEvent) || typeof ev.detail !== "string") return;
    setSessionDetailOpen(true);
    if (state.tab !== "sessions") setTab("sessions");
    requestAnimationFrame(() => focusTimestamp(ev.detail));
  });
  bus.addEventListener("focus-live-time", (ev) => {
    if (!(ev instanceof CustomEvent) || typeof ev.detail !== "string") return;
    const ts = ev.detail;
    setSessionDetailOpen(true);
    setTab("sessions");
    if (state.selectedSession !== LIVE) {
      state.selectedSession = LIVE;
      bus.dispatchEvent(new Event("session-selected"));
      // The timeline reloads; mark the incident once the minutes are in.
      void loadMinutes().then(() => focusTimestamp(ts));
    } else {
      requestAnimationFrame(() => focusTimestamp(ts));
    }
  });
  bus.addEventListener("focus-point", (ev) => {
    if (!(ev instanceof CustomEvent) || typeof ev.detail !== "string") return;
    setTab("map");
    requestAnimationFrame(() => focusPoint(ev.detail));
  });
  bus.addEventListener("redraw-live", () => requestAnimationFrame(() => {
    if (state.tab === "now") { renderTopology(); renderCards(); }
  }));

  let rt: ReturnType<typeof setTimeout> | undefined;
  window.addEventListener("resize", () => {
    clearTimeout(rt);
    rt = setTimeout(redrawActiveTab, 150);
  });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", redrawActiveTab);
}

/** Reloads what belongs to the running session after a switch or restart (at most once per 500 ms). */
let changeTimer: ReturnType<typeof setTimeout> | undefined;
function onSessionChange(): void {
  clearTimeout(changeTimer);
  changeTimer = setTimeout(() => {
    state.liveRing.clear();
    state.lanSeries = [];
    state.highlightTs = null;
    state.liveReport = null;
    void loadStatus();
    void loadControl().then(() => { renderHeader(); renderAudit(); renderNowMeasure(); });
    void loadPlan().then(() => { renderHeader(); renderPointsCompare(); renderNowMeasure(); });
    void loadSite();
    void loadSessions().then(renderPointsCompare);
    void loadSpeed();
    void loadScan();
    void loadAudit().then(loadAdvice);
    void loadLiveReport();
    void loadLiveMinutes();
    if (state.selectedSession === LIVE) {
      void loadMinutes();
      void loadEvents();
    }
  }, 500);
}

async function main(): Promise<void> {
  initControls();
  initMeasure();
  initSiteControls();
  bus.addEventListener("session-change", onSessionChange);
  await loadStatus();
  void loadControl().then(() => { renderHeader(); renderAudit(); renderNowMeasure(); });
  void loadLiveMinutes();
  void loadMinutes();
  void loadEvents();
  void loadReport();
  void loadSpeed();
  void loadScan();
  void loadAudit().then(loadAdvice);
  void loadSessions().then(renderPointsCompare);
  // The map colours come from the plan: load the site first, then the plan.
  void loadSite().then(loadPlan).then(() => { renderHeader(); renderPointsCompare(); renderNowMeasure(); });
  connect();
  setInterval(updateStaleState, 5000);
  setInterval(() => { renderMeasureCurrent(); renderNowMeasure(); renderHeader(); }, 30000);
  setInterval(() => void loadPlan().then(renderPointsCompare), 300000);
  setInterval(() => { if (!state.live) void loadStatus(); }, 5000);
  setInterval(() => { if (state.live) void loadStatus(); }, 30000);
  setInterval(() => {
    void loadLiveMinutes();
    void loadMinutes();
    void loadLiveReport();
  }, 60000);
  setInterval(() => { void loadSpeed(); void loadScan(); void loadAdvice(); }, 120000);
  setInterval(() => void loadSessions().then(renderPointsCompare), 300000);
}

void main();
