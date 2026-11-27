// Router diagnostics (adapters, gateway port scan, on-demand CVEs) & config/security advisor.

import type { AdviceItem } from "./api/AdviceItem.js";
import type { CveItem } from "./api/CveItem.js";
import type { PortCheck } from "./api/PortCheck.js";
import {
  type CveLookupBody,
  type RouterAdapter,
  type RouterProbeBody,
  fetchAdvice,
  fetchRouterAudit,
  postRouterCve,
  postRouterProbe,
} from "./client.js";
import { byId, el } from "./dom.js";
import { fmtDur, fmtTime } from "./format.js";
import { t, tDyn } from "./i18n.js";
import { maskedMac } from "./wifi.js";
import { oneOf, state } from "./state.js";
import { renderAlertBar } from "./system.js";
import { tip } from "./tips.js";

const ADAPTERS: readonly RouterAdapter[] = ["auto", "upnp", "snmp", "tr064", "openwrt", "mikrotik", "http"];

function sevTone(sev: string): string {
  if (sev === "critical" || sev === "high") return "bad";
  if (sev === "warn" || sev === "medium") return "warn";
  if (sev === "info" || sev === "low") return "info";
  if (sev === "ok") return "ok";
  return "neutral";
}

function showMsg(id: string, text: string, tone: "ok" | "bad" | "info"): void {
  const m = byId(id);
  m.textContent = text;
  m.className = "meas-msg small " + tone;
  m.hidden = text === "";
}

function kvRow(dl: HTMLDListElement, label: string, val: Node | string): void {
  dl.append(
    el("dt", { text: label }),
    el("dd", null, val),
  );
}

function renderAdviceItem(a: AdviceItem): HTMLLIElement {
  const tone = sevTone(a.severity);
  return el("li", { class: "advice-item " + tone },
    el("div", { class: "advice-top" },
      el("span", { class: "advice-title", text: tDyn("advice." + a.code + ".title", a.title, a.args) }),
      el("span", { class: "advice-pills" },
        el("span", { class: "pill small " + tone, text: tDyn("sev." + a.severity, a.severity) }),
        el("span", { class: "pill small neutral", text: tDyn("cat." + a.category, a.category) }))),
    el("div", { class: "small muted", text: tDyn("advice." + a.code + ".evidence", a.evidence, a.args) }),
    el("div", { class: "advice-rec small", text: t("sys.advice_action", { text: tDyn("advice." + a.code + ".rec", a.recommendation, a.args) }) }));
}

export function renderAdvice(): void {
  const list = byId("advice-list");
  const badge = byId("advice-count");
  const items = state.advice?.items ?? [];
  const activeCount = items.filter((i) => i.severity !== "ok").length;
  badge.textContent = String(activeCount);
  if (!items.length) {
    list.replaceChildren(el("li", { class: "empty small", text: t("sys.advice_wait") }));
    return;
  }
  list.replaceChildren(...items.map(renderAdviceItem));
}

export async function loadAdvice(): Promise<void> {
  const a = await fetchAdvice();
  if (a) {
    state.advice = a;
    renderAdvice();
    renderAlertBar();
  }
}

function renderPortChip(p: PortCheck): HTMLElement {
  const cls = p.open ? sevTone(p.risk) : "closed";
  const lbl = p.port + " " + p.service + " · " + t(p.open ? "sys.port_open" : "sys.port_closed");
  return el("span", { class: "port-chip " + cls, text: lbl });
}

function renderCveRow(c: CveItem): HTMLLIElement {
  const tone = c.kev ? "bad" : sevTone(c.severity.toLowerCase());
  const titleNode: Node | string = c.url.startsWith("https://")
    ? el("a", { class: "mono cve-id", href: c.url, target: "_blank", rel: "noopener noreferrer", text: c.id })
    : el("span", { class: "mono cve-id", text: c.id });
  return el("li", { class: "cve-item " + tone },
    el("div", { class: "cve-top" },
      titleNode,
      el("span", { class: "advice-pills" },
        el("span", { class: "pill small " + tone, text: c.severity + (c.cvss !== null ? " " + c.cvss.toFixed(1) : "") }),
        c.kev ? el("span", { class: "pill small bad", text: "CISA KEV" }) : null,
        c.published ? el("span", { class: "small muted mono", text: c.published.slice(0, 10) }) : null)),
    el("div", { class: "small", text: c.summary }));
}

function renderCve(): void {
  const box = byId("cve-results");
  const res = state.cve;
  if (!res) {
    box.replaceChildren();
    return;
  }
  const meta = el("div", { class: "small muted cve-meta" },
    t("sys.cve_query") + " ",
    el("span", { class: "mono", text: res.query }),
    " · " + t("sys.cve_meta", { src: res.source, n: res.total }) +
    (res.kev_count ? " · KEV: " + res.kev_count : "") +
    (res.cached ? " · " + t("sys.cve_cached") : ""));
  const note = res.note ? el("p", { class: "small muted cve-note", text: res.note }) : null;
  const list = res.items.length
    ? el("ul", { class: "cve-list" }, ...res.items.map(renderCveRow))
    : el("p", { class: "empty small", text: t("sys.cve_none") });
  box.replaceChildren(meta, ...(note ? [note] : []), list);
}

function syncAdapterInputs(): void {
  const sel = byId("audit-adapter-sel", HTMLSelectElement).value;
  byId("audit-cred-fields").hidden = sel !== "auto" && sel !== "tr064" && sel !== "openwrt" && sel !== "mikrotik";
  byId("audit-snmp-fields").hidden = sel !== "snmp";
}

function prefillCveInputs(): void {
  const a = state.audit;
  const vEl = byId("cve-vendor", HTMLInputElement);
  const mEl = byId("cve-model", HTMLInputElement);
  const fEl = byId("cve-fw", HTMLInputElement);
  if (vEl.dataset["touched"] !== "1" && a?.vendor) vEl.value = a.vendor;
  const model = a?.model ?? state.status?.router?.model;
  if (mEl.dataset["touched"] !== "1" && model) mEl.value = model;
  if (fEl.dataset["touched"] !== "1" && a?.firmware) fEl.value = a.firmware;
}

function tokenMissingForPosts(): boolean {
  const c = state.control;
  return c !== null && !c.enabled && Boolean(c.reason?.includes("token"));
}

function syncAuthState(busy = false): void {
  const blocked = tokenMissingForPosts();
  byId("audit-token-note").hidden = !blocked;
  byId("audit-token-note").textContent = blocked ? t("sys.audit_token") : "";
  byId("audit-probe-btn", HTMLButtonElement).disabled = busy || blocked;
  byId("cve-check-btn", HTMLButtonElement).disabled = busy || blocked;
}

export function renderAudit(): void {
  const pill = byId("audit-adapter");
  const kvBox = byId("audit-kv", HTMLDListElement);
  const portsBox = byId("audit-ports");
  const warnBox = byId("audit-warnings");
  const a = state.audit;

  syncAuthState(false);
  prefillCveInputs();

  if (!a) {
    pill.textContent = t("sys.audit_idle");
    pill.className = "pill small neutral";
    kvBox.replaceChildren();
    portsBox.replaceChildren(el("span", { class: "small muted", text: t("sys.audit_wait") }));
    warnBox.replaceChildren();
    renderCve();
    return;
  }

  pill.textContent = a.adapter_used === "none" ? t("sys.not_probed") : a.adapter_used;
  pill.className = "pill small " + (a.adapter_used === "none" ? "neutral" : "ok");

  kvBox.replaceChildren();
  kvRow(kvBox, t("k.gateway_ip"), a.gateway_ip ?? "–");
  if (a.gateway_mac) kvRow(kvBox, t("k.gateway_mac"), maskedMac(a.gateway_mac));
  if (a.vendor) kvRow(kvBox, t("k.vendor"), a.vendor);
  if (a.model) kvRow(kvBox, t("k.model"), a.model);
  if (a.firmware) kvRow(kvBox, t("k.firmware"), a.firmware);
  if (a.admin_url) {
    const safeUrl = a.admin_url.startsWith("http://") || a.admin_url.startsWith("https://");
    kvRow(
      kvBox,
      t("k.admin_ui"),
      safeUrl
        ? el("a", { class: "mono", href: a.admin_url, target: "_blank", rel: "noopener noreferrer", text: a.admin_url })
        : el("span", { class: "mono", text: a.admin_url }),
    );
  }
  if (a.uptime_s !== null) kvRow(kvBox, t("k.uptime"), fmtDur(a.uptime_s));
  if (a.adapter_used !== "none") kvRow(kvBox, t("k.probed"), fmtTime(a.probed_at));
  for (const d of a.details) kvRow(kvBox, d.label, d.value);

  portsBox.replaceChildren(
    ...(a.ports.length
      ? a.ports.map(renderPortChip)
      : [el("span", { class: "small muted", text: t("sys.ports_empty") })]),
  );

  warnBox.replaceChildren(...a.warnings.map((w) => el("li", { class: "small warn", text: w })));
  renderCve();
}

export async function loadAudit(): Promise<void> {
  const a = await fetchRouterAudit();
  if (a) {
    state.audit = a;
    renderAudit();
  }
}

async function runProbe(): Promise<void> {
  if (tokenMissingForPosts()) return;
  const sel = byId("audit-adapter-sel", HTMLSelectElement).value;
  const adapter: RouterAdapter = oneOf(ADAPTERS, sel) ? sel : "auto";
  const host = byId("audit-host", HTMLInputElement).value.trim();
  const userEl = byId("audit-user", HTMLInputElement);
  const passEl = byId("audit-pass", HTMLInputElement);
  const commEl = byId("audit-comm", HTMLInputElement);
  const credsShown = !byId("audit-cred-fields").hidden;
  const snmpShown = !byId("audit-snmp-fields").hidden;

  const body: RouterProbeBody = { adapter };
  if (host) body.host = host;
  if (credsShown) {
    const u = userEl.value.trim();
    const p = passEl.value;
    if (u) body.username = u;
    if (p) body.password = p;
  }
  if (snmpShown) {
    const c = commEl.value.trim();
    if (c) body.community = c;
  }

  // Wipe secret inputs from DOM immediately after reading them into memory.
  passEl.value = "";
  commEl.value = "";

  syncAuthState(true);
  showMsg("audit-msg", t("sys.probing"), "info");
  const r = await postRouterProbe(body);
  syncAuthState(false);

  if (r.ok) {
    state.audit = r.data;
    renderAudit();
    showMsg("audit-msg", t("sys.probe_ok", { adapter: r.data.adapter_used }), "ok");
    void loadAdvice();
  } else {
    showMsg("audit-msg", r.error, "bad");
  }
}

async function runCveLookup(): Promise<void> {
  if (tokenMissingForPosts()) return;
  const vendor = byId("cve-vendor", HTMLInputElement).value.trim();
  const model = byId("cve-model", HTMLInputElement).value.trim();
  const firmware = byId("cve-fw", HTMLInputElement).value.trim();
  if (!model) {
    showMsg("cve-msg", t("sys.cve_enter_model"), "bad");
    byId("cve-model", HTMLInputElement).focus();
    return;
  }

  const body: CveLookupBody = { model };
  if (vendor) body.vendor = vendor;
  if (firmware) body.firmware = firmware;

  syncAuthState(true);
  showMsg("cve-msg", t("sys.cve_querying"), "info");
  const r = await postRouterCve(body);
  syncAuthState(false);

  if (r.ok) {
    state.cve = r.data;
    renderCve();
    showMsg(
      "cve-msg",
      t("sys.cve_found", {
        total: r.data.total,
        kev: r.data.kev_count ? " (" + r.data.kev_count + " CISA KEV)" : "",
        cached: r.data.cached ? " · cached" : "",
      }),
      r.data.kev_count > 0 ? "bad" : "ok",
    );
  } else {
    showMsg("cve-msg", r.error, "bad");
  }
}

export function initAudit(): void {
  byId("audit-tip").replaceChildren(tip("router_audit"));
  byId("advice-refresh").addEventListener("click", () => { void loadAdvice(); });
  byId("audit-adapter-sel").addEventListener("change", syncAdapterInputs);
  byId("audit-probe-btn").addEventListener("click", () => { void runProbe(); });
  byId("cve-check-btn").addEventListener("click", () => { void runCveLookup(); });

  for (const id of ["audit-host", "audit-user", "audit-pass", "audit-comm"]) {
    byId(id, HTMLInputElement).addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        void runProbe();
      }
    });
  }
  for (const id of ["cve-vendor", "cve-model", "cve-fw"]) {
    const inp = byId(id, HTMLInputElement);
    inp.addEventListener("input", () => { inp.dataset["touched"] = "1"; });
    inp.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        void runCveLookup();
      }
    });
  }
  syncAdapterInputs();
  renderAdvice();
  renderAudit();
}
