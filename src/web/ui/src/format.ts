// Formatting, labels and classification (pure functions, no DOM).

import type { Envelope } from "./api/Envelope.js";
import type { LinkState } from "./api/LinkState.js";
import type { PathState } from "./api/PathState.js";
import type { ScanBss } from "./api/ScanBss.js";
import type { ScanEntry } from "./api/ScanEntry.js";
import type { Verdict } from "./api/Verdict.js";
import { type MsgKey, getLang, t } from "./i18n.js";

/** CSS class of a status colour. */
export type Tone = "ok" | "warn" | "bad" | "neutral" | "info";
export type Label = readonly [text: string, tone: Tone];

export function fmtDur(s: number | null | undefined): string {
  if (s === null || s === undefined || !isFinite(s)) return "–";
  s = Math.max(0, Math.round(s));
  if (s < 60) return t("u.s", { n: s });
  const m = Math.floor(s / 60);
  if (m < 60) return t("u.min", { n: m });
  const h = Math.floor(m / 60);
  if (h < 48) return t("u.h_min", { h, m: m % 60 });
  return t("u.d_h", { d: Math.floor(h / 24), h: h % 24 });
}

export function fmtTime(t: string | null | undefined): string {
  if (!t) return "–";
  const d = new Date(t);
  if (isNaN(d.getTime())) return "–";
  const now = new Date();
  const lang = getLang();
  const hm = d.toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  if (d.toDateString() === now.toDateString()) return hm;
  return d.toLocaleDateString(lang, { month: "short", day: "numeric" }) + " " + hm;
}

/** Short time without seconds ("21:04", or "26 Nov 21:04" on another day). */
export function fmtTimeShort(t: string | null | undefined): string {
  if (!t) return "–";
  const d = new Date(t);
  if (isNaN(d.getTime())) return "–";
  const lang = getLang();
  const hm = d.toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit" });
  if (d.toDateString() === new Date().toDateString()) return hm;
  return d.toLocaleDateString(lang, { month: "short", day: "numeric" }) + " " + hm;
}

/** Seconds from `from` to `to` (or now), for ISO time strings. */
export function secsSince(from: string, to?: string): number {
  return ((to === undefined ? Date.now() : new Date(to).getTime()) - new Date(from).getTime()) / 1000;
}

export function ms(v: number | null | undefined): string {
  return v === null || v === undefined ? "–" : (v < 10 ? v.toFixed(1) : Math.round(v)) + " ms";
}

export function freqToChannel(f: number | null | undefined): number | null {
  if (!f) return null;
  if (f === 2484) return 14;
  if (f >= 2412 && f <= 2472) return (f - 2407) / 5;
  if (f >= 5955 && f <= 7115) return (f - 5950) / 5;
  if (f >= 5000 && f <= 5900) return (f - 5000) / 5;
  return null;
}

export function band(f: number | null | undefined): string {
  if (!f) return "";
  if (f < 3000) return "2.4 GHz";
  if (f < 5925) return "5 GHz";
  return "6 GHz";
}

export function sigPct(dbm: number | null | undefined): number {
  if (dbm === null || dbm === undefined || !isFinite(dbm)) return 0;
  return Math.round(Math.max(0, Math.min(100, ((dbm + 95) / 65) * 100)));
}

type MacBytes = readonly [number, number, number, number, number, number];

function parseMacBytes(mac: string | null | undefined): MacBytes | null {
  if (!mac) return null;
  const parts = mac.trim().split(/[:-]/);
  const out: number[] = [];
  for (const p of parts) {
    if (!/^[0-9a-fA-F]{2}$/.test(p)) return null;
    out.push(parseInt(p, 16));
  }
  const [a, b, c, d, e, f] = out;
  if (out.length !== 6 || a === undefined || b === undefined || c === undefined || d === undefined || e === undefined || f === undefined) {
    return null;
  }
  return [a, b, c, d, e, f];
}

const hex = (bytes: readonly number[]): string => bytes.map((x) => x.toString(16).padStart(2, "0")).join(":");
/** OUI with the locally-administered bit cleared (virtual APs of one radio). */
const ouiNormKey = (b: MacBytes): string => hex([b[0] & ~0x02, b[1], b[2]]);
const macPref5Key = (b: MacBytes): string => hex([b[0] & ~0x02, b[1], b[2], b[3], b[4]]);

export type BssRole =
  | "connected"
  | "same_router_band"
  | "same_router_vap"
  | "same_ssid_other"
  | "co_channel"
  | "adjacent"
  | "neighbour";
export type BssGroup = "ours" | "interfering" | "neighbour";

/** How a scanned network relates to the one the interface uses. */
export interface BssMeta {
  id: BssRole;
  label: string;
  cls: Tone;
  rowCls: string;
  group: BssGroup;
  rank: number;
  ch: number | null;
  bBand: string;
}

export interface ClassifiedBss {
  b: ScanBss;
  meta: BssMeta;
}

export function classifyBss(b: ScanBss, s: ScanEntry): BssMeta {
  const bBssid = b.bssid.toLowerCase();
  const ourBssid = (s.our_bssid ?? "").toLowerCase();
  const ch = b.channel ?? freqToChannel(b.freq_mhz);
  const oursCh = s.our_channel ?? freqToChannel(s.our_freq_mhz);
  const bBand = band(b.freq_mhz);
  const ourBand = band(s.our_freq_mhz);
  const meta = (id: BssRole, label: string, cls: Tone, rowCls: string, group: BssGroup, rank: number): BssMeta =>
    ({ id, label, cls, rowCls, group, rank, ch, bBand });

  if (b.associated || (ourBssid && bBssid && ourBssid === bBssid)) {
    return meta("connected", t("bss.connected"), "ok", "connected", "ours", 0);
  }

  const ourBytes = parseMacBytes(s.our_bssid);
  const bBytes = parseMacBytes(b.bssid);
  const sameOui = Boolean(ourBytes && bBytes && ouiNormKey(ourBytes) === ouiNormKey(bBytes));
  const samePref5 = Boolean(ourBytes && bBytes && macPref5Key(ourBytes) === macPref5Key(bBytes));
  const sameSsid = Boolean(s.our_ssid && b.ssid && b.ssid === s.our_ssid);

  if (sameOui && (sameSsid || samePref5) && ourBand && bBand && ourBand !== bBand) {
    return meta("same_router_band", t("bss.router_band", { band: bBand }), "info", "ours", "ours", 1);
  }
  if (sameOui && (sameSsid || samePref5)) {
    return meta("same_router_vap", t("bss.router_vap"), "info", "ours", "ours", 2);
  }
  if (sameSsid) {
    return meta("same_ssid_other", t("bss.same_ssid"), "warn", "same", "ours", 3);
  }
  if (oursCh && ch && ch === oursCh) {
    return meta("co_channel", t("bss.co_channel", { ch }), "bad", "same", "interfering", 4);
  }
  if (oursCh && ch && ourBand === "2.4 GHz" && bBand === "2.4 GHz" && Math.abs(ch - oursCh) >= 1 && Math.abs(ch - oursCh) <= 4) {
    return meta("adjacent", t("bss.adjacent"), "warn", "same", "interfering", 5);
  }
  return meta("neighbour", t("bss.neighbour"), "neutral", "", "neighbour", 6);
}

// ---------- labels ----------

const VERDICT: { readonly [K in Verdict]: readonly [MsgKey, Tone] } = {
  all_ok: ["verdict.all_ok", "ok"],
  wifi_problem: ["verdict.wifi_problem", "warn"],
  wired_problem: ["verdict.wired_problem", "warn"],
  router_problem: ["verdict.router_problem", "bad"],
  line_problem: ["verdict.line_problem", "bad"],
  internet_problem: ["verdict.internet_problem", "bad"],
  dns: ["verdict.dns", "warn"],
  single_path: ["verdict.single_path", "neutral"],
  unknown: ["verdict.unknown", "neutral"],
};

const PSTATE: { readonly [K in PathState]: readonly [MsgKey, Tone] } = {
  ok: ["pstate.ok", "ok"],
  degraded: ["pstate.degraded", "warn"],
  link_down: ["pstate.link_down", "bad"],
  no_ip: ["pstate.no_ip", "bad"],
  lan_down: ["pstate.lan_down", "bad"],
  isp_down: ["pstate.isp_down", "bad"],
  wan_down: ["pstate.wan_down", "bad"],
  dns_down: ["pstate.dns_down", "warn"],
  unknown: ["pstate.unknown", "neutral"],
};

function lookup(table: { readonly [k: string]: readonly [MsgKey, Tone] }, v: string | null | undefined): Label {
  const hit = v ? table[v] : undefined;
  // A value this UI does not know (older or newer server) reads as "Unknown", not as a raw key.
  return hit ? [t(hit[0]), hit[1]] : [t("verdict.unknown"), "neutral"];
}

/** Label of a verdict; also takes free-form strings (session summaries). */
export const verdictLabel = (v: Verdict | string | null | undefined): Label => lookup(VERDICT, v);
export const stateLabel = (s: PathState | null | undefined): Label => lookup(PSTATE, s);

function linkDiff(a: LinkState, b: LinkState): string {
  const parts: string[] = [];
  if (a.present !== b.present) parts.push(t(b.present ? "ev.if_appeared" : "ev.if_missing"));
  if (a.up !== b.up) parts.push(t(b.up ? "ev.up" : "ev.down"));
  if (a.carrier !== b.carrier) parts.push(t(b.carrier ? "ev.carrier_back" : "ev.carrier_lost"));
  if (a.ipv4 !== b.ipv4) parts.push(b.ipv4 ? t("ev.addr", { ip: b.ipv4 }) : t("ev.addr_lost"));
  if (a.gateway !== b.gateway) parts.push(b.gateway ? t("ev.gw", { ip: b.gateway }) : t("ev.gw_lost"));
  return parts.length ? parts.join(", ") : t("ev.link_details");
}

/** Severity of an event line: a tone, or "detail" for routine lines hidden by default. */
export type EventSeverity = Exclude<Tone, "neutral"> | "detail";
export type EventCategory = "outages" | "wifi" | "observer" | "security" | "detail";
export type EventText = readonly [text: string, severity: EventSeverity, category: EventCategory];

const DISK_MODE: { readonly [mode: string]: MsgKey } = {
  normal: "ev.disk_normal",
  events_only: "ev.disk_events",
  stopped: "ev.disk_stopped",
};

/** Human text, severity and category of an event envelope. */
export function describe(env: Envelope): EventText {
  if (env.type !== "event") return [t("ev.event"), "info", "detail"];
  const ev = env;
  switch (ev.kind) {
    case "start": {
      let s = t("ev.start", { v: ev.version });
      if (ev.gap_s !== undefined) s += t("ev.start_gap", { d: fmtDur(ev.gap_s) });
      if (ev.prev_boot_id && ev.prev_boot_id !== ev.boot_id) s += t("ev.start_reboot");
      return [s, "info", "observer"];
    }
    case "stop":
      return [t("ev.stop", { reason: ev.reason }), "info", "observer"];
    case "state_change": {
      const [to, sev] = stateLabel(ev.to);
      return [t("ev.state", { iface: ev.iface, from: stateLabel(ev.from)[0], to, d: fmtDur(ev.prev_duration_s) }), sev === "neutral" ? "info" : sev, "outages"];
    }
    case "verdict_change": {
      const [to, sev] = verdictLabel(ev.to);
      return [t("ev.verdict", { from: verdictLabel(ev.from)[0], to, d: fmtDur(ev.prev_duration_s) }), sev === "neutral" ? "info" : sev, "outages"];
    }
    case "link_change": {
      const down = (ev.from.carrier && !ev.to.carrier) || (ev.from.up && !ev.to.up) || (ev.from.present && !ev.to.present);
      return [ev.iface + ": " + linkDiff(ev.from, ev.to), down ? "bad" : "detail", "outages"];
    }
    case "roam":
      return [t("ev.roam", { iface: ev.iface, from: ev.from_bssid || "?", to: ev.to_bssid || "?" }), "warn", "wifi"];
    case "channel_change": {
      const c = (f: number | undefined): string => (f ? (freqToChannel(f) || "?") + " (" + f + " MHz)" : "–");
      return [t("ev.channel", { iface: ev.iface, from: c(ev.from_mhz), to: c(ev.to_mhz) }), "warn", "wifi"];
    }
    case "clock_jump":
      return [t("ev.clock", { s: ev.wall_delta_s.toFixed(1) }), "warn", "observer"];
    case "suspend_gap":
      return [t("ev.suspend", { d: fmtDur(ev.secs) }), "bad", "observer"];
    case "dropped_records":
      return [t("ev.dropped", { n: ev.count }), "warn", "observer"];
    case "task_restart":
      return [t("ev.task", { task: ev.task, err: ev.error }), "warn", "observer"];
    case "disk_pressure": {
      const mb = Math.round(ev.free_bytes / 1048576);
      const key = DISK_MODE[ev.mode];
      return [t("ev.disk", { mb, mode: key ? t(key) : ev.mode }), ev.mode === "normal" ? "ok" : "bad", "observer"];
    }
    case "note":
      return [ev.text, "detail", "detail"];
    case "reconnect":
      return [t("ev.reconnect", { iface: ev.iface }) + (ev.bssid ? " (" + ev.bssid + ")" : ""), "warn", "wifi"];
    case "wifi_disconnect": {
      const who = t(ev.by_ap === true ? "ev.by_ap" : ev.by_ap === false ? "ev.by_client" : ev.timed_out ? "ev.timed_out" : "ev.by_unknown");
      const r = ev.reason_code !== undefined ? t("ev.reason", { code: ev.reason_code }) + (ev.reason ? " " + ev.reason : "") : t("ev.disconnect");
      return [t("ev.wifi_disc", { iface: ev.iface, r, who }), "bad", "wifi"];
    }
    case "host_alert":
      return [t("ev.host_alert", { alert: ev.alert, detail: ev.detail }), "warn", ev.alert === "wifi_power_save" ? "wifi" : "observer"];
    case "security":
      return [t("ev.security", { sev: ev.severity, det: ev.detector }) + (ev.iface ? " " + ev.iface : "") + ": " + ev.detail, ev.severity === "high" ? "bad" : "warn", "security"];
    case "network_info":
      return [t("ev.netinfo"), "detail", "detail"];
    case "unknown":
      return [t("ev.event"), "info", "detail"];
    default: {
      // A kind this UI does not know yet (newer server).
      const kind: unknown = (ev as { kind?: unknown }).kind;
      return [typeof kind === "string" && kind ? kind : t("ev.event"), "info", "detail"];
    }
  }
}
