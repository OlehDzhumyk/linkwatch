// JSON API client. Response types are generated from the Rust handlers (src/api/, ts-rs).

import type { AdviceResponse } from "./api/AdviceResponse.js";
import type { CompareReport } from "./api/CompareReport.js";
import type { ControlResponse } from "./api/ControlResponse.js";
import type { CveLookupResponse } from "./api/CveLookupResponse.js";
import type { Envelope } from "./api/Envelope.js";
import type { EventsResponse } from "./api/EventsResponse.js";
import type { MinutesResponse } from "./api/MinutesResponse.js";
import type { PlanResponse } from "./api/PlanResponse.js";
import type { RedactionLevel } from "./api/RedactionLevel.js";
import type { ReportResponse } from "./api/ReportResponse.js";
import type { RouterAudit } from "./api/RouterAudit.js";
import type { ScanResponse } from "./api/ScanResponse.js";
import type { SessionEventsResponse } from "./api/SessionEventsResponse.js";
import type { SessionsResponse } from "./api/SessionsResponse.js";
import type { SiteResponse } from "./api/SiteResponse.js";
import type { SpeedResponse } from "./api/SpeedResponse.js";
import type { StatusResponse } from "./api/StatusResponse.js";
import type { SupportAudience } from "./api/SupportAudience.js";
import type { SupportLang } from "./api/SupportLang.js";
import type { SupportPack } from "./api/SupportPack.js";
import { LIVE } from "./state.js";

const TIMEOUT_MS = 15000;

export function isObject(v: unknown): v is { readonly [k: string]: unknown } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * GET a JSON body. Null on network errors, timeouts, non-2xx answers and bodies that are not
 * an object with the field `key`. The server is trusted for the rest of the shape: the types
 * come from the same Rust code that builds the responses.
 */
async function getJSON<T extends object>(url: string, key: keyof T & string): Promise<T | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, { signal: ctl.signal, cache: "no-store" });
    if (!r.ok) return null;
    const body: unknown = await r.json();
    return isObject(body) && key in body ? (body as T) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

const enc = encodeURIComponent;

export const fetchStatus = (): Promise<StatusResponse | null> => getJSON<StatusResponse>("/api/status", "ifaces");

export function fetchMinutes(session: string, hours: number): Promise<MinutesResponse | null> {
  const span = hours < 1 ? "minutes=" + Math.round(hours * 60) : "hours=" + hours;
  const q = session === LIVE
    ? "/api/minutes?" + span
    : "/api/minutes?session=" + enc(session) + "&" + span;
  return getJSON<MinutesResponse>(q, "ifaces");
}

export function fetchReport(session: string): Promise<ReportResponse | null> {
  const url = session === LIVE ? "/api/report" : "/api/report?session=" + enc(session);
  return getJSON<ReportResponse>(url, "ifaces");
}

/** URL of `/api/compare` for 2..=8 session ids (`format` json or md). */
export function compareUrl(ids: readonly string[], format: "json" | "md", toleranceS = 2): string {
  return "/api/compare?sessions=" + ids.map(enc).join(",") + "&format=" + format + "&tolerance_s=" + enc(String(toleranceS));
}

export const fetchCompare = (ids: readonly string[], toleranceS = 2): Promise<CompareReport | null> =>
  getJSON<CompareReport>(compareUrl(ids, "json", toleranceS), "sessions");

export function fetchEvents(session: string): Promise<EventsResponse | SessionEventsResponse | null> {
  return session === LIVE
    ? getJSON<EventsResponse>("/api/events?limit=500", "events")
    : getJSON<SessionEventsResponse>("/api/sessions/" + enc(session) + "/events?limit=500", "events");
}

export const fetchSpeed = (): Promise<SpeedResponse | null> => getJSON<SpeedResponse>("/api/speed", "speed");
export const fetchScan = (): Promise<ScanResponse | null> => getJSON<ScanResponse>("/api/scan", "scan");
export const fetchSite = (): Promise<SiteResponse | null> => getJSON<SiteResponse>("/api/site", "buildings");
export const fetchSessions = (): Promise<SessionsResponse | null> => getJSON<SessionsResponse>("/api/sessions", "sessions");

export const fetchControl = (): Promise<ControlResponse | null> => getJSON<ControlResponse>("/api/control", "enabled");
export const fetchPlan = (): Promise<PlanResponse | null> => getJSON<PlanResponse>("/api/plan", "items");
export const fetchRouterAudit = (): Promise<RouterAudit | null> => getJSON<RouterAudit>("/api/router/audit", "adapter_used");
export const fetchAdvice = (): Promise<AdviceResponse | null> => getJSON<AdviceResponse>("/api/advice", "items");

/** Body of POST /api/control/session (`control::SessionRequest` in Rust). */
export interface SessionRequestBody {
  point?: string;
  label?: string;
  note?: string;
}

export type RouterAdapter = "auto" | "upnp" | "snmp" | "tr064" | "openwrt" | "mikrotik" | "http";

/** Body of POST /api/router/probe (`router_audit::RouterProbeRequest` in Rust). */
export interface RouterProbeBody {
  adapter?: RouterAdapter;
  host?: string;
  username?: string;
  password?: string;
  community?: string;
}

/** Body of POST /api/router/cve (`cve::CveLookupRequest` in Rust). */
export interface CveLookupBody {
  vendor?: string;
  model: string;
  firmware?: string;
}

export type PostResult<T> = { ok: true; data: T } | { ok: false; error: string };

async function postJSON<T extends object>(
  url: string,
  body: unknown,
  timeoutMs: number,
  key: keyof T & string,
): Promise<PostResult<T>> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: ctl.signal,
      cache: "no-store",
      credentials: "same-origin",
    });
    let v: unknown = null;
    try { v = await r.json(); } catch { /* the body is not JSON */ }
    if (r.ok && isObject(v) && key in v) return { ok: true, data: v as T };
    const err = isObject(v) && typeof v["error"] === "string" ? v["error"] : "HTTP " + r.status;
    return { ok: false, error: err };
  } catch {
    return { ok: false, error: "no answer from the monitor (network error or timeout)" };
  } finally {
    clearTimeout(timer);
  }
}

/** Result of a session switch: the new session id, or the reason it failed. */
export type SwitchResult = { ok: true; session: string } | { ok: false; error: string };

/** Asks the monitor to close the running session and start a new one. */
export async function postSession(body: SessionRequestBody): Promise<SwitchResult> {
  const r = await postJSON<{ session: string }>("/api/control/session", body, 90000, "session");
  return r.ok ? { ok: true, session: r.data.session } : r;
}

export const postRouterProbe = (body: RouterProbeBody): Promise<PostResult<RouterAudit>> =>
  postJSON<RouterAudit>("/api/router/probe", body, 25000, "adapter_used");

export const postRouterCve = (body: CveLookupBody): Promise<PostResult<CveLookupResponse>> =>
  postJSON<CveLookupResponse>("/api/router/cve", body, 25000, "items");

export interface SupportReportOpts {
  audience: SupportAudience;
  lang: SupportLang;
  redact: RedactionLevel;
  toleranceS?: number;
}

/** URL of `/api/support-report` for JSON, plain ticket text, Markdown or printable HTML. */
export function supportReportUrl(
  ids: readonly string[],
  opts: SupportReportOpts,
  format: "json" | "text" | "md" | "html",
): string {
  const parts = [
    "audience=" + enc(opts.audience),
    "lang=" + enc(opts.lang),
    "redact=" + enc(opts.redact),
    "format=" + enc(format),
  ];
  if (ids.length > 0) parts.push("sessions=" + ids.map(enc).join(","));
  if (opts.toleranceS !== undefined) parts.push("tolerance_s=" + enc(String(opts.toleranceS)));
  return "/api/support-report?" + parts.join("&");
}

export const fetchSupportReport = (ids: readonly string[], opts: SupportReportOpts): Promise<SupportPack | null> =>
  getJSON<SupportPack>(supportReportUrl(ids, opts, "json"), "short_text");

/** An SSE `data` payload as an envelope, or null when it is not one. */
export function parseEnvelope(data: string): Envelope | null {
  let v: unknown;
  try {
    v = JSON.parse(data);
  } catch {
    return null;
  }
  return isObject(v) && typeof v["type"] === "string" ? (v as Envelope) : null;
}
