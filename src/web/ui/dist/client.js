// JSON API client. Response types are generated from the Rust handlers (src/api/, ts-rs).
import { LIVE } from "./state.js";
const TIMEOUT_MS = 15000;
export function isObject(v) {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}
/**
 * GET a JSON body. Null on network errors, timeouts, non-2xx answers and bodies that are not
 * an object with the field `key`. The server is trusted for the rest of the shape: the types
 * come from the same Rust code that builds the responses.
 */
async function getJSON(url, key) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    try {
        const r = await fetch(url, { signal: ctl.signal, cache: "no-store" });
        if (!r.ok)
            return null;
        const body = await r.json();
        return isObject(body) && key in body ? body : null;
    }
    catch {
        return null;
    }
    finally {
        clearTimeout(timer);
    }
}
const enc = encodeURIComponent;
export const fetchStatus = () => getJSON("/api/status", "ifaces");
export function fetchMinutes(session, hours) {
    const span = hours < 1 ? "minutes=" + Math.round(hours * 60) : "hours=" + hours;
    const q = session === LIVE
        ? "/api/minutes?" + span
        : "/api/minutes?session=" + enc(session) + "&" + span;
    return getJSON(q, "ifaces");
}
export function fetchReport(session) {
    const url = session === LIVE ? "/api/report" : "/api/report?session=" + enc(session);
    return getJSON(url, "ifaces");
}
/** URL of `/api/compare` for 2..=8 session ids (`format` json or md). */
export function compareUrl(ids, format) {
    return "/api/compare?sessions=" + ids.map(enc).join(",") + "&format=" + format;
}
export const fetchCompare = (ids) => getJSON(compareUrl(ids, "json"), "sessions");
export function fetchEvents(session) {
    return session === LIVE
        ? getJSON("/api/events?limit=500", "events")
        : getJSON("/api/sessions/" + enc(session) + "/events?limit=500", "events");
}
export const fetchSpeed = () => getJSON("/api/speed", "speed");
export const fetchScan = () => getJSON("/api/scan", "scan");
export const fetchSite = () => getJSON("/api/site", "buildings");
export const fetchSessions = () => getJSON("/api/sessions", "sessions");
export const fetchControl = () => getJSON("/api/control", "enabled");
export const fetchPlan = () => getJSON("/api/plan", "items");
export const fetchRouterAudit = () => getJSON("/api/router/audit", "adapter_used");
export const fetchAdvice = () => getJSON("/api/advice", "items");
async function postJSON(url, body, timeoutMs, key) {
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
        let v = null;
        try {
            v = await r.json();
        }
        catch { /* the body is not JSON */ }
        if (r.ok && isObject(v) && key in v)
            return { ok: true, data: v };
        const err = isObject(v) && typeof v["error"] === "string" ? v["error"] : "HTTP " + r.status;
        return { ok: false, error: err };
    }
    catch {
        return { ok: false, error: "no answer from the monitor (network error or timeout)" };
    }
    finally {
        clearTimeout(timer);
    }
}
/** Asks the monitor to close the running session and start a new one. */
export async function postSession(body) {
    const r = await postJSON("/api/control/session", body, 90000, "session");
    return r.ok ? { ok: true, session: r.data.session } : r;
}
export const postRouterProbe = (body) => postJSON("/api/router/probe", body, 25000, "adapter_used");
export const postRouterCve = (body) => postJSON("/api/router/cve", body, 25000, "items");
/** An SSE `data` payload as an envelope, or null when it is not one. */
export function parseEnvelope(data) {
    let v;
    try {
        v = JSON.parse(data);
    }
    catch {
        return null;
    }
    return isObject(v) && typeof v["type"] === "string" ? v : null;
}
