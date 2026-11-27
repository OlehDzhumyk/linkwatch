// One table of thresholds for every colour the UI gives a number. The ⓘ tips describe the
// same limits, so the colour and the explanation always agree.
const valid = (v) => v !== null && v !== undefined && isFinite(v);
/** Availability: ≥ 99.9 % good, ≥ 99 % some problems, else bad. */
export function availTone(a) {
    if (!valid(a))
        return null;
    return a >= 99.9 ? "ok" : a >= 99 ? "warn" : "bad";
}
/** Drops per hour: < 0.5 good, < 2 some problems, else bad. */
export function dropsTone(d) {
    if (!valid(d))
        return null;
    return d < 0.5 ? "ok" : d < 2 ? "warn" : "bad";
}
/** Wi-Fi signal: ≥ −67 dBm good, ≥ −75 dBm usable, else weak. */
export function sigTone(dbm) {
    if (!valid(dbm))
        return null;
    return dbm >= -67 ? "ok" : dbm >= -75 ? "warn" : "bad";
}
/** Channel airtime busy: < 50 % good, < 70 % crowded, else congested. */
export function busyTone(p) {
    if (!valid(p))
        return null;
    return p < 50 ? "ok" : p < 70 ? "warn" : "bad";
}
/** Incident count of a session: none good, only micro-drops some problems, else bad. */
export function incidentsTone(network, micro) {
    return network > 0 ? "bad" : micro > 2 ? "warn" : "ok";
}
