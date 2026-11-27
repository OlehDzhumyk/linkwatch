// Shared UI state. One mutable object; modules read it and re-render their part.
/** Value of the session selector for the running session. */
export const LIVE = "__live__";
export const THEMES = ["auto", "dark", "light"];
export const TABS = ["now", "sessions", "map", "diag"];
export const EVENT_FILTERS = ["important", "outages", "wifi", "observer", "security", "all"];
export const SCAN_FILTERS = ["all", "ours", "interfering", "2.4", "5"];
/** Whether `v` is one of `list` (for values read from data-* attributes and storage). */
export function oneOf(list, v) {
    return v !== null && v !== undefined && list.includes(v);
}
export const COLOR_MODES = ["status", "availability", "drops"];
export const ADJ_FLOORS = ["off", "below", "above"];
/**
 * Page-wide notifications between modules that must not import each other.
 * "session-change": the running session is another one (switch or restart).
 * "switch-tab": CustomEvent<Tab> asks main.ts to open another view.
 * "events-change": state.events was replaced from /api/events.
 * "focus-time": CustomEvent<string> highlights an incident timestamp on the timeline.
 * "focus-point": CustomEvent<string> jumps to a point on the floor plan.
 * "session-selected": user switched between Live and a historical session.
 * "brush-change": timeline brush zoom range changed (filter incidents list).
 */
export const bus = new EventTarget();
export const state = {
    status: null,
    selectedSession: LIVE,
    hours: 24,
    rangeUserSet: false,
    minutes: {},
    liveMinutes: {},
    lanSeries: [],
    liveRing: new Map(),
    lastUpdateMs: 0,
    events: [],
    evFilter: "important",
    showAll: false,
    speed: [],
    scan: {},
    scanFilter: "all",
    site: null,
    sessions: [],
    sessionsLoaded: false,
    building: null,
    unit: null,
    selected: null,
    live: false,
    theme: "auto",
    control: null,
    plan: null,
    colorMode: "status",
    adjFloor: "off",
    tab: "now",
    openCardDetails: new Set(),
    report: null,
    liveReport: null,
    compareSel: [],
    compareTol: 2,
    compare: null,
    highlightTs: null,
    brushRange: null,
    tlInspected: false,
    audit: null,
    advice: null,
    cve: null,
};
