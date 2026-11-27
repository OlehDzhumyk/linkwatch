// Shared UI state. One mutable object; modules read it and re-render their part.

import type { AdviceResponse } from "./api/AdviceResponse.js";
import type { CompareReport } from "./api/CompareReport.js";
import type { ControlResponse } from "./api/ControlResponse.js";
import type { CveLookupResponse } from "./api/CveLookupResponse.js";
import type { Envelope } from "./api/Envelope.js";
import type { LanPoint } from "./api/LanPoint.js";
import type { PlanResponse } from "./api/PlanResponse.js";
import type { MinuteBucket } from "./api/MinuteBucket.js";
import type { PathState } from "./api/PathState.js";
import type { ReportResponse } from "./api/ReportResponse.js";
import type { RouterAudit } from "./api/RouterAudit.js";
import type { ScanEntry } from "./api/ScanEntry.js";
import type { SessionEntry } from "./api/SessionEntry.js";
import type { SiteResponse } from "./api/SiteResponse.js";
import type { SpeedRow } from "./api/SpeedRow.js";
import type { StatusResponse } from "./api/StatusResponse.js";

/** Value of the session selector for the running session. */
export const LIVE = "__live__";

export const THEMES = ["auto", "dark", "light"] as const;
export type Theme = (typeof THEMES)[number];

export const TABS = ["now", "sessions", "map", "diag"] as const;
export type Tab = (typeof TABS)[number];

export const EVENT_FILTERS = ["important", "outages", "wifi", "observer", "security", "all"] as const;
export type EventFilter = (typeof EVENT_FILTERS)[number];

export const SCAN_FILTERS = ["all", "ours", "interfering", "2.4", "5"] as const;
export type ScanFilter = (typeof SCAN_FILTERS)[number];

/** Whether `v` is one of `list` (for values read from data-* attributes and storage). */
export function oneOf<T extends string>(list: readonly T[], v: string | null | undefined): v is T {
  return v !== null && v !== undefined && (list as readonly string[]).includes(v);
}

/** One second of an interface for the sparkline. */
export interface LivePoint {
  gw: number | null;
  net: number | null;
  state: PathState;
}

export interface State {
  status: StatusResponse | null;
  /** Session id, or LIVE. */
  selectedSession: string;
  hours: number;
  rangeUserSet: boolean;
  minutes: { [iface: string]: MinuteBucket[] };
  liveMinutes: { [iface: string]: MinuteBucket[] };
  lanSeries: LanPoint[];
  liveRing: Map<string, LivePoint[]>;
  lastUpdateMs: number;
  events: Envelope[];
  evFilter: EventFilter;
  showAll: boolean;
  speed: SpeedRow[];
  scan: { [iface: string]: ScanEntry };
  scanFilter: ScanFilter;
  site: SiteResponse | null;
  sessions: SessionEntry[];
  sessionsLoaded: boolean;
  building: string | null;
  /** Full id of the flat drawn in detail (`B1/F2`). */
  unit: string | null;
  selected: string | null;
  live: boolean;
  theme: Theme;
  control: ControlResponse | null;
  plan: PlanResponse | null;
  /** What the room colours on the map show. */
  colorMode: ColorMode;
  adjFloor: AdjFloor;
  tab: Tab;
  openCardDetails: Set<string>;
  report: ReportResponse | null;
  /** Report of the running session (Now view), independent of the Sessions selection. */
  liveReport: ReportResponse | null;
  /** Sessions ticked for comparison (ids, order of ticking). */
  compareSel: string[];
  compareTol: number;
  compare: CompareReport | null;
  highlightTs: number | null;
  brushRange: readonly [number, number] | null;
  tlInspected: boolean;
  audit: RouterAudit | null;
  advice: AdviceResponse | null;
  cve: CveLookupResponse | null;
}

export const COLOR_MODES = ["status", "availability", "drops"] as const;
export type ColorMode = (typeof COLOR_MODES)[number];

export const ADJ_FLOORS = ["off", "below", "above"] as const;
export type AdjFloor = (typeof ADJ_FLOORS)[number];

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

export const state: State = {
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
