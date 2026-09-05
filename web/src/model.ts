export type Kind =
  "request" | "response" | "process" | "file" | "network" | "policy" | "other";
export interface Event {
  id: string;
  time: string;
  kind: Kind;
  summary: string;
  severity: string;
  outcome: string;
  source: string;
  pid?: number;
  ppid?: number;
  process?: string;
  host?: string;
  container?: string;
  trace_id?: string;
  parent_id?: string;
  attributes: Record<string, string>;
}
export interface Bundle {
  schema: string;
  id: string;
  title: string;
  created: string;
  scenario: string;
  mode: string;
  collector: string;
  notes: string[];
  events: Event[];
  digest: string;
}
export interface Summary {
  id: string;
  title: string;
  created: string;
  scenario: string;
  mode: string;
  collector: string;
  events: number;
  high: number;
  digest: string;
}
export interface Edge {
  from: string;
  to: string;
  confidence: string;
  reason: string;
}
export interface Change {
  signature: string;
  kind: string;
  summary: string;
  before: number;
  after: number;
  delta: number;
  severity: string;
}
export interface Comparison {
  before: string;
  after: string;
  changes: Change[];
  removed: number;
  added: number;
  unchanged: number;
  compatible: boolean;
  notes: string[];
}
export const kinds: Kind[] = [
  "request",
  "process",
  "file",
  "network",
  "policy",
  "response",
  "other",
];
export const rank = (s: string) =>
  ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 })[s] ?? 0;
export const labels: Record<string, string> = {
  "diagnostic-export": "Diagnostic export",
  "path-traversal": "Path traversal",
  "stale-authorization": "Stale authorization",
};
export const title = (s: string) => labels[s] ?? s;
export const summary = (b: Bundle): Summary => ({
  ...b,
  events: b.events.length,
  high: b.events.filter((e) => rank(e.severity) >= 3 && e.outcome !== "blocked")
    .length,
});
export function graph(b: Bundle): Edge[] {
  const edges: Edge[] = [];
  const last = new Map<string, string>();
  for (const e of b.events) {
    const key = `${e.host ?? ""}|${e.container ?? ""}|${e.pid ?? 0}`;
    if (e.parent_id)
      edges.push({
        from: e.parent_id,
        to: e.id,
        confidence: "observed",
        reason: "Explicit event linkage reported by collector",
      });
    else if (e.pid && last.has(key))
      edges.push({
        from: last.get(key)!,
        to: e.id,
        confidence: "inferred",
        reason:
          "Same process identifier; temporal association, not proof of causality",
      });
    if (e.pid) last.set(key, e.id);
  }
  return edges;
}
export function signature(e: Event) {
  return [
    e.kind,
    e.outcome,
    e.process ?? "",
    ...[
      "action",
      "method",
      "route",
      "path",
      "destination",
      "operation",
      "rule",
    ].map((k) => `${k}=${e.attributes[k] ?? ""}`),
  ].join("\x1f");
}
export function compare(a: Bundle, b: Bundle): Comparison {
  const changes = new Map<string, Change>();
  for (const [i, bundle] of [a, b].entries()) {
    for (const e of bundle.events) {
      const key = signature(e);
      const c = changes.get(key) ?? {
        signature: key,
        kind: e.kind,
        summary: e.summary,
        before: 0,
        after: 0,
        delta: 0,
        severity: e.severity,
      };
      if (rank(e.severity) > rank(c.severity)) c.severity = e.severity;
      if (i === 0) c.before++;
      else c.after++;
      changes.set(key, c);
    }
  }
  const result: Comparison = {
    before: a.id,
    after: b.id,
    changes: [],
    removed: 0,
    added: 0,
    unchanged: 0,
    compatible: a.scenario === b.scenario && a.collector === b.collector,
    notes: [
      "A behavior difference is not proof of a complete fix. Check workload and telemetry coverage.",
    ],
  };
  for (const c of changes.values()) {
    c.delta = c.after - c.before;
    result.removed += Math.max(0, -c.delta);
    result.added += Math.max(0, c.delta);
    result.unchanged += Math.min(c.before, c.after);
    result.changes.push(c);
  }
  result.changes.sort(
    (a, b) =>
      rank(b.severity) - rank(a.severity) ||
      (a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0),
  );
  return result;
}
export function filterEvents(
  events: Event[],
  query: string,
  kind: string,
  onlyFindings: boolean,
) {
  const q = query.toLowerCase();
  return events.filter(
    (e) =>
      (kind === "all" || e.kind === kind) &&
      (!onlyFindings || rank(e.severity) >= 3) &&
      (!q ||
        [e.summary, e.kind, e.process, ...Object.values(e.attributes)]
          .join(" ")
          .toLowerCase()
          .includes(q)),
  );
}
export function relative(e: Event, b: Bundle) {
  return Math.max(
    0,
    (Date.parse(e.time) - Date.parse(b.events[0]?.time ?? e.time)) / 1000,
  );
}
export const seconds = (n: number) => `${n.toFixed(3)}s`;
