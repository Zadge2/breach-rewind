import { describe, it, expect } from "vitest";
import {
  compare,
  filterEvents,
  graph,
  signature,
  type Bundle,
  type Event,
} from "./model";
const event: Event = {
  id: "one",
  time: "2026-09-05T12:00:00Z",
  kind: "file",
  summary: "Sensitive file access",
  severity: "high",
  outcome: "success",
  source: "test",
  process: "python",
  pid: 1,
  attributes: { path: "/fixture/key", operation: "read" },
};
const bundle = (events: Event[]): Bundle => ({
  schema: "1.0",
  id: "record",
  title: "Test",
  created: event.time,
  scenario: "test",
  mode: "vulnerable",
  collector: "native",
  events,
  notes: [],
  digest: "a".repeat(64),
});
describe("evidence semantics", () => {
  it("filters case-insensitively across evidence attributes", () => {
    expect(filterEvents([event], "FIXTURE", "all", false)).toHaveLength(1);
    expect(filterEvents([event], "absent", "all", false)).toHaveLength(0);
  });
  it("combines kind and severity filters", () => {
    expect(filterEvents([event], "", "network", true)).toHaveLength(0);
    expect(
      filterEvents([{ ...event, severity: "info" }], "", "all", true),
    ).toHaveLength(0);
  });
  it("normalizes volatile identity without hiding behavior changes", () => {
    expect(signature(event)).toBe(
      signature({
        ...event,
        id: "other",
        pid: 345,
        time: "2026-09-05T13:00:00Z",
      }),
    );
    expect(signature(event)).not.toBe(
      signature({ ...event, outcome: "blocked" }),
    );
  });
  it("counts multiset differences rather than set differences", () => {
    const c = compare(
      bundle([event, { ...event, id: "two" }]),
      bundle([event]),
    );
    expect(c.removed).toBe(1);
    expect(c.unchanged).toBe(1);
    expect(c.added).toBe(0);
  });
  it("separates explicit and inferred edges", () => {
    const g = graph(
      bundle([
        event,
        { ...event, id: "two", parent_id: "one" },
        { ...event, id: "three" },
      ]),
    );
    expect(g.map((e) => e.confidence)).toEqual(["observed", "inferred"]);
  });
  it("does not associate processes across hosts", () => {
    expect(
      graph(bundle([event, { ...event, id: "two", host: "different" }])),
    ).toHaveLength(0);
  });
  it("flags incomparable collectors", () => {
    const a = bundle([event]);
    expect(compare(a, { ...a, collector: "tracee" }).compatible).toBe(false);
  });
  it("keeps XSS-like evidence as ordinary strings", () => {
    const e = { ...event, summary: "<img src=x onerror=alert(1)>" };
    expect(filterEvents([e], "onerror", "all", false)[0].summary).toBe(
      e.summary,
    );
  });
});
