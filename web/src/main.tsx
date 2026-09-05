import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowDownToLine,
  ArrowLeftRight,
  ArrowRight,
  Check,
  ChevronRight,
  Code2,
  Database,
  FileText,
  GitBranch,
  Globe,
  HardDrive,
  Import,
  Layers,
  LoaderCircle,
  LockKeyhole,
  Pause,
  Play,
  Radio,
  RotateCcw,
  Search,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  X,
} from "lucide-react";
import * as api from "./api";
import {
  compare,
  filterEvents,
  graph,
  kinds,
  rank,
  relative,
  seconds,
  title,
  type Bundle,
  type Event,
  type Kind,
  type Summary,
} from "./model";
import "./style.css";

const icons: Record<Kind, typeof Activity> = {
  request: Globe,
  response: ArrowRight,
  process: Terminal,
  file: FileText,
  network: Radio,
  policy: ShieldCheck,
  other: Activity,
};
function KindIcon({ kind, size = 17 }: { kind: Kind; size?: number }) {
  const Icon = icons[kind] ?? Activity;
  return <Icon size={size} />;
}
function App() {
  const [recordings, setRecordings] = useState<Summary[]>([]),
    [selected, setSelected] = useState(""),
    [bundle, setBundle] = useState<Bundle | null>(null),
    [selectedEvent, setSelectedEvent] = useState("");
  const [view, setView] = useState<"timeline" | "graph" | "compare">(
      "timeline",
    ),
    [query, setQuery] = useState(""),
    [kind, setKind] = useState("all"),
    [findings, setFindings] = useState(false),
    [cursor, setCursor] = useState(0),
    [playing, setPlaying] = useState(false),
    [page, setPage] = useState(0);
  const [baseline, setBaseline] = useState(""),
    [base, setBase] = useState<Bundle | null>(null),
    [loading, setLoading] = useState(true),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [showDemo, setShowDemo] = useState(false),
    [scenario, setScenario] = useState("diagnostic-export");
  const input = useRef<HTMLInputElement>(null);
  const refresh = async (id?: string) => {
    const values = await api.list();
    setRecordings(values);
    setSelected(
      (old) =>
        id ?? (values.some((v) => v.id === old) ? old : (values[0]?.id ?? "")),
    );
    return values;
  };
  useEffect(() => {
    refresh()
      .catch((e) => setError(String(e.message)))
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    if (!selected) {
      setBundle(null);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setBundle(null);
    api
      .get(selected, controller.signal)
      .then((b) => {
        if (controller.signal.aborted) return;
        setBundle(b);
        setCursor(b.events.length);
        setSelectedEvent(
          b.events.find((e) => rank(e.severity) >= 3)?.id ??
            b.events[0]?.id ??
            "",
        );
        setPlaying(false);
        setPage(0);
        setQuery("");
        setKind("all");
        setFindings(false);
        setBaseline(
          recordings.find(
            (r) =>
              r.id !== b.id && r.scenario === b.scenario && r.mode !== b.mode,
          )?.id ?? "",
        );
      })
      .catch((e) => {
        if (e.name !== "AbortError") setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [selected]);
  useEffect(() => {
    setBase(null);
    if (!baseline) return;
    const controller = new AbortController();
    api
      .get(baseline, controller.signal)
      .then((b) => {
        if (!controller.signal.aborted) setBase(b);
      })
      .catch((e) => {
        if (e.name !== "AbortError") setError(e.message);
      });
    return () => controller.abort();
  }, [baseline]);
  useEffect(() => {
    if (!playing || !bundle) return;
    const timer = setInterval(
      () =>
        setCursor((c) => {
          if (c >= bundle.events.length) {
            setPlaying(false);
            return c;
          }
          return c + 1;
        }),
      500,
    );
    return () => clearInterval(timer);
  }, [playing, bundle]);
  useEffect(() => {
    setPage(0);
  }, [query, kind, findings, cursor]);
  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(""), 6000);
    return () => clearTimeout(t);
  }, [notice]);
  const events = useMemo(
    () =>
      filterEvents(
        bundle?.events.slice(0, cursor) ?? [],
        query,
        kind,
        findings,
      ),
    [bundle, cursor, query, kind, findings],
  );
  const focused = bundle?.events.find((e) => e.id === selectedEvent);
  const edges = useMemo(() => (bundle ? graph(bundle) : []), [bundle]);
  const delta = useMemo(
    () => (bundle && base ? compare(bundle, base) : null),
    [bundle, base],
  );
  const duration = bundle?.events.length
    ? relative(bundle.events.at(-1)!, bundle)
    : 0;
  const dangerous =
    bundle?.events.filter(
      (e) => rank(e.severity) >= 3 && e.outcome !== "blocked",
    ).length ?? 0;
  const blocked =
    bundle?.events.filter((e) => e.kind === "policy" && e.outcome === "blocked")
      .length ?? 0;
  async function runDemo() {
    setBusy(true);
    setError("");
    try {
      const result = await api.request<{ ids: string[] }>("/api/demo", {
        method: "POST",
        body: JSON.stringify({ scenario, mode: "both" }),
      });
      await refresh(result.ids[0]);
      setShowDemo(false);
      setNotice(
        "Vulnerable and patched executions recorded. Both positive controls passed.",
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function importFile(file: File) {
    setBusy(true);
    setError("");
    try {
      if (file.size > 16 * 1024 * 1024)
        throw new Error("Recording exceeds the 16 MiB limit.");
      const result = await api.request<{ id: string }>("/api/import", {
        method: "POST",
        body: await file.text(),
      });
      await refresh(result.id);
      setNotice("Checksum verified. Recording redacted and imported.");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  }
  async function exportReport() {
    if (!bundle) return;
    setError("");
    try {
      await api.report(bundle.id, view === "compare" ? baseline : "");
      setNotice("Offline report exported. Review the evidence before sharing.");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  function jsonDownload() {
    if (bundle)
      api.download(
        new Blob([JSON.stringify(bundle, null, 2)], {
          type: "application/json",
        }),
        `${bundle.id}.json`,
      );
  }
  function togglePlay() {
    if (!bundle) return;
    if (cursor >= bundle.events.length) setCursor(0);
    setPlaying((v) => !v);
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a
          href="#"
          className="brand"
          onClick={(e) => {
            e.preventDefault();
            setView("timeline");
          }}
          aria-label="Breach Rewind home"
        >
          <span className="brand-mark">
            <RotateCcw size={24} />
          </span>
          <span>
            BREACH<span className="brand-sub">REWIND</span>
          </span>
          <span className="version">1.0</span>
        </a>
        <div className="workspace-label">
          <span className="live-dot" />
          {api.offline ? "OFFLINE EVIDENCE" : "LOCAL WORKSPACE"}
          <LockKeyhole size={12} />
        </div>
        <div className="side-heading">INVESTIGATE</div>
        <button
          className={`nav-item ${view !== "compare" ? "active" : ""}`}
          onClick={() => setView("timeline")}
        >
          <Layers size={18} />
          Recordings<span className="count">{recordings.length}</span>
        </button>
        <button
          className={`nav-item ${view === "compare" ? "active" : ""}`}
          onClick={() => setView("compare")}
        >
          <ArrowLeftRight size={18} />
          Compare runs
        </button>
        <div className="side-heading recording-heading">
          CAPTURE LIBRARY <span>{recordings.length}/500</span>
        </div>
        <div className="recording-list">
          {recordings.map((r) => (
            <button
              key={r.id}
              className={`recording ${selected === r.id ? "selected" : ""}`}
              onClick={() => setSelected(r.id)}
            >
              <span
                className={`recording-dot ${r.mode === "patched" ? "green" : ""}`}
              />
              <span className="recording-copy">
                <strong>{r.scenario ? title(r.scenario) : r.title}</strong>
                <span>
                  {r.events} events <span className="separator">/</span>{" "}
                  {r.mode || r.collector}
                </span>
              </span>
              {selected === r.id && <ChevronRight size={14} />}
            </button>
          ))}
          {!recordings.length && (
            <p className="side-empty">
              No recordings yet.
              <br />
              Run a demo or import evidence.
            </p>
          )}
        </div>
        <div className="sidebar-bottom">
          <div>
            <HardDrive size={16} />
            <span>
              {api.offline
                ? "Self-contained report"
                : "Evidence stays on this device"}
            </span>
          </div>
          <small>No accounts. No cloud. No telemetry.</small>
          <a
            href="https://github.com/aquasecurity/tracee"
            target="_blank"
            rel="noreferrer"
          >
            Tracee-compatible JSONL <ArrowRight size={12} />
          </a>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <ChevronRight size={13} />
            <strong>
              {view === "compare" ? "Run comparison" : "Capture analysis"}
            </strong>
          </div>
          <span className="local-badge">
            <span className="live-dot" />
            {api.offline ? "Offline report" : "Loopback only"}
          </span>
        </header>
        <div className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">FOLLOW THE EVIDENCE</div>
              <h1>
                Every action leaves a trace<span>.</span>
              </h1>
              <p>
                Reconstruct the attack. Inspect the evidence. Verify what
                changed.
              </p>
            </div>
            <div className="heading-actions">
              {!api.offline && (
                <>
                  <input
                    ref={input}
                    type="file"
                    accept=".json,application/json"
                    hidden
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) void importFile(f);
                    }}
                  />
                  <button
                    className="button secondary"
                    onClick={() => input.current?.click()}
                    disabled={busy}
                  >
                    <Import size={16} />
                    Import
                  </button>
                  <button
                    className="button primary"
                    onClick={() => setShowDemo(true)}
                    disabled={busy}
                  >
                    <Radio size={16} />
                    Record demo
                  </button>
                </>
              )}
            </div>
          </div>
          {error && (
            <div role="alert" className="alert error">
              <TriangleAlert size={18} />
              <span>{error}</span>
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {notice && (
            <div role="status" className="alert success">
              <Check size={18} />
              <span>{notice}</span>
              <button aria-label="Dismiss notice" onClick={() => setNotice("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {loading && (
            <div className="loading">
              <LoaderCircle className="spin" />
              Reading verified evidence…
            </div>
          )}
          {!loading && !bundle && (
            <section className="empty-state">
              <span className="empty-icon">
                <GitBranch size={40} />
              </span>
              <h2>Your first investigation starts here.</h2>
              <p>
                Record a real vulnerable / patched demonstration, or import a
                checksum-verified recording. No kernel privileges are needed for
                the built-in demos.
              </p>
              {!api.offline && (
                <button
                  className="button primary"
                  onClick={() => setShowDemo(true)}
                >
                  <Play size={16} />
                  Run your first capture
                </button>
              )}
              <div className="empty-steps">
                <span>
                  01 <b>Record</b>
                </span>
                <ArrowRight />
                <span>
                  02 <b>Investigate</b>
                </span>
                <ArrowRight />
                <span>
                  03 <b>Compare</b>
                </span>
              </div>
            </section>
          )}
          {bundle && (
            <>
              <section className="capture-card">
                <div className="capture-title">
                  <div className="capture-icon">
                    <Terminal size={22} />
                  </div>
                  <div>
                    <div className="capture-name">
                      <h2>
                        {bundle.scenario
                          ? title(bundle.scenario)
                          : bundle.title}
                      </h2>
                      <span
                        className={`mode-badge ${bundle.mode === "patched" ? "patched" : ""}`}
                      >
                        {bundle.mode || "imported"}
                      </span>
                    </div>
                    <div className="capture-meta">
                      <span>{bundle.collector}</span>
                      <span>•</span>
                      <time>{new Date(bundle.created).toLocaleString()}</time>
                      <span>•</span>
                      <code>{bundle.id.slice(0, 8)}</code>
                    </div>
                  </div>
                  <div className="capture-export">
                    {!api.offline && (
                      <button
                        className="button secondary small"
                        onClick={exportReport}
                      >
                        <ArrowDownToLine size={15} />
                        Export report
                      </button>
                    )}
                    <button
                      className="icon-button"
                      title="Download evidence JSON"
                      aria-label="Download evidence JSON"
                      onClick={jsonDownload}
                    >
                      <Code2 size={18} />
                    </button>
                  </div>
                </div>
                <div className="metrics">
                  <Metric
                    label="CAPTURED EVENTS"
                    value={bundle.events.length}
                    icon={<Activity />}
                  />
                  <Metric
                    label="HIGH-RISK EVENTS"
                    value={dangerous}
                    accent={dangerous > 0 ? "danger" : ""}
                    icon={<TriangleAlert />}
                  />
                  <Metric
                    label="POLICY BLOCKS"
                    value={blocked}
                    accent={blocked > 0 ? "positive" : ""}
                    icon={<ShieldCheck />}
                  />
                  <Metric
                    label="CAPTURE SPAN"
                    value={seconds(duration)}
                    icon={<Radio />}
                  />
                </div>
              </section>
              <div className="analysis-toolbar">
                <div
                  className="tabs"
                  role="tablist"
                  aria-label="Evidence views"
                >
                  {(
                    [
                      ["timeline", "Event timeline", Activity],
                      ["graph", "Evidence graph", GitBranch],
                      ["compare", "Before / after", ArrowLeftRight],
                    ] as const
                  ).map(([key, label, Icon]) => (
                    <button
                      key={key}
                      role="tab"
                      aria-selected={view === key}
                      className={view === key ? "current" : ""}
                      onClick={() => setView(key)}
                    >
                      <Icon size={16} />
                      {label}
                    </button>
                  ))}
                </div>
                <span className="integrity">
                  <ShieldCheck size={14} />
                  {api.offline
                    ? "Export-time checksum recorded"
                    : "SHA-256 verified on load"}
                </span>
              </div>
              {view === "compare" ? (
                <section className="comparison">
                  <div className="compare-controls">
                    <div>
                      <span className="field-label">
                        BEFORE · CURRENT RECORDING
                      </span>
                      <strong>
                        {title(bundle.scenario) || bundle.title}{" "}
                        <span className="muted">
                          / {bundle.mode || bundle.id.slice(0, 8)}
                        </span>
                      </strong>
                    </div>
                    <ArrowRight />
                    <label>
                      <span className="field-label">
                        AFTER · COMPARE AGAINST
                      </span>
                      <select
                        aria-label="Comparison recording"
                        value={baseline}
                        onChange={(e) => setBaseline(e.target.value)}
                      >
                        <option value="">Choose a recording</option>
                        {recordings
                          .filter((r) => r.id !== bundle.id)
                          .map((r) => (
                            <option key={r.id} value={r.id}>
                              {title(r.scenario) || r.title} /{" "}
                              {r.mode || r.id.slice(0, 8)} · {r.id.slice(0, 6)}
                            </option>
                          ))}
                      </select>
                    </label>
                  </div>
                  {delta ? (
                    <>
                      <div className="diff-metrics">
                        <div className="positive">
                          <b>−{delta.removed}</b>
                          <span>Events removed</span>
                        </div>
                        <div className="danger">
                          <b>+{delta.added}</b>
                          <span>Events added</span>
                        </div>
                        <div>
                          <b>{delta.unchanged}</b>
                          <span>Events retained</span>
                        </div>
                      </div>
                      {!delta.compatible && (
                        <div className="alert warning">
                          <TriangleAlert size={17} />
                          Different scenarios or collectors: results are not
                          like-for-like.
                        </div>
                      )}
                      <p className="comparison-note">
                        Normalized by operation, resource, process name and
                        outcome. PIDs, timestamps and trace IDs are excluded.
                        This is a behavioral diff, not a security verdict.
                      </p>
                      <div className="diff-table">
                        <div className="diff-row table-heading">
                          <span>BEHAVIOR</span>
                          <span>BEFORE</span>
                          <span>AFTER</span>
                          <span>CHANGE</span>
                        </div>
                        {delta.changes.map((c) => (
                          <div className="diff-row" key={c.signature}>
                            <span>
                              <span className={`kind-dot ${c.kind}`} />
                              <span>
                                <strong>{c.summary}</strong>
                                <small>
                                  {c.kind} · {c.severity}
                                </small>
                              </span>
                            </span>
                            <code>{c.before}</code>
                            <code>{c.after}</code>
                            <span
                              className={`delta ${c.delta < 0 ? "positive" : c.delta > 0 ? "danger" : ""}`}
                            >
                              {c.delta > 0 ? "+" : ""}
                              {c.delta === 0 ? "—" : c.delta}
                            </span>
                          </div>
                        ))}
                      </div>
                      <div className="note">
                        <ShieldCheck size={17} />
                        <span>
                          Retained health checks show the demo application still
                          responds. That does not prove all legitimate workflows
                          survived the fix.
                        </span>
                      </div>
                    </>
                  ) : (
                    <div className="empty-inline">
                      Select a second recording to inspect changes. Run a demo
                      to capture both versions.
                    </div>
                  )}
                </section>
              ) : (
                <>
                  <section className="playback">
                    <button
                      className="play-button"
                      onClick={togglePlay}
                      aria-label={playing ? "Pause playback" : "Play recording"}
                    >
                      {playing ? <Pause size={17} /> : <Play size={17} />}
                    </button>
                    <button
                      className="icon-button"
                      aria-label="Reset playback"
                      onClick={() => {
                        setPlaying(false);
                        setCursor(0);
                      }}
                    >
                      <RotateCcw size={15} />
                    </button>
                    <div className="scrubber">
                      <div>
                        <span>RECORDING PLAYBACK</span>
                        <code>
                          {cursor} / {bundle.events.length} events
                        </code>
                      </div>
                      <input
                        type="range"
                        aria-label="Playback position"
                        min={0}
                        max={bundle.events.length}
                        value={cursor}
                        onChange={(e) => {
                          setPlaying(false);
                          setCursor(Number(e.target.value));
                        }}
                      />
                    </div>
                    <code className="playback-time">
                      {seconds(
                        cursor
                          ? relative(bundle.events[cursor - 1], bundle)
                          : 0,
                      )}
                    </code>
                    <span className="playback-hint">
                      Evidence playback
                      <br />
                      not system replay
                    </span>
                  </section>
                  <div className="investigation-grid">
                    <section className="events-panel">
                      <div className="event-filters">
                        <label className="search-field">
                          <Search size={16} />
                          <input
                            placeholder="Search events, paths, operations…"
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                            aria-label="Search events"
                          />
                        </label>
                        <button
                          className={`filter-button ${findings ? "enabled" : ""}`}
                          onClick={() => setFindings(!findings)}
                          aria-pressed={findings}
                        >
                          <TriangleAlert size={14} />
                          High risk
                        </button>
                      </div>
                      <div className="kind-filters">
                        <button
                          className={kind === "all" ? "chosen" : ""}
                          onClick={() => setKind("all")}
                        >
                          All events
                        </button>
                        {kinds
                          .filter((k) =>
                            bundle.events.some((e) => e.kind === k),
                          )
                          .map((k) => (
                            <button
                              key={k}
                              className={kind === k ? "chosen" : ""}
                              onClick={() => setKind(k)}
                            >
                              <span className={`kind-dot ${k}`} />
                              {k}
                            </button>
                          ))}
                      </div>
                      {view === "timeline" ? (
                        <>
                          <div className="timeline-header">
                            <span>OFFSET / TYPE</span>
                            <span>OBSERVED ACTIVITY</span>
                            <span>OUTCOME</span>
                          </div>
                          <div
                            className="timeline"
                            role="list"
                            aria-label="Recorded events"
                          >
                            {events
                              .slice(page * 150, (page + 1) * 150)
                              .map((e) => (
                                <button
                                  role="listitem"
                                  key={e.id}
                                  className={`event-row ${selectedEvent === e.id ? "focused" : ""}`}
                                  onClick={() => setSelectedEvent(e.id)}
                                >
                                  <span className="event-time">
                                    <code>+{seconds(relative(e, bundle))}</code>
                                    <span className={`event-symbol ${e.kind}`}>
                                      <KindIcon kind={e.kind} />
                                    </span>
                                  </span>
                                  <span className="event-description">
                                    <strong>{e.summary}</strong>
                                    <span>
                                      {e.process || e.source}{" "}
                                      {e.pid ? `· PID ${e.pid}` : ""}{" "}
                                      <span className="event-severity">
                                        {rank(e.severity) >= 3
                                          ? `/ ${e.severity}`
                                          : ""}
                                      </span>
                                    </span>
                                  </span>
                                  <span
                                    className={`outcome ${e.outcome === "blocked" ? "blocked" : rank(e.severity) >= 3 ? "risk" : ""}`}
                                  >
                                    {e.outcome}
                                  </span>
                                </button>
                              ))}
                          </div>
                          {!events.length && (
                            <div className="empty-inline">
                              No events match this view. Adjust the filters or
                              advance playback.
                            </div>
                          )}
                          <div className="timeline-footer">
                            <span>
                              {events.length} matching events ·{" "}
                              {Math.min((page + 1) * 150, events.length)} shown
                            </span>
                            {events.length > 150 && (
                              <div>
                                <button
                                  disabled={page === 0}
                                  onClick={() => setPage((p) => p - 1)}
                                >
                                  Previous
                                </button>
                                <button
                                  disabled={(page + 1) * 150 >= events.length}
                                  onClick={() => setPage((p) => p + 1)}
                                >
                                  Next
                                </button>
                              </div>
                            )}
                            <span>
                              <span className="live-dot" />
                              Read-only evidence
                            </span>
                          </div>
                        </>
                      ) : (
                        <EvidenceGraph
                          events={events}
                          edges={edges}
                          selected={selectedEvent}
                          select={setSelectedEvent}
                        />
                      )}
                    </section>
                    <aside className="inspector">
                      <div className="inspector-heading">
                        <span>
                          <Search size={15} />
                          EVIDENCE INSPECTOR
                        </span>
                        <span className="inspector-number">
                          {focused
                            ? String(
                                bundle.events.indexOf(focused) + 1,
                              ).padStart(2, "0")
                            : "—"}
                        </span>
                      </div>
                      {focused ? (
                        <>
                          <div className={`inspector-type ${focused.kind}`}>
                            <KindIcon kind={focused.kind} />
                            {focused.kind}
                            <span
                              className={`severity severity-${focused.severity}`}
                            >
                              {focused.severity}
                            </span>
                          </div>
                          <h3>{focused.summary}</h3>
                          <dl className="facts">
                            <dt>Timestamp</dt>
                            <dd>{focused.time}</dd>
                            <dt>Source</dt>
                            <dd>{focused.source}</dd>
                            <dt>Process</dt>
                            <dd>
                              {focused.process || "Not captured"}{" "}
                              {focused.pid ? `(${focused.pid})` : ""}
                            </dd>
                            <dt>Parent PID</dt>
                            <dd>{focused.ppid || "Not captured"}</dd>
                            <dt>Outcome</dt>
                            <dd>{focused.outcome}</dd>
                            <dt>Trace ID</dt>
                            <dd>{focused.trace_id || "Not captured"}</dd>
                          </dl>
                          <div className="section-label">
                            CAPTURED ATTRIBUTES
                          </div>
                          <div className="attributes">
                            {Object.entries(focused.attributes).map(
                              ([k, v]) => (
                                <div key={k}>
                                  <span>{k}</span>
                                  <code>{v}</code>
                                </div>
                              ),
                            )}
                          </div>
                          <div className="section-label">EVIDENCE LINK</div>
                          <div className="link-explanation">
                            <GitBranch size={16} />
                            <span>
                              {focused.parent_id
                                ? "Collector-reported link to the preceding operation. Not independently authenticated."
                                : edges.some((e) => e.to === focused.id)
                                  ? "Inferred from process identity and ordering. Causality is not established."
                                  : "No preceding relationship captured."}
                            </span>
                          </div>
                          <button
                            className="button secondary full small"
                            onClick={() => {
                              api.download(
                                new Blob([JSON.stringify(focused, null, 2)], {
                                  type: "application/json",
                                }),
                                `event-${focused.id}.json`,
                              );
                              setNotice(
                                "Event fragment exported. Use the full recording for checksum verification.",
                              );
                            }}
                          >
                            <ArrowDownToLine size={14} />
                            Export event fragment
                          </button>
                        </>
                      ) : (
                        <div className="empty-inline">
                          Select an event to inspect its evidence.
                        </div>
                      )}
                    </aside>
                  </div>
                </>
              )}
              <details className="capture-notes">
                <summary>
                  <FileText size={15} />
                  Capture notes & limitations <span>{bundle.notes.length}</span>
                </summary>
                <ul>
                  {bundle.notes.map((note, i) => (
                    <li key={i}>{note}</li>
                  ))}
                </ul>
                <div className="digest">
                  <b>SHA-256</b>
                  <code>{bundle.digest}</code>
                </div>
                <p>
                  A checksum detects content changes; it does not authenticate
                  the collector. Redaction is best-effort. Review all evidence
                  before sharing.
                </p>
              </details>
            </>
          )}
          <footer className="footer">
            <span>
              <Database size={13} />
              BREACH REWIND <span className="muted">/</span> Evidence, not
              assumptions.
            </span>
            <span>LOCAL-FIRST · VERSION 1.0.0</span>
          </footer>
        </div>
      </main>
      {showDemo && (
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget && !busy) setShowDemo(false);
          }}
        >
          <DemoDialog
            busy={busy}
            scenario={scenario}
            setScenario={setScenario}
            close={() => setShowDemo(false)}
            run={runDemo}
          />
        </div>
      )}
    </div>
  );
}

function Metric({
  label,
  value,
  icon,
  accent = "",
}: {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="metric">
      <div>
        <span>{label}</span>
        {icon}
      </div>
      <strong className={accent}>{value}</strong>
    </div>
  );
}
function DemoDialog({
  busy,
  scenario,
  setScenario,
  close,
  run,
}: {
  busy: boolean;
  scenario: string;
  setScenario: (s: string) => void;
  close: () => void;
  run: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
    return () => ref.current?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className="demo-modal"
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) close();
      }}
    >
      <div className="modal-title">
        <span className="eyebrow">CONTROLLED DEMONSTRATION</span>
        <button
          className="icon-button"
          aria-label="Close demo dialog"
          onClick={close}
          disabled={busy}
        >
          <X size={19} />
        </button>
      </div>
      <h2>Record both sides of the fix.</h2>
      <p>
        Real requests and operations. Disposable data. Two recordings you can
        compare immediately.
      </p>
      <label className="field-label" htmlFor="scenario">
        CHOOSE A SCENARIO
      </label>
      <select
        id="scenario"
        value={scenario}
        disabled={busy}
        onChange={(e) => setScenario(e.target.value)}
      >
        <option value="diagnostic-export">
          Diagnostic export — request → process → file → network
        </option>
        <option value="path-traversal">
          Path traversal — public / private directory boundary
        </option>
        <option value="stale-authorization">
          Stale authorization — access after membership revocation
        </option>
      </select>
      <div className="demo-safety">
        <ShieldCheck size={21} />
        <div>
          <strong>Confined to synthetic fixtures</strong>
          <span>
            Python 3.11+ · Loopback-only services · No real credentials ·
            Automatic cleanup
          </span>
        </div>
      </div>
      <div className="demo-pair">
        <span className="mode-badge">Vulnerable</span>
        <ArrowRight size={18} />
        <span className="mode-badge patched">Patched</span>
        <span>+ positive health controls</span>
      </div>
      <button className="button primary full" onClick={run} disabled={busy}>
        {busy ? (
          <LoaderCircle className="spin" size={18} />
        ) : (
          <Radio size={18} />
        )}{" "}
        {busy
          ? "Executing and recording both runs…"
          : "Run & record both versions"}
      </button>
      <small className="modal-footnote">
        No imported code is executed. This runs only the bundled demonstration.
      </small>
    </dialog>
  );
}
function EvidenceGraph({
  events,
  edges,
  selected,
  select,
}: {
  events: Event[];
  edges: ReturnType<typeof graph>;
  selected: string;
  select: (id: string) => void;
}) {
  const visible = events.slice(0, 60),
    positions = new Map(
      visible.map((e, i) => [
        e.id,
        { x: 24 + (i % 3) * 245, y: 28 + Math.floor(i / 3) * 106 },
      ]),
    );
  return (
    <div className="graph-panel">
      <div className="graph-legend">
        <span>
          <i />
          Collector-reported link
        </span>
        <span>
          <i className="dashed" />
          Inferred association
        </span>
      </div>
      <div className="graph-scroll">
        <svg
          viewBox={`0 0 760 ${Math.max(240, Math.ceil(visible.length / 3) * 106 + 30)}`}
          role="img"
          aria-label="Event evidence graph"
        >
          <defs>
            <marker
              id="arrow"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#63736a" />
            </marker>
          </defs>
          {edges
            .filter((e) => positions.has(e.from) && positions.has(e.to))
            .map((e) => {
              const a = positions.get(e.from)!,
                b = positions.get(e.to)!;
              return (
                <path
                  key={e.from + e.to}
                  className={`graph-edge ${e.confidence}`}
                  d={`M ${a.x + 105} ${a.y + 62} C ${a.x + 105} ${a.y + 85}, ${b.x + 105} ${b.y - 20}, ${b.x + 105} ${b.y}`}
                  markerEnd="url(#arrow)"
                >
                  <title>{e.reason}</title>
                </path>
              );
            })}
          {visible.map((e) => {
            const p = positions.get(e.id)!;
            return (
              <g
                key={e.id}
                role="button"
                tabIndex={0}
                aria-label={`Inspect ${e.summary}`}
                onClick={() => select(e.id)}
                onKeyDown={(key) => {
                  if (key.key === "Enter" || key.key === " ") {
                    key.preventDefault();
                    select(e.id);
                  }
                }}
                className={`graph-node ${e.id === selected ? "graph-selected" : ""}`}
                transform={`translate(${p.x},${p.y})`}
              >
                <rect width="214" height="64" rx="7" />
                <circle cx="14" cy="17" r="3" className={`fill-${e.kind}`} />
                <text x="24" y="21" className="graph-kind">
                  {e.kind.toUpperCase()} · {e.outcome}
                </text>
                <text x="12" y="44">
                  {e.summary.length > 27
                    ? e.summary.slice(0, 26) + "…"
                    : e.summary}
                </text>
                <title>{e.summary}</title>
              </g>
            );
          })}
        </svg>
      </div>
      {events.length > 60 && (
        <div className="note">
          Graph shows the first 60 matching events. Narrow your filters to
          inspect later activity.
        </div>
      )}
      <div className="timeline-footer">
        Links describe captured evidence. They do not prove whole-system
        causality.
      </div>
    </div>
  );
}

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <div className="fatal">
        <TriangleAlert />
        <h1>The viewer could not render this recording.</h1>
        <p>
          Reload the workspace. If the problem persists, verify the source
          bundle with the CLI.
        </p>
        <button onClick={() => location.reload()}>Reload</button>
      </div>
    ) : (
      this.props.children
    );
  }
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
);
