# Architecture

BREACH REWIND is a local evidence workbench, not an autonomous pentester, EDR, sandbox, or deterministic system-replay engine.

## Data flow

1. A bundled demo, instrumented application, or operator-managed Tracee process emits events.
2. `collector.Read` accepts native / Tracee JSONL with input, line, field, nesting, and event-count limits. Malformed input aborts the recording; it is not silently skipped.
3. Events are normalized to schema 1.0. Redaction runs **before** sealing and storage.
4. SHA-256 covers Go's deterministic JSON encoding of the typed bundle with `digest` set to the empty string. This is a content-consistency check, not a signature or RFC 8785 implementation.
5. SQLite stores the complete document plus a small summary in one transaction. Duplicate recording IDs cannot overwrite evidence. Schema 2 maintains a summary index and migrates schema-1 recordings one at a time.
6. The Go API serves an embedded React viewer on IPv4 loopback. Reading a recording revalidates its digest.
7. HTML export embeds one or two redacted bundles, the production JavaScript, and CSS. There are no runtime CDN dependencies. A restrictive CSP permits only the hashed script and blocks networking.

## Event relationships

- **Observed / collector-reported:** the producer explicitly supplies `parent_id`. This describes a claimed operation relationship, not independent proof of causation or authenticity.
- **Inferred:** consecutive events share host, container, and PID. This is association only. PID reuse, concurrent requests, dropped events, and process lifetime ambiguity can make it misleading.
- No request-to-kernel link is fabricated by matching timestamps. Native and kernel captures remain separate unless the operator explicitly supplies instrumentation-level linkage.
- Graph display is limited to 60 filtered events; timeline pages contain up to 150. A recording is limited to 20,000 events / 16 MiB.

## Comparison semantics

The engine compares multisets, not sets. A signature contains kind, outcome, process name, and the attributes `action`, `method`, `route`, `path`, `destination`, `operation`, `rule`. PIDs, timestamps, IDs and unrelated attributes do not affect the signature. Thus repeated operations affect counts, while PID churn does not.

This intentionally does not compare every attribute. Use the event inspector and JSON export for full evidence. Review workload equivalence and capture completeness. An absent event is not proof of prevention; health controls are not exhaustive functional tests. Different scenarios / collectors receive a compatibility warning.

## Execution boundaries

- UI execution is restricted to a compiled allowlist of three bundled demos and two modes. No imported document or arbitrary command is executed through the API.
- CLI `capture -- ...` explicitly executes the operator's command without a shell. It is **not sandboxed**. Use Docker / a disposable VM for untrusted workloads.
- The Python SDK uses context variables for request linkage. Optional audit hooks report attempts. They do not observe every native operation, establish syscall success, or automatically propagate context to new processes.
- Process cleanup uses Windows job objects or Unix process groups. Job assignment has a start-to-attach interval; Unix workloads can deliberately detach. These are cleanup measures, not containment of hostile code.
- Raw SDK / Tracee logs exist before ingestion and may contain sensitive metadata. Protect them separately. Cooperative per-recorder limits do not prevent several processes from filling a shared raw log.

## Layout

| Directory | Purpose |
|---|---|
| `cmd/rewind` | CLI |
| `internal/evidence` | Validation, redaction, checksums, graph and comparison |
| `internal/collector` | Native / Tracee ingestion and explicit command capture |
| `internal/storage` | SQLite document store and summary index |
| `internal/process` | Trusted workload lifecycle management |
| `internal/demo` | Embedded Python demonstrations and orchestration |
| `internal/server` | Loopback API, embedded viewer, offline export |
| `web/src` | React / TypeScript viewer and pure evidence utilities |
| `sdk/python` | Dependency-free instrumentation helper |
| `scripts` | Build and repeated test automation |

## Resource and platform scope

The library lists the most recent 500 recordings. Older recordings remain accessible through the CLI by ID; there is no deletion or automatic retention. Monitor disk use. Run the service as an ordinary user. On Unix, new evidence directories / files request modes 0700 / 0600. On Windows, inherited ACLs determine access; protect the workspace with your user profile ACLs. Existing file permissions are not silently rewritten.

Windows and Linux execution are supported and tested. macOS is source-buildable but not validated in this delivery. Kernel tracing requires compatible Linux capabilities and kernel features; the viewer, imported recordings and application instrumentation do not.
