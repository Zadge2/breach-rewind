# BREACH REWIND

**Record an attack. Follow the evidence. Compare the fix.**

A local-first security evidence workspace built with Go, React / TypeScript and Python. It turns real application or Linux kernel activity into inspectable timelines, evidence graphs, behavioral comparisons, and self-contained offline reports.

No accounts. No cloud service. No LLM key. No automatic network scanning. This directory is a codebase only: Git has not been initialized and nothing has been published.

## What works

- Go CLI: `serve`, `demo`, `capture`, `record`, `import`, `list`, `inspect`, `compare`, `export`, `verify`.
- Three executable vulnerable / patched demo pairs with positive health controls.
- Native JSONL and Tracee JSON ingestion, strict validation and bounded input handling.
- Dependency-free Python SDK with request scopes and optional file/process/network audit hooks.
- SQLite evidence persistence, summary indexing, non-overwriting imports and transactional demo pairs.
- Timeline playback, kind / text / severity filters, pagination, event inspector and evidence graph.
- Normalized before / after comparison with multiplicity and compatibility warnings.
- Versioned JSON bundles with SHA-256 consistency checks and best-effort redaction.
- Offline HTML export with the actual interactive viewer and optional comparison recording.
- Browser origin / Host guards, CSP, output escaping, deadlines and process cleanup.

## Start on Windows

From this directory in PowerShell:

```powershell
# Build the executable first (the repository intentionally does not commit binaries).
.\scripts\build.ps1
.\bin\rewind.exe demo --scenario all --mode both
.\bin\rewind.exe serve
```

Open **http://127.0.0.1:9847/**. The supplied local database already contains demonstration captures; running the demo command creates fresh ones. You can also click **Record demo** in the viewer.

Python 3.11+ must be available as `python` for demos / SDK workloads. Use `--python C:\path\to\python.exe` if needed. Viewing, importing, comparing and exporting recordings do not require Python or Docker.

Alternatively, `scripts/start.ps1` starts the server and builds it if the executable is absent. If the port is occupied, choose another explicitly, such as `rewind serve --addr 127.0.0.1:9850`. No existing service is stopped automatically.

## Build from source

Requirements: **Go 1.27.1+**, Node 22.12+ (or compatible Vite-supported Node), npm, and Python 3.11+. A current C compiler is needed for Go's race detector, but not a normal pure-Go SQLite build. The Go module pins a patched minimum toolchain; older Go installations with automatic toolchain selection can download it.

```powershell
.\scripts\build.ps1
```

On Linux:

```sh
bash scripts/build.sh
./bin/rewind demo --scenario all --mode both
./bin/rewind serve
```

The build runs `npm ci`, type checking, Vite production bundling and Go vet, then embeds the frontend into the executable. **Rebuild Go after changing frontend assets.** Do not overwrite a running Windows executable; stop the instance first or use `build.ps1 -Output bin/rewind-next.exe`.

## Capture your own instrumented Python workload

```powershell
.\bin\rewind.exe capture --title "Documentation request" --timeout 30 -- python sdk/python/example.py
```

For your application, import `Recorder` from `sdk/python/breach_rewind.py`, create it inside the application, and wrap handlers with `recording.request(method, route)`. `capture` supplies `BREACH_REWIND_EVENTS` and ingests the resulting file after the command ends. It suppresses workload stdout/stderr to avoid accidental secret logging. A failed workload can still yield a valid recording; its non-successful exit is recorded in notes.

```python
with Recorder() as recording:
    recording.enable_audit()  # optional; attempts, not syscall success
    with recording.request("GET", "/documentation"):
        handle_request()
```

This is cooperative instrumentation, not a sandbox or comprehensive profiler. Audit hooks can affect application behavior when limits/errors occur. See [architecture](docs/ARCHITECTURE.md).

## Import telemetry and exchange evidence

```powershell
.\bin\rewind.exe record --format native --input events.jsonl --title "Application capture"
.\bin\rewind.exe record --format tracee --input tracee.jsonl --title "Kernel capture"
.\bin\rewind.exe list
.\bin\rewind.exe inspect --id RECORDING_ID
.\bin\rewind.exe compare --before VULNERABLE_ID --after PATCHED_ID
.\bin\rewind.exe export --id RECORDING_ID --format json --out recording.json
.\bin\rewind.exe verify --input recording.json
.\bin\rewind.exe import --input recording.json --db data/second-workspace.db
.\bin\rewind.exe export --id VULNERABLE_ID --baseline PATCHED_ID --out investigation.html
```

`record --input -` accepts a finite JSONL stream from stdin. The stream must reach EOF; use a bounded capture source. Inputs are limited to 16 MiB, 20,000 events and 128 KiB per JSONL line. Imported bundles must carry a valid digest; raw event files use `record`, not `import`. Exports refuse to overwrite existing files.

The HTML report opens directly from disk without the server or internet. Its viewer can investigate both included recordings. Network requests are blocked by CSP. Review exported content: redaction is not a guarantee against every secret format.

## Demonstrations

| Scenario | Vulnerable behavior | Patched behavior |
|---|---|---|
| Diagnostic export | Unauthenticated route starts a fixed helper, reads a decoy credential, sends it to a loopback sink | Administrator requirement denies export |
| Path traversal | Download crosses from the public fixture directory into the private fixture directory | Canonical path containment enforced |
| Stale authorization | Revoked member reads an export through a cached authorization decision | Membership rechecked at download |

The diagnostic scenario is a missing-authorization demonstration, **not arbitrary command execution**. All scenarios are restricted to disposable data. They do not scan a target, read real credentials, or contact an external sink.

Docker isolation is optional:

```powershell
docker compose build
docker compose run --rm -T vulnerable | Out-File -Encoding utf8NoBOM vulnerable.jsonl
.\bin\rewind.exe record --format native --input vulnerable.jsonl --title "Docker demo"
```

See [Linux / Tracee capture](docs/TRACEE.md) for scoped kernel recording. A real Tracee 0.24.1 capture was validated on this host's Docker / WSL2 Linux kernel; the adapter is not advertised as compatible with every Tracee release.

## Test repeatedly

```powershell
.\scripts\test.ps1 -Repeat 3
```

This builds a separate test executable; runs shuffled, repeated Go race/coverage tests, vet, Go vulnerability analysis, Python SDK tests, frontend unit tests, npm audit, and repeated Chromium end-to-end tests against a separate temporary database and port. Logs go to `artifacts/verification-*`. It stops only the test server it creates.

Additional fuzzing:

```sh
go test ./internal/evidence -run '^$' -fuzz FuzzDecode -fuzztime 30s -parallel 2
go test ./internal/collector -run '^$' -fuzz FuzzTracee -fuzztime 30s -parallel 2
```

See [verification results](docs/VERIFICATION.md) and [security model](SECURITY.md). Clean tests and scans do **not** establish zero bugs, zero vulnerabilities, complete event coverage, or a production-readiness certification.

## Development

Run the Go server at port 9847, then `npm run dev` inside `web/` for the Vite development viewer. Its local development proxy rewrites Host and removes Origin for the backend; use only on your own loopback interface. The production embedded server does not use this proxy.

Details: [architecture](docs/ARCHITECTURE.md) · [API](docs/API.md) · [schema](docs/recording.schema.json) · [security](SECURITY.md).
