# Verification record

The repository was validated locally on 2026-09-05 from Windows 11 / Docker Desktop WSL2 (Linux kernel `6.6.87.2-microsoft-standard-WSL2`). This is a test record, not a security certification.

## Completed gates

- Go production build with embedded Vite viewer.
- `go vet ./...`.
- Go unit/integration tests, shuffled and race-enabled, repeated three times by `scripts/test.ps1`.
- Go fuzzing: `FuzzDecode` and `FuzzTracee`, 15 seconds each, two workers; both passed.
- `govulncheck` with Go 1.27.1: no reachable vulnerabilities reported.
- Python SDK `unittest`: 4 tests passed.
- Vite / TypeScript production build.
- Vitest: 8 evidence-model tests passed.
- `npm audit --audit-level=low`: no vulnerabilities reported.
- Chromium Playwright investigation workflow: 9 passes (three browser scenarios repeated three times), including playback, filters, graph, comparison, offline report, mobile layout, API origin checks and import errors.
- Docker Compose vulnerable/patched fixture image builds.
- Scoped Tracee 0.24.1 Docker / WSL2 smoke capture: 645 kernel events collected and imported (637 `openat`, 6 `connect`, 2 `sched_process_exec`).
- Linux amd64 cross-build and non-root/no-network container demo execution.

## Scope and remaining limitations

The complete verification script passed before a final small Go comparison-signature serialization tweak; targeted Go tests passed after subsequent hardening changes. The entire suite should be rerun after future changes.

Tests do not prove absence of vulnerabilities, complete kernel / application telemetry, deterministic whole-system replay, or production readiness. The Python audit hook is cooperative and can miss native operations. Process cleanup is not hostile-code containment. Redaction is best-effort. The local API is intentionally single-user and has no authentication.

Run the repeatable gates with:

```powershell
.\scripts\test.ps1 -Repeat 3
```

Do not run arbitrary workloads outside a disposable container or VM. Protect raw captures and exported reports as sensitive data.
