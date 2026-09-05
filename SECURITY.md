# Security model

## Intended use

A single-user, local-first investigation tool for authorized test environments. Importing evidence never executes it. The server binds only to `127.0.0.1`, validates the exact Host, rejects foreign / opaque origins and cross-site fetches, requires a custom API header, and provides no CORS permissions.

There is **no claim of zero vulnerabilities**. Repeated tests and clean dependency scans reduce risk; they cannot establish universal correctness. Independent review is recommended before operational deployment.

## Trust boundaries

- Treat imported recordings, descriptions, attributes and collector results as untrusted data. JSON nesting / size limits, structural validation, checksum checks and React text escaping apply.
- A digest is not a signature. An attacker can fabricate or reseal a bundle. Neither explicit links nor severity labels authenticate a collector or establish actual exploitability.
- Do not run the service on a shared/untrusted host, forward its port, add a permissive proxy, or expose it to a LAN. Other local users/processes can use the API. The custom client header is not a bearer credential.
- Python and Tracee capture metadata may contain secrets. Raw JSONL is not redacted until ingestion. Normalized storage and exports apply best-effort redaction of sensitive attribute keys, common tokens, assignment patterns and home paths. Unknown / encoded / split secrets can remain. Review before sharing.
- Evidence is not encrypted at rest. Protect the workspace and backups with OS access controls and disk encryption as appropriate. No automatic uploads occur.
- Bundled demos deliberately contain application-policy flaws in vulnerable mode. They are temporary fixtures, not production application code. They use only synthetic data and loopback endpoints. Docker Compose adds a read-only filesystem, no external network, dropped capabilities, and resource limits.
- Arbitrary CLI capture commands are explicitly operator-selected and are **not sandboxed**. Lifecycle cleanup is not a defense against hostile executables. Tracee itself requires privileged Linux access; restrict its scope to the test workload.

## Reporting

Until this project is published, report findings privately to the project owner through the same channel used to obtain the codebase. Include affected version, a minimal local reproduction, expected / observed behavior, and impact. Do not attach live secrets. Configure a private reporting channel before public release.

## Maintenance

Run `scripts/test.ps1`, `npm audit`, and `govulncheck` after changes. Keep the Go toolchain, Node build environment, Python, container base images and Tracee patched. Rebuild the embedded viewer and the executable together. Review updated dependencies rather than blindly applying fixes. The Tracee adapter's tested input dialect is 0.24.1 JSON; upstream formats may change.
