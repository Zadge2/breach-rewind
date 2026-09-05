# Local API

Default URL: `http://127.0.0.1:9847`. Every API request requires `X-Rewind-Client: 1`. POST bodies require `Content-Type: application/json` exactly. Do not expose this service through a reverse proxy or tunnel.

| Method | Path | Result |
|---|---|---|
| GET | `/api/health` | Version and readiness |
| GET | `/api/recordings` | Latest 500 summaries |
| GET | `/api/recordings/{id}` | Checksum-verified bundle |
| GET | `/api/recordings/{id}/graph` | Explicit / inferred edges |
| GET | `/api/recordings/{id}/report?baseline={optional-id}` | Downloadable offline HTML |
| GET | `/api/compare?before={id}&after={id}` | Normalized multiset diff |
| POST | `/api/import` | Verify, redact, seal, store a bundle; returns its ID |
| POST | `/api/demo` | Run bundled scenarios; returns recording IDs |

Demo body:

```json
{"scenario":"diagnostic-export","mode":"both"}
```

Scenarios: `diagnostic-export`, `path-traversal`, `stale-authorization`.
Modes: `both`, `vulnerable`, `patched`.

Errors are JSON with an `error` field. Statuses include 400 (invalid evidence / parameters), 403 (host, origin or client-header rejection), 404 (missing recording), 409 (duplicate ID / demo already running), 415 (wrong content type), and 500 (local execution or storage failure). Demo requests have a 45-second context deadline; imports have a 16 MiB limit. There is no CORS opt-in, remote authentication, arbitrary command endpoint, or server-side URL fetching.

The custom header is a browser cross-origin barrier, **not an authentication secret**. Local users and local processes are trusted. Read the threat model before using sensitive evidence on a shared workstation.
