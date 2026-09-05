# Scoped Linux kernel recording

The adapter was tested against **Tracee 0.24.1** JSON output on Docker Desktop's Linux / WSL2 kernel `6.6.87.2-microsoft-standard-WSL2`. An actual scoped capture yielded 645 events: 637 `openat`, 6 `connect`, and 2 `sched_process_exec`. All imported successfully; unknown additional metadata fields from Tracee are ignored, while supported fields are validated.

This is kernel telemetry, separate from the application-instrumented demo trace. Request-level causal links are **not** inferred merely by joining their timestamps.

## Important boundaries

- Tracee needs privileged Linux access. The workbench itself does not.
- Always restrict capture to an explicitly owned test container. Never leave host-wide capture running on a shared workstation.
- The target container must already be running when an ID-based scope is initialized; a merely created container has no populated cgroup yet.
- Do not enable environment / file-content capture unless you deliberately want to handle that sensitive data.
- Raw output precedes BREACH REWIND redaction. Protect it and review before sharing.

## Reproduce from Windows PowerShell

```powershell
.\scripts\tracee-smoke.ps1
```

This creates uniquely named, disposable containers and cleans up only those containers. The fixture has no external network, runs as an unprivileged user, and has a read-only root filesystem. Tracee is privileged and scoped to that fixture. The script writes raw JSONL under `artifacts/kernel-*` and imports the capture into a separate evidence database in that directory.

## Existing Linux test workload

Use an already-running container's full ID in a Tracee invocation, following the [Tracee scope documentation](https://aquasecurity.github.io/tracee/dev/docs/flags/scope.1/) and the [0.24 output flags](https://aquasecurity.github.io/tracee/v0.24/docs/flags/output.1/):

```sh
# Replace OWNED_RUNNING_CONTAINER_ID with the exact test container ID.
docker run --rm --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$PWD/capture:/evidence" \
  aquasec/tracee:0.24.1 \
  --scope container=OWNED_RUNNING_CONTAINER_ID \
  --events sched_process_exec,openat,connect \
  --output json:/evidence/tracee.jsonl
```

Create `capture/` first. In another terminal execute only the intended test workload. Stop Tracee cleanly, then import its finite output:

```sh
./bin/rewind record --format tracee --input capture/tracee.jsonl --title "Scoped kernel recording"
```

The supported dialect uses `timestamp` (epoch nanoseconds or decimal epoch seconds), `eventName`, `processId`, `parentProcessId`, `processName`, `hostName`, `containerId`, `returnValue`, and `args` entries with `name` / `value`. Timestamps preserve nanosecond precision. Events without instrumentation-level linkage receive only inferred process associations. Events default to informational severity; this adapter is not an automatic vulnerability detector.

## Diagnosing failures

- **Container ID not found:** start the fixture before launching Tracee; confirm you selected the intended Docker engine.
- **Missing os-release bind:** mount `/etc/os-release` at `/etc/os-release-host:ro` as shown.
- **BPF initialization failures:** check kernel BTF / eBPF support, capabilities, cgroup compatibility and Tracee's own logs. Do not disable host security controls automatically.
- **Import parse errors:** keep diagnostics out of the JSONL stream; use an event output file. The 0.24 adapter is intentionally not a promise of support for every newer dialect.
- **Large capture:** scope and bound it upstream. The importer refuses oversized / malformed input instead of silently truncating.
