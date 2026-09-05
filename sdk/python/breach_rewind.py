"""Small dependency-free recorder for Python 3.11+ applications.

Use Recorder.request around a request handler. Optional Python audit hooks record
attempted file opens, process creation and socket connects, not syscall outcomes.
Audit hooks are observability, not a sandbox, and can be bypassed by native code.
"""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import os
import socket
import sys
import threading
import uuid

def _bounded(value, size):
    return str(value).encode("utf-8")[:size].decode("utf-8", errors="ignore")

class Recorder:
    def __init__(self, path=None, max_events=20000):
        self.path = path or os.environ.get("BREACH_REWIND_EVENTS")
        if not self.path:
            raise ValueError("Provide an output path or BREACH_REWIND_EVENTS")
        if not 1 <= max_events <= 20000:
            raise ValueError("max_events must be between 1 and 20000")
        self.max_events = max_events
        self.count = 0
        self.bytes_written = 0
        self._lock = threading.RLock()
        self._guard = threading.local()
        self._context = ContextVar("rewind_request", default=("", ""))
        self._enabled = True
        self._hooked = False
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        self.bytes_written = os.fstat(fd).st_size
        self._stream = os.fdopen(fd, "a", encoding="utf-8", buffering=1)

    def close(self):
        with self._lock:
            self._enabled = False
            self._stream.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def emit(self, kind, summary, *, outcome="observed", severity="info", attributes=None, parent=None):
        with self._lock:
            if not self._enabled: return ""
            if self.count >= self.max_events:
                # Explicit failure prevents silently representing a truncated capture as complete.
                raise RuntimeError("BREACH REWIND event limit reached")
            self._guard.active = True
            try:
                trace, root = self._context.get()
                ident = uuid.uuid4().hex
                attrs = {_bounded(k,128): _bounded(v,4096) for k, v in (attributes or {}).items()}
                if len(attrs) > 64: raise ValueError("Too many event attributes")
                item = {"id": ident, "time": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                        "kind": kind, "summary": _bounded(summary,2048), "severity": severity, "outcome": outcome,
                        "source": "python-sdk", "pid": os.getpid(), "ppid": os.getppid(),
                        "process": "python", "host": socket.gethostname(), "trace_id": trace,
                        "parent_id": root if parent is None else parent, "attributes": attrs}
                encoded = json.dumps(item, ensure_ascii=False) + "\n"
                size = len(encoded.encode("utf-8"))
                if size > 120 * 1024 or self.bytes_written + size > 16 * 1024 * 1024:
                    raise RuntimeError("BREACH REWIND byte limit reached")
                self._stream.write(encoded)
                self.bytes_written += size
                self.count += 1
                return ident
            finally:
                self._guard.active = False

    @contextmanager
    def request(self, method, route):
        token = self._context.set((uuid.uuid4().hex, ""))
        try:
            root = self.emit("request", f"{method} {route}", outcome="attempted", attributes={"method": method, "route": route})
            self._context.set((self._context.get()[0], root))
            try:
                yield root
            except BaseException:
                self.emit("response", "Request handler failed", outcome="failed", attributes={"method": method, "route": route})
                raise
            else:
                self.emit("response", "Request handler completed", outcome="success", attributes={"method": method, "route": route})
        finally:
            self._context.reset(token)

    def enable_audit(self):
        if self._hooked: return
        self._hooked = True
        def audit(name, args):
            if not self._enabled or getattr(self._guard, "active", False) or not self._context.get()[0]: return
            if name == "open":
                self.emit("file", "Python attempted to open a file", outcome="attempted", attributes={"path": args[0], "operation": "open"})
            elif name == "subprocess.Popen":
                # Never record environment variables, stdin or the full command line.
                self.emit("process", "Python attempted to start a subprocess", outcome="attempted", attributes={"operation": "spawn", "executable": args[0]})
            elif name == "socket.connect":
                self.emit("network", "Python attempted a socket connection", outcome="attempted", attributes={"operation": "connect", "destination": args[1]})
        sys.addaudithook(audit)
