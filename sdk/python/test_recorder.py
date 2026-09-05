import json
from pathlib import Path
import tempfile
import unittest
from breach_rewind import Recorder

class RecorderTests(unittest.TestCase):
    def test_request_and_audit(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/"events.jsonl"
            with Recorder(out) as r:
                r.enable_audit()
                with r.request("GET","/file"):
                    (Path(d)/"fixture").write_text("hello")
            events=[json.loads(s) for s in out.read_text().splitlines()]
            self.assertEqual([e["kind"] for e in events],["request","file","response"])
            self.assertEqual(events[1]["parent_id"],events[0]["id"])
            self.assertEqual(events[1]["outcome"],"attempted")
    def test_failure_and_context_reset(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/"events.jsonl"
            with Recorder(out) as r:
                with self.assertRaises(ValueError):
                    with r.request("GET","/failure"): raise ValueError("test")
                r.emit("other","outside request")
            events=[json.loads(s) for s in out.read_text().splitlines()]
            self.assertEqual(events[1]["outcome"],"failed")
            self.assertEqual(events[2]["trace_id"],"")
    def test_limit_is_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            with Recorder(Path(d)/"events",max_events=1) as r:
                r.emit("other","one")
                with self.assertRaises(RuntimeError): r.emit("other","two")
    def test_audit_disabled_after_close(self):
        with tempfile.TemporaryDirectory() as d:
            with Recorder(Path(d)/"events") as r: r.enable_audit()
            (Path(d)/"outside").write_text("no capture")
            self.assertEqual((Path(d)/"events").read_text(),"")

if __name__=="__main__": unittest.main()
