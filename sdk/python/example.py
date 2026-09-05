"""Capture this safe workload with rewind capture -- python sdk/python/example.py."""
from breach_rewind import Recorder
from pathlib import Path
import tempfile

with tempfile.TemporaryDirectory(prefix="rewind-sdk-fixture-") as directory:
    fixture = Path(directory) / "hello.txt"
    fixture.write_text("Synthetic documentation", encoding="utf-8")
    with Recorder() as recording:
        recording.enable_audit()
        with recording.request("GET", "/documentation"):
            assert fixture.read_text(encoding="utf-8") == "Synthetic documentation"
