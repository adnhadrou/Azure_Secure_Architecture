"""Check evidence selection against mixed synthetic log records, offline."""
import contextlib
import io
import json
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import patch

COLLECTOR = Path(__file__).resolve().parents[1] / "scripts/purple/purple-events.py"
RUN = "abcdef123456"
START = "2026-09-27T18:00:00.1234567Z"

def collect(source, records, run=RUN):
    lines = "\n".join(json.dumps(record) for record in records) + "\ninvalid-json\n"
    output = io.StringIO()
    with patch.object(sys, "argv", [str(COLLECTOR), run, START, source]), \
         patch.object(Path, "open", return_value=io.StringIO(lines)), \
         contextlib.redirect_stdout(output):
        runpy.run_path(str(COLLECTOR), run_name="__main__")
    return json.loads(output.getvalue())

def probe(stamp, run=RUN, sid=1000003, action="allowed"):
    return {"timestamp": stamp, "alert": {"signature_id": sid, "action": action},
            "http": {"url": "/pfa-purple-probe?run=" + run}}

class EvidenceSelectionTests(unittest.TestCase):
    def test_excludes_old_other_run_and_other_signature(self):
        records = [probe("2026-09-27T17:59:59+0000"),
                   probe("2026-09-27T18:01:00+0000", "000000000000"),
                   probe("2026-09-27T18:01:00+0000", sid=1000002),
                   probe("2026-09-27T18:01:00+0000", action="blocked")]
        result = collect("suricata", records)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["action"], "blocked")

    def test_wazuh_classifies_events_and_separates_admin_action(self):
        stamp = "2026-09-27T18:01:00.000+0000"
        records = [
            {"timestamp": stamp, "syscheck": {"path": "/tmp/purple-" + RUN}, "rule": {"id": "550"}},
            {"timestamp": stamp, "full_log": "Invalid user pt-" + RUN, "rule": {"id": "5710"}},
            {"timestamp": stamp, "full_log": "sudo pfa-app denial", "rule": {"id": "100121"}},
            {"timestamp": stamp, "full_log": "sudo pfa-app controller action", "rule": {"id": "5402"}},
            {"timestamp": stamp, "data": probe(stamp, action="blocked"), "rule": {"id": "100110"}},
        ]
        kinds = [e["kind"] for e in collect("wazuh", records)["events"]]
        self.assertEqual(kinds, ["file_integrity", "invalid_ssh_user", "privilege_boundary", "controller_admin_action", "web_probe"])

    def test_handles_offset_time_and_drops_raw_sensitive_fields(self):
        item = probe("2026-09-27T20:01:00+0200")
        item.update(src_ip="198.51.100.1", full_log="not for export", password="synthetic-fixture")
        result = collect("suricata", [item])
        self.assertEqual(len(result["events"]), 1)
        event = result["events"][0]
        self.assertNotIn("src_ip", event)
        self.assertNotIn("full_log", event)
        self.assertNotIn("password", event)

    def test_rejects_path_like_run_identifier(self):
        with self.assertRaises(AssertionError):
            collect("suricata", [], run="../../etc/passwd")

if __name__ == "__main__":
    unittest.main()
