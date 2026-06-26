import json
import tempfile
import unittest
from pathlib import Path

from p1hunt.orchestrator.event_log import EventLog


class EventLogRedirectTests(unittest.TestCase):
    def test_redirect_preserves_existing_log_and_appends_new_events(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events.jsonl"
            path.write_text(json.dumps({
                "id": "old",
                "ts": 1,
                "agent": "parent_a",
                "kind": "message",
                "data": {"phase": "old"},
            }) + "\n", encoding="utf-8")

            log = EventLog()
            log.emit("operator", "message", {"phase": "new"})
            log.redirect(path)

            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows[0]["id"], "old")
            self.assertEqual(rows[1]["agent"], "operator")
            self.assertEqual(rows[1]["data"]["phase"], "new")

    def test_redirect_twice_to_same_path_does_not_duplicate_flushed_events(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events.jsonl"
            log = EventLog()
            log.emit("a", "message", {"n": 1})
            log.redirect(path)
            log.redirect(path)

            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["data"]["n"], 1)


if __name__ == "__main__":
    unittest.main()
