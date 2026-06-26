import datetime as dt
import json
import os
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from p1hunt import session_limit


class SessionLimitState(unittest.TestCase):
    def test_parse_utc_reset_notice(self):
        ref = dt.datetime(2026, 6, 25, 12, 22, 0, tzinfo=dt.timezone.utc).timestamp()
        out = session_limit.parse_reset_epoch("You've hit your session limit · resets 12:30pm (UTC)", reference_ts=ref)
        parsed = dt.datetime.fromtimestamp(out, dt.timezone.utc)
        self.assertEqual(parsed.hour, 12)
        self.assertEqual(parsed.minute, 30)

    def test_event_reset_keeps_gate_closed_until_reset_time(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            eng = root / "eng"
            eng.mkdir()
            ref = dt.datetime(2026, 6, 25, 12, 22, 0, tzinfo=dt.timezone.utc).timestamp()
            throttle = root / "throttle.json"
            throttle.write_text(json.dumps({
                "throttled": True,
                "seconds": 30,
                "strikes": 4,
                "reason": "exhausted all models",
                "at": ref - 100,
            }), encoding="utf-8")
            (eng / "events.jsonl").write_text(json.dumps({
                "ts": ref,
                "agent": "exploit_dev",
                "kind": "output",
                "data": {"text": "You've hit your session limit · resets 12:30pm (UTC)"},
            }) + "\n", encoding="utf-8")

            before = session_limit.session_limit_state(eng, throttle_file=throttle, now=ref)
            self.assertTrue(before["throttled"])
            self.assertFalse(before["can_jumpstart"])
            self.assertEqual(before["remaining_s"], 480.0)

            blocked = session_limit.jumpstart_if_clear(eng, throttle_file=throttle, now=ref)
            self.assertFalse(blocked["cleared"])
            self.assertTrue(json.loads(throttle.read_text(encoding="utf-8"))["throttled"])

            after_reset = ref + 9 * 60
            cleared = session_limit.jumpstart_if_clear(eng, throttle_file=throttle, now=after_reset)
            self.assertTrue(cleared["cleared"])
            self.assertFalse(json.loads(throttle.read_text(encoding="utf-8"))["throttled"])
            self.assertTrue(json.loads(throttle.read_text(encoding="utf-8"))["manual"])

    def test_force_jumpstart_clears_even_before_reset(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            eng = root / "eng"
            eng.mkdir()
            ref = dt.datetime(2026, 6, 25, 12, 22, 0, tzinfo=dt.timezone.utc).timestamp()
            throttle = root / "throttle.json"
            throttle.write_text(json.dumps({
                "throttled": True,
                "seconds": 900,
                "strikes": 4,
                "reason": "exhausted all models",
                "at": ref,
            }), encoding="utf-8")

            cleared = session_limit.jumpstart_if_clear(eng, throttle_file=throttle, now=ref + 10, force=True)
            self.assertTrue(cleared["cleared"])
            self.assertTrue(cleared["forced"])
            doc = json.loads(throttle.read_text(encoding="utf-8"))
            self.assertFalse(doc["throttled"])
            self.assertTrue(doc["manual"])


class SessionLimitWebEndpoint(unittest.TestCase):
    def test_web_check_endpoint_jumpstarts_when_clear(self):
        from p1hunt.web.server import _Handler

        with tempfile.TemporaryDirectory() as d:
            old_root = os.environ.get("P1HUNT_ENGAGEMENTS")
            old_filter = os.environ.get("P1HUNT_WEB_ENGAGEMENTS")
            old_throttle = session_limit.THROTTLE_FILE
            os.environ["P1HUNT_ENGAGEMENTS"] = d
            os.environ["P1HUNT_WEB_ENGAGEMENTS"] = "eng"
            session_limit.THROTTLE_FILE = Path(d) / "throttle.json"
            session_limit.THROTTLE_FILE.write_text(json.dumps({
                "throttled": True,
                "seconds": 1,
                "strikes": 1,
                "reason": "exhausted all models",
                "at": 1000,
            }), encoding="utf-8")
            srv = None
            try:
                eng = Path(d) / "eng"
                eng.mkdir()
                (eng / "events.jsonl").write_text("", encoding="utf-8")
                srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
                thread = threading.Thread(target=srv.serve_forever, daemon=True)
                thread.start()
                port = srv.server_address[1]
                body = json.dumps({"eng": "eng"}).encode("utf-8")
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/session-limit-check",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                out = json.loads(urllib.request.urlopen(req, timeout=5).read().decode("utf-8"))
                self.assertTrue(out["ok"])
                self.assertTrue(out["cleared"])
                doc = json.loads(session_limit.THROTTLE_FILE.read_text(encoding="utf-8"))
                self.assertFalse(doc["throttled"])
                self.assertTrue(doc["manual"])
            finally:
                try:
                    if srv is not None:
                        srv.shutdown()
                        srv.server_close()
                except Exception:
                    pass
                session_limit.THROTTLE_FILE = old_throttle
                if old_root is None:
                    os.environ.pop("P1HUNT_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_ENGAGEMENTS"] = old_root
                if old_filter is None:
                    os.environ.pop("P1HUNT_WEB_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_WEB_ENGAGEMENTS"] = old_filter


if __name__ == "__main__":
    unittest.main()
