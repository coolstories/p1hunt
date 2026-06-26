import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from p1hunt.autopilot import (
    AutopilotConfig,
    candidate_sweeper_pick,
    directive_for_candidate,
    ensure_web,
    maybe_resume_hunt,
    queue_triage_if_due,
    repair_confirmed_criticals,
    run_autopilot,
    supervise_engagement,
)


class AutopilotDirectives(unittest.TestCase):
    def test_posted_critical_enters_parent_pipeline(self):
        d = directive_for_candidate({
            "title": "live critical",
            "severity": "critical",
            "pipeline": {"status": "posted", "stage": "blackboard", "updated_ts": 100},
        }, now=110, stale_s=900)
        self.assertIsNotNone(d)
        self.assertEqual(d["target_agent"], "parent_a")
        self.assertIn("verifier", d["action"])

    def test_real_not_reproduced_goes_to_poc_prover(self):
        d = directive_for_candidate({
            "title": "real lead",
            "severity": "critical",
            "pipeline": {"status": "real", "stage": "verifier", "blocked_by": "not_reproduced_yet"},
        }, now=1000)
        self.assertIsNotNone(d)
        self.assertEqual(d["target_agent"], "poc_prover")

    def test_autonomous_followup_goes_to_exploit_developer(self):
        d = directive_for_candidate({
            "title": "needs win chain",
            "severity": "critical",
            "pipeline": {"status": "autonomous_followup", "blocked_by": "attacker_win_not_yet_demonstrated"},
        }, now=1000)
        self.assertIsNotNone(d)
        self.assertEqual(d["target_agent"], "exploit_developer")

    def test_active_recent_candidate_is_not_retriaged(self):
        d = directive_for_candidate({
            "title": "currently running",
            "severity": "critical",
            "pipeline": {"status": "running", "stage": "poc_prover", "updated_ts": 900},
        }, now=1000, stale_s=300)
        self.assertIsNone(d)

    def test_confirmed_candidate_is_done(self):
        d = directive_for_candidate({
            "title": "confirmed p1",
            "severity": "critical",
            "pipeline": {"status": "confirmed_critical_reproduced", "stage": "operator_verified", "updated_ts": 1},
        }, now=1000, stale_s=300)
        self.assertIsNone(d)

    def test_candidate_sweeper_waits_until_backlog_threshold(self):
        cands = [{"title": f"c{i}", "severity": "critical", "pipeline": {"status": "posted"}} for i in range(9)]
        self.assertIsNone(candidate_sweeper_pick(cands, now=1000, stale_s=300))

    def test_candidate_sweeper_picks_highest_severity_open_candidate(self):
        cands = [
            {"title": "active critical", "severity": "critical",
             "pipeline": {"status": "running", "stage": "poc_prover", "updated_ts": 950}},
            {"title": "medium backlog", "severity": "medium",
             "pipeline": {"status": "posted", "stage": "blackboard", "updated_ts": 100}},
            {"title": "high backlog", "severity": "high",
             "pipeline": {"status": "posted", "stage": "blackboard", "updated_ts": 100}},
        ] + [
            {"title": f"low{i}", "severity": "low",
             "pipeline": {"status": "posted", "stage": "blackboard", "updated_ts": 100}}
            for i in range(7)
        ]
        picked = candidate_sweeper_pick(cands, now=1000, stale_s=300)
        self.assertIsNotNone(picked)
        cand, directive = picked
        self.assertEqual(cand["title"], "high backlog")
        self.assertEqual(directive["source_agent"], "candidate_sweeper")
        self.assertEqual(directive["target_agent"], "parent_a")

    def test_candidate_sweeper_ignores_low_priority_backlog(self):
        cands = [
            {"title": f"low{i}", "severity": "low",
             "pipeline": {"status": "posted", "stage": "blackboard", "updated_ts": 100}}
            for i in range(12)
        ]
        self.assertIsNone(candidate_sweeper_pick(cands, now=1000, stale_s=300))


class AutopilotQueue(unittest.TestCase):
    def test_queue_triage_is_cooldown_deduped(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d)
            cand = {"title": "lead", "severity": "critical", "dedup_key": "k1"}
            directive = {"target_agent": "poc_prover", "action": "build proof", "message": "move"}
            state = {}
            first = queue_triage_if_due(eng, cand, directive, state, now=1000, cooldown_s=600)
            second = queue_triage_if_due(eng, cand, directive, state, now=1100, cooldown_s=600)
            self.assertIsNotNone(first)
            self.assertIsNone(second)
            lines = (eng / "control.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertEqual(json.loads(lines[0])["target_agent"], "poc_prover")

    def test_queue_triage_preserves_source_agent(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d)
            cand = {"title": "lead", "severity": "critical", "dedup_key": "k1"}
            directive = {"target_agent": "parent_a", "action": "move", "message": "sweep",
                         "source_agent": "candidate_sweeper"}
            out = queue_triage_if_due(eng, cand, directive, {}, now=1000, cooldown_s=600)
            self.assertEqual(out["source_agent"], "candidate_sweeper")
            line = json.loads((eng / "control.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(line["source_agent"], "candidate_sweeper")

    def test_supervise_engagement_queues_live_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            (eng / "events.jsonl").write_text(json.dumps({
                "id": "1", "ts": 10.0, "agent": "child_b1", "kind": "finding_reported",
                "data": {"title": "live critical", "severity": "critical", "file": "x.py", "line": 1},
            }) + "\n", encoding="utf-8")
            cfg = AutopilotConfig(root=Path(d), supervise_web=False, resume_hunts=False)
            events = supervise_engagement(eng, cfg, {}, now=1000)
            self.assertTrue(any(e["event"] == "triage_queued" for e in events))
            self.assertIn("live critical", (eng / "control.jsonl").read_text(encoding="utf-8"))

    def test_stop_control_suppresses_candidate_triage(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            (eng / "events.jsonl").write_text(json.dumps({
                "id": "1", "ts": 10.0, "agent": "child_b1", "kind": "finding_reported",
                "data": {"title": "live critical", "severity": "critical", "file": "x.py", "line": 1},
            }) + "\n", encoding="utf-8")
            (eng / "control.jsonl").write_text(json.dumps({"kind": "stop"}) + "\n", encoding="utf-8")
            cfg = AutopilotConfig(root=Path(d), supervise_web=False, resume_hunts=False)
            events = supervise_engagement(eng, cfg, {}, now=1000)
            self.assertEqual(events, [])
            self.assertEqual(len((eng / "control.jsonl").read_text(encoding="utf-8").splitlines()), 1)

    def test_pause_control_suppresses_candidate_triage(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            (eng / "events.jsonl").write_text(json.dumps({
                "id": "1", "ts": 10.0, "agent": "child_b1", "kind": "finding_reported",
                "data": {"title": "live critical", "severity": "critical", "file": "x.py", "line": 1},
            }) + "\n", encoding="utf-8")
            (eng / "control.jsonl").write_text(json.dumps({"kind": "pause"}) + "\n", encoding="utf-8")
            cfg = AutopilotConfig(root=Path(d), supervise_web=False, resume_hunts=False)
            events = supervise_engagement(eng, cfg, {}, now=1000)
            self.assertEqual(events, [])
            self.assertEqual(len((eng / "control.jsonl").read_text(encoding="utf-8").splitlines()), 1)

    def test_repair_confirmed_criticals_from_operator_pin(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            (eng / "findings.json").write_text(json.dumps({
                "program": "P",
                "counts": {"confirmed_critical": 0, "needs_human_review": 0, "candidates": 0},
                "confirmed_criticals": [],
                "needs_human_review": [],
                "candidates": [],
            }), encoding="utf-8")
            (eng / "operator_confirmed_criticals.json").write_text(json.dumps({
                "confirmed_criticals": [{
                    "title": "Recovered joint key",
                    "severity": "critical",
                    "location": "src/key.cpp:10",
                    "root_cause": "nonce reuse",
                }],
            }), encoding="utf-8")

            out = repair_confirmed_criticals(eng)
            self.assertIsNotNone(out)
            self.assertEqual(out["event"], "confirmed_criticals_repaired")
            doc = json.loads((eng / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(doc["counts"]["confirmed_critical"], 1)
            self.assertEqual(doc["confirmed_criticals"][0]["title"], "Recovered joint key")


class AutopilotResume(unittest.TestCase):
    def test_resume_hunt_uses_saved_argv_and_adds_resume(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            ev = eng / "events.jsonl"
            ev.write_text("", encoding="utf-8")
            os.utime(ev, (1, 1))
            (eng / "state.json").write_text("{}", encoding="utf-8")
            (eng / "process.json").write_text(json.dumps({
                "kind": "hunt",
                "pid": 0,
                "argv": ["python3", "-m", "p1hunt.main", "hunt", "https://example.test", "--web", "--program", "P"],
                "cwd": d,
            }), encoding="utf-8")
            state = {}
            out = maybe_resume_hunt(eng, state, now=1000, stale_s=100, dry_run=True)
            self.assertIsNotNone(out)
            self.assertEqual(out["event"], "hunt_resumed")
            self.assertIn("--resume", out["cmd"])

    def test_latest_stop_suppresses_resume(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            ev = eng / "events.jsonl"
            ev.write_text("", encoding="utf-8")
            os.utime(ev, (1, 1))
            (eng / "state.json").write_text("{}", encoding="utf-8")
            (eng / "control.jsonl").write_text(json.dumps({"kind": "stop"}) + "\n", encoding="utf-8")
            (eng / "process.json").write_text(json.dumps({
                "kind": "hunt",
                "pid": 0,
                "argv": ["python3", "-m", "p1hunt.main", "hunt", "repo", "--program", "P"],
                "cwd": d,
            }), encoding="utf-8")
            out = maybe_resume_hunt(eng, {}, now=1000, stale_s=100, dry_run=True)
            self.assertEqual(out["event"], "resume_skipped")
            self.assertIn("stop", out["reason"])

    def test_latest_pause_suppresses_resume(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            ev = eng / "events.jsonl"
            ev.write_text("", encoding="utf-8")
            os.utime(ev, (1, 1))
            (eng / "state.json").write_text("{}", encoding="utf-8")
            (eng / "control.jsonl").write_text(json.dumps({"kind": "pause"}) + "\n", encoding="utf-8")
            (eng / "process.json").write_text(json.dumps({
                "kind": "hunt",
                "pid": 0,
                "argv": ["python3", "-m", "p1hunt.main", "hunt", "repo", "--program", "P"],
                "cwd": d,
            }), encoding="utf-8")
            out = maybe_resume_hunt(eng, {}, now=1000, stale_s=100, dry_run=True)
            self.assertEqual(out["event"], "resume_skipped")
            self.assertIn("pause", out["reason"])

    def test_run_once_writes_autopilot_state(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = AutopilotConfig(root=Path(d), once=True, dry_run=True, supervise_web=False,
                                  resume_hunts=False, engagements=["eng"])
            self.assertEqual(run_autopilot(cfg), 0)
            state = json.loads((Path(d) / "autopilot_state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["supervisor"]["engagements"], ["eng"])
            self.assertGreater(state["supervisor"]["pid"], 0)

    def test_ensure_web_passes_engagement_filter_to_dashboard(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = AutopilotConfig(root=Path(d), host="127.0.0.1", port=8787, engagements=["two", "one"])
            with mock.patch("p1hunt.autopilot._port_open", return_value=False), \
                 mock.patch("p1hunt.autopilot.subprocess.Popen") as popen:
                out = ensure_web(cfg, {}, now=1000)
            self.assertEqual(out["event"], "web_started")
            env = popen.call_args.kwargs["env"]
            self.assertEqual(env["P1HUNT_WEB_ENGAGEMENTS"], "one,two")

    def test_run_once_skips_stopped_archive_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "old"
            eng.mkdir()
            ev = eng / "events.jsonl"
            ev.write_text(json.dumps({
                "id": "1", "ts": 1.0, "agent": "child_b1", "kind": "finding_reported",
                "data": {"title": "archive critical", "severity": "critical", "file": "x.py"},
            }) + "\n", encoding="utf-8")
            os.utime(ev, (1, 1))
            cfg = AutopilotConfig(root=Path(d), once=True, dry_run=False, supervise_web=False,
                                  resume_hunts=False, hunt_stale_s=10)
            self.assertEqual(run_autopilot(cfg), 0)
            self.assertFalse((eng / "control.jsonl").exists())

    def test_include_stopped_processes_archive(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "old"
            eng.mkdir()
            ev = eng / "events.jsonl"
            ev.write_text(json.dumps({
                "id": "1", "ts": 1.0, "agent": "child_b1", "kind": "finding_reported",
                "data": {"title": "archive critical", "severity": "critical", "file": "x.py"},
            }) + "\n", encoding="utf-8")
            os.utime(ev, (1, 1))
            cfg = AutopilotConfig(root=Path(d), once=True, dry_run=False, supervise_web=False,
                                  resume_hunts=False, hunt_stale_s=10, include_stopped=True)
            self.assertEqual(run_autopilot(cfg), 0)
            self.assertIn("archive critical", (eng / "control.jsonl").read_text(encoding="utf-8"))

    def test_engagement_filter_only_processes_named_run(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("one", "two"):
                eng = Path(d) / name
                eng.mkdir()
                (eng / "events.jsonl").write_text(json.dumps({
                    "id": "1", "ts": 1.0, "agent": "child_b1", "kind": "finding_reported",
                    "data": {"title": f"{name} critical", "severity": "critical", "file": "x.py"},
                }) + "\n", encoding="utf-8")
            cfg = AutopilotConfig(root=Path(d), once=True, dry_run=False, supervise_web=False,
                                  resume_hunts=False, engagements=["two"])
            self.assertEqual(run_autopilot(cfg), 0)
            self.assertFalse((Path(d) / "one" / "control.jsonl").exists())
            self.assertIn("two critical", (Path(d) / "two" / "control.jsonl").read_text(encoding="utf-8"))

    def test_session_limit_probe_is_cadenced(self):
        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            (eng / "events.jsonl").write_text("", encoding="utf-8")
            cfg = AutopilotConfig(root=Path(d), supervise_web=False, resume_hunts=False,
                                  session_probe_s=300, dry_run=True)
            state = {}
            status = {"throttled": True, "remaining_s": 120.0, "can_jumpstart": False}
            result = {"cleared": False, "state": status}
            with mock.patch("p1hunt.autopilot.session_limit_state", return_value=status), \
                 mock.patch("p1hunt.autopilot._hunt_pid_alive", return_value=True), \
                 mock.patch("p1hunt.autopilot.jumpstart_if_clear", return_value=result) as jump:
                first = supervise_engagement(eng, cfg, state, now=1000)
                second = supervise_engagement(eng, cfg, state, now=1100)
            self.assertTrue(any(e["event"] == "session_limit_waiting" for e in first))
            self.assertFalse(any(e["event"] == "session_limit_waiting" for e in second))
            self.assertEqual(jump.call_count, 1)


if __name__ == "__main__":
    unittest.main()
