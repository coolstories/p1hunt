import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest import mock

from p1hunt.agents.claude_session import ClaudeFinding
from p1hunt.agents.claude_swarm import ClaudeSwarm
from p1hunt.config import Config
from p1hunt.models import Asset, Scope
from p1hunt.orchestrator.blackboard import Blackboard
from p1hunt.orchestrator.bus import MessageBus
from p1hunt.orchestrator.event_log import EventLog


def _swarm(tmp: str) -> ClaudeSwarm:
    root = Path(tmp)
    repo = root / "repo"
    repo.mkdir()
    (repo / "target.py").write_text("def vulnerable():\n    return True\n", encoding="utf-8")
    eng = root / "eng"
    log = EventLog()
    log.redirect(eng / "events.jsonl")
    bus = MessageBus(log)
    bb = Blackboard(log)
    scope = Scope(
        program="Unit Program",
        in_scope=[Asset(id="a", label="repo", kind="repo", value=str(repo), environment="local")],
        severity_taxonomy={"Critical": "key or rogue signature", "High": "lesser key/signature path"},
        scope_note="Bugcrowd VRT plus engagement-specific reward table.",
    )
    return ClaudeSwarm(scope, str(repo), config=Config(), bus=bus, blackboard=bb, event_log=log)


class LiveFindingPersistenceTests(unittest.TestCase):
    def test_finding_reported_writes_live_ledger_snapshot_and_pack(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            s._emit("child_b1", "finding_reported", {
                "title": "Unauthenticated SSRF",
                "severity": "high",
                "file": "target.py",
                "line": 1,
                "root_cause": "domain_url is fetched server-side",
                "counterfactual": "attacker reaches internal metadata",
                "remediation": "validate and proxy through an allowlist",
            })
            eng = Path(d) / "eng"
            live = json.loads((eng / "live_findings.json").read_text(encoding="utf-8"))
            snap = json.loads((eng / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(live["counts"]["candidates"], 1)
            self.assertEqual(snap["counts"]["candidates"], 1)
            self.assertEqual(live["candidates"][0]["pipeline"]["status"], "posted")
            self.assertEqual(live["candidates"][0]["pipeline"]["blocked_by"], "awaiting_parent_pipeline")
            key = live["candidates"][0]["dedup_key"]
            pack = eng / "report_artifacts" / key
            self.assertTrue((pack / "finding.json").is_file())
            self.assertTrue((pack / "rubric.md").read_text(encoding="utf-8").startswith("# Program Rubric"))
            self.assertIn("def vulnerable", (pack / "source_excerpt.txt").read_text(encoding="utf-8"))

    def test_parent_intervention_records_next_service_and_blocker(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            cf = ClaudeFinding(
                title="Real but not reproduced",
                severity="critical",
                file="target.py",
                line=1,
                lens="supply-chain",
                root_cause="untrusted source",
                reproduction="run pytest",
                counterfactual="developer machine command execution",
                confidence="high",
            )
            s._parent_intervene(
                cf,
                target_agent="poc_prover",
                blocked_by="not_reproduced_yet",
                reason="falsifier says real",
                directive="build proof harness now",
            )
            pipe = s._pipeline_for(cf)
            self.assertEqual(pipe["status"], "intervened")
            self.assertEqual(pipe["target_agent"], "poc_prover")
            self.assertEqual(pipe["blocked_by"], "not_reproduced_yet")
            self.assertIn("build proof harness", s._operator_notes_for("poc_prover", cf))

    def test_control_reload_applies_runtime_reload(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            eng = Path(d) / "eng"
            (eng / "control.jsonl").write_text(
                json.dumps({"kind": "reload", "modules": ["p1hunt.agents.claude_hunter"]}) + "\n",
                encoding="utf-8",
            )
            with mock.patch("p1hunt.runtime_reload.apply_runtime_reload", return_value={
                "reloaded": ["p1hunt.agents.claude_hunter"],
                "skipped": {},
                "rebound": ["child_b1"],
                "refreshed": ["model_routing"],
                "limitations": "round-boundary only",
            }) as reload_fn:
                s._drain_control()
            reload_fn.assert_called_once()
            events = (eng / "events.jsonl").read_text(encoding="utf-8")
            self.assertIn("runtime_reload", events)
            self.assertIn("p1hunt.agents.claude_hunter", events)

    def test_control_pause_resume_stop_updates_runtime_state(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            eng = Path(d) / "eng"
            (eng / "control.jsonl").write_text(
                "\n".join([
                    json.dumps({"kind": "pause", "message": "operator pause"}),
                    json.dumps({"kind": "resume", "message": "operator resume"}),
                    json.dumps({"kind": "stop", "message": "operator stop"}),
                ]) + "\n",
                encoding="utf-8",
            )
            s._drain_control()
            self.assertFalse(s._paused)
            self.assertTrue(s._safety_event)
            events = (eng / "events.jsonl").read_text(encoding="utf-8")
            self.assertIn('"event": "pause"', events)
            self.assertIn('"event": "resume"', events)
            self.assertIn('"event": "stop"', events)

    def test_live_blackboard_posts_become_verifier_candidates(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            s._emit("child_b1", "finding_reported", {
                "title": "Bito installer sources CDN shell",
                "severity": "critical",
                "location": "tmp/mcp-fetch/install.sh:115",
                "evidence": "BITO_CDN_URL controls manifest_install.sh before source",
                "attempted_escalation": "served hostile manifest in local harness",
                "verification_depth": "source path traced through curl and source",
                "blocked_by": "needs deterministic host proof",
            })
            live = s._live_findings_as_candidates()
            self.assertEqual(len(live), 1)
            self.assertEqual(live[0].file, "tmp/mcp-fetch/install.sh")
            self.assertEqual(live[0].line, 115)
            self.assertIn("BITO_CDN_URL", live[0].root_cause)
            self.assertIn("local harness", live[0].reproduction)

    def test_verified_live_post_keeps_confirmed_pipeline_status(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            s._emit("operator", "finding_reported", {
                "title": "Recovered joint key",
                "severity": "critical",
                "file": "target.py",
                "line": 1,
                "status": "confirmed_critical_reproduced",
                "verified": True,
                "verification_depth": "local harness recovered the key with zero aborts",
            })
            live = json.loads((Path(d) / "eng" / "live_findings.json").read_text(encoding="utf-8"))
            pipe = live["candidates"][0]["pipeline"]
            self.assertEqual(pipe["stage"], "operator_verified")
            self.assertEqual(pipe["status"], "confirmed_critical_reproduced")
            self.assertEqual(pipe["blocked_by"], "")

    def test_reworded_duplicate_inherits_pipeline_status_by_location(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            s._emit("child_b4", "finding_reported", {
                "title": "BAM add_user accepts attacker chosen shares",
                "severity": "critical",
                "file": "target.py",
                "line": 1,
                "root_cause": "first map entry controls expected public key",
            })
            live = json.loads((Path(d) / "eng" / "live_findings.json").read_text(encoding="utf-8"))
            original = live["candidates"][0]
            renamed = ClaudeFinding(
                title="BAM add_user accepts substituted public key from one source entry",
                severity="critical",
                file="target.py",
                line=1,
                lens="authorization",
                root_cause="same vulnerable branch described with different wording",
                reproduction="exploit-depth running",
                counterfactual="target key control if full attacker chain closes",
                confidence="medium",
            )
            s._record_candidate_status(
                renamed,
                stage="EXPLOIT",
                status="running",
                target_agent="exploit_developer",
                next_action="close attacker-win chain or write blocker",
                reason="same file:line lead was normalized by Parent A",
            )

            enriched = s._apply_pipeline_status(dict(original))
            self.assertEqual(enriched["pipeline"]["status"], "running")
            self.assertEqual(enriched["pipeline"]["target_agent"], "exploit_developer")

    def test_fastlane_pending_marks_hot_post_without_demoting_running_work(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            lead = ClaudeFinding(
                title="Hot blackboard lead",
                severity="critical",
                file="target.py",
                line=1,
                lens="authz",
                root_cause="broken trust boundary",
                reproduction="static candidate",
                counterfactual="protected control if proven",
                confidence="medium",
            )
            s._mark_fastlane_pending(lead, cut_discovery=False)
            pipe = s._pipeline_for(lead)
            self.assertEqual(pipe["status"], "fastlane_pending_verification")
            self.assertEqual(pipe["blocked_by"], "round_in_progress")

            s._record_candidate_status(
                lead,
                stage="EXPLOIT",
                status="running",
                target_agent="exploit_developer",
                next_action="close attacker-win chain",
            )
            s._mark_fastlane_pending(lead, cut_discovery=False)
            self.assertEqual(s._pipeline_for(lead)["status"], "running")

    def test_write_findings_json_accepts_claude_finding_without_poc(self):
        with tempfile.TemporaryDirectory() as d:
            s = _swarm(d)
            cf = ClaudeFinding(
                title="Critical without poc object",
                severity="critical",
                file="target.py",
                line=1,
                lens="authz",
                root_cause="broken invariant",
                reproduction="reasoned",
                counterfactual="rogue signature",
                confidence="high",
                remediation="bind the invariant",
            )
            s._write_findings_json([cf], [cf], [cf])
            doc = json.loads((Path(d) / "eng" / "findings.json").read_text(encoding="utf-8"))
            self.assertEqual(doc["counts"]["confirmed_critical"], 1)
            self.assertEqual(doc["counts"]["needs_human_review"], 1)
            self.assertEqual(doc["counts"]["candidates"], 1)

    def test_web_tail_merges_live_blackboard_findings_with_stale_snapshot(self):
        from p1hunt.web.server import _tail

        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            (eng / "findings.json").write_text(json.dumps({
                "program": "Unit Program",
                "counts": {"confirmed_critical": 0, "needs_human_review": 0, "candidates": 1},
                "confirmed_criticals": [],
                "needs_human_review": [],
                "candidates": [{
                    "title": "Old SSRF candidate",
                    "severity": "high",
                    "file": "https://example.test/api",
                }],
            }), encoding="utf-8")
            events = [
                {"id": "1", "ts": 1.0, "agent": "child_b1", "kind": "finding_reported",
                 "data": {"title": "Live critical supply chain issue", "severity": "critical",
                          "file": "install.sh", "line": 115}},
            ]
            (eng / "events.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in events),
                encoding="utf-8",
            )

            doc = _tail(eng, 0)["findings"]
            titles = [c["title"] for c in doc["candidates"]]
            self.assertIn("Old SSRF candidate", titles)
            self.assertIn("Live critical supply chain issue", titles)
            self.assertEqual(doc["counts"]["candidates"], 2)

    def test_web_tail_enriches_live_findings_with_candidate_status_events(self):
        from p1hunt.web.server import _tail

        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            key = "abc123"
            events = [
                {"id": "1", "ts": 1.0, "agent": "child_b1", "kind": "finding_reported",
                 "data": {"dedup_key": key, "title": "Live finding", "severity": "critical",
                          "file": "target.py", "line": 1}},
                {"id": "2", "ts": 2.0, "agent": "parent_a", "kind": "lifecycle",
                 "data": {"event": "candidate_status", "dedup_key": key, "title": "Live finding",
                          "stage": "verifier", "status": "real", "target_agent": "poc_prover",
                          "next_action": "build proof", "blocked_by": "not_reproduced_yet"}},
            ]
            (eng / "events.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in events),
                encoding="utf-8",
            )

            doc = _tail(eng, 0)["findings"]
            cand = doc["candidates"][0]
            self.assertEqual(cand["pipeline"]["status"], "real")
            self.assertEqual(cand["pipeline"]["blocked_by"], "not_reproduced_yet")

    def test_web_tail_preserves_candidate_status_history_for_process_view(self):
        from p1hunt.web.server import _tail

        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            key = "abc123"
            events = [
                {"id": "1", "ts": 1.0, "agent": "child_b1", "kind": "finding_reported",
                 "data": {"dedup_key": key, "title": "Live finding", "severity": "critical",
                          "file": "target.py", "line": 1}},
                {"id": "2", "ts": 2.0, "agent": "parent_a", "kind": "lifecycle",
                 "data": {"event": "candidate_status", "dedup_key": key, "title": "Live finding",
                          "stage": "verifier", "status": "real", "target_agent": "poc_prover",
                          "next_action": "build proof", "blocked_by": "not_reproduced_yet"}},
                {"id": "3", "ts": 3.0, "agent": "parent_a", "kind": "lifecycle",
                 "data": {"event": "candidate_status", "dedup_key": key, "title": "Live finding",
                          "stage": "poc_prover", "status": "running", "target_agent": "poc_prover",
                          "next_action": "running proof", "blocked_by": ""}},
            ]
            (eng / "events.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in events),
                encoding="utf-8",
            )

            doc = _tail(eng, 0)["findings"]
            hist = doc["candidates"][0]["pipeline"]["history"]
            self.assertGreaterEqual(len(hist), 2)
            self.assertEqual(hist[-1]["status"], "running")
            self.assertIn(key, doc["activity"]["candidate_history"])

    def test_web_tail_exposes_current_route_without_demoting_best_proof(self):
        from p1hunt.web.server import _tail

        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            key = "abc123"
            events = [
                {"id": "1", "ts": 1.0, "agent": "child_b1", "kind": "finding_reported",
                 "data": {"dedup_key": key, "title": "Live finding", "severity": "critical",
                          "file": "target.py", "line": 1}},
                {"id": "2", "ts": 2.0, "agent": "parent_a", "kind": "lifecycle",
                 "data": {"event": "candidate_status", "dedup_key": key, "title": "Live finding",
                          "stage": "runner", "status": "reproduced", "target_agent": "poc_prover",
                          "next_action": "promote"}},
                {"id": "3", "ts": 3.0, "agent": "parent_a", "kind": "lifecycle",
                 "data": {"event": "candidate_status", "dedup_key": key, "title": "Live finding",
                          "stage": "parent_a", "status": "intervened",
                          "target_agent": "exploit_developer",
                          "next_action": "close attacker win"}},
            ]
            (eng / "events.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in events),
                encoding="utf-8",
            )

            cand = _tail(eng, 0)["findings"]["candidates"][0]
            self.assertEqual(cand["pipeline"]["status"], "reproduced")
            self.assertEqual(cand["pipeline"]["target_agent"], "poc_prover")
            self.assertEqual(cand["pipeline"]["current"]["status"], "intervened")
            self.assertEqual(cand["pipeline"]["current_agent"], "exploit_developer")

    def test_web_tail_title_only_status_enriches_matching_candidate(self):
        from p1hunt.web.server import _tail

        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            events = [
                {"id": "1", "ts": 1.0, "agent": "child_b1", "kind": "finding_reported",
                 "data": {"title": "Title keyed finding", "severity": "critical",
                          "file": "target.py", "line": 1}},
                {"id": "2", "ts": 2.0, "agent": "parent_a", "kind": "lifecycle",
                 "data": {"event": "candidate_status", "title": "Title keyed finding",
                          "stage": "verifier", "status": "real",
                          "target_agent": "poc_prover"}},
            ]
            (eng / "events.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in events),
                encoding="utf-8",
            )

            cand = _tail(eng, 0)["findings"]["candidates"][0]
            self.assertEqual(cand["pipeline"]["status"], "real")
            self.assertEqual(cand["pipeline"]["current_agent"], "poc_prover")

    def test_web_tail_preserves_confirmed_status_over_later_blackboard_post(self):
        from p1hunt.web.server import _tail

        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            key = "same-root"
            (eng / "findings.json").write_text(json.dumps({
                "program": "Unit Program",
                "counts": {"confirmed_critical": 1, "needs_human_review": 0, "candidates": 1},
                "confirmed_criticals": [{
                    "dedup_key": key,
                    "title": "RAND_R reuse recovers key",
                    "severity": "critical",
                    "file": "mpc.py",
                    "root_cause": "same nonce reused",
                    "counterfactual": "private key recovered",
                }],
                "needs_human_review": [],
                "candidates": [{
                    "dedup_key": key,
                    "title": "RAND_R reuse recovers key",
                    "severity": "critical",
                    "file": "mpc.py",
                    "root_cause": "same nonce reused",
                    "pipeline": {"stage": "operator_verified", "status": "confirmed_critical_reproduced"},
                }],
            }), encoding="utf-8")
            events = [
                {"id": "1", "ts": 2.0, "agent": "parent_a", "kind": "lifecycle",
                 "data": {"event": "candidate_status", "dedup_key": key,
                          "title": "RAND_R reuse recovers key", "stage": "blackboard", "status": "posted",
                          "blocked_by": "awaiting_parent_pipeline"}},
            ]
            (eng / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")

            doc = _tail(eng, 0)["findings"]
            self.assertEqual(doc["confirmed_criticals"][0]["pipeline"]["status"], "confirmed_critical_reproduced")
            self.assertEqual(doc["candidates"][0]["pipeline"]["status"], "confirmed_critical_reproduced")
            self.assertTrue(doc["candidates"][0]["already_confirmed"])
            self.assertEqual(doc["counts"]["actionable_candidates"], 0)

    def test_web_tail_reconstructs_activity_for_first_load_panels(self):
        from p1hunt.web.server import _tail

        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            (eng / "findings.json").write_text(json.dumps({
                "program": "Unit Program",
                "counts": {"confirmed_critical": 1, "needs_human_review": 0, "candidates": 2},
                "confirmed_criticals": [{"title": "Confirmed critical", "severity": "critical"}],
                "needs_human_review": [],
                "candidates": [
                    {"title": "Duplicate title", "severity": "critical", "file": "a.py"},
                    {"title": "Duplicate title", "severity": "critical", "file": "a.py:12"},
                ],
            }), encoding="utf-8")
            events = [
                {"id": "1", "ts": 1.0, "agent": "child_b1", "kind": "thinking", "data": {"text": "hunt"}},
                {"id": "2", "ts": 2.0, "agent": "parent_a", "kind": "lifecycle",
                 "data": {"event": "candidate_status", "dedup_key": "x", "title": "Duplicate title",
                          "stage": "verifier", "status": "real"}},
            ]
            (eng / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")

            doc = _tail(eng, 0)["findings"]
            agents = {a["agent"] for a in doc["activity"]["agents"]}
            self.assertIn("child_b1", agents)
            self.assertIn("parent_a", agents)
            self.assertIn("No debate events", doc["activity"]["debate"][0]["text"])
            self.assertIn("duplicate-looking", doc["activity"]["dedup"][0]["text"])

    def test_web_counts_low_priority_candidates_separately(self):
        from p1hunt.web.server import _tail

        with tempfile.TemporaryDirectory() as d:
            eng = Path(d) / "eng"
            eng.mkdir()
            (eng / "findings.json").write_text(json.dumps({
                "program": "Unit Program",
                "confirmed_criticals": [],
                "needs_human_review": [],
                "candidates": [
                    {"title": "Low note", "severity": "low", "file": "a.py"},
                    {"title": "Info note", "severity": "info", "file": "b.py"},
                    {"title": "High lead", "severity": "high", "file": "c.py"},
                ],
            }), encoding="utf-8")
            (eng / "events.jsonl").write_text("", encoding="utf-8")

            doc = _tail(eng, 0)["findings"]
            self.assertEqual(doc["counts"]["candidates"], 1)
            self.assertEqual(doc["counts"]["raw_candidates"], 3)
            self.assertEqual(doc["counts"]["actionable_candidates"], 1)
            self.assertEqual(doc["counts"]["low_priority_candidates"], 2)

    def test_web_control_endpoint_queues_targeted_triage(self):
        import urllib.request
        from p1hunt.web.server import _Handler

        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("P1HUNT_ENGAGEMENTS")
            os.environ["P1HUNT_ENGAGEMENTS"] = d
            srv = None
            try:
                eng = Path(d) / "eng"
                eng.mkdir()
                (eng / "events.jsonl").write_text("", encoding="utf-8")
                srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
                thread = threading.Thread(target=srv.serve_forever, daemon=True)
                thread.start()
                port = srv.server_address[1]
                body = json.dumps({
                    "eng": "eng",
                    "kind": "triage",
                    "title": "Live finding",
                    "target_agent": "poc_prover",
                    "action": "build proof now",
                }).encode("utf-8")
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/control",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                out = json.loads(urllib.request.urlopen(req, timeout=5).read().decode("utf-8"))
                self.assertTrue(out["ok"])
                rec = json.loads((eng / "control.jsonl").read_text(encoding="utf-8"))
                self.assertEqual(rec["target_agent"], "poc_prover")
                self.assertEqual(rec["action"], "build proof now")
            finally:
                try:
                    if srv is not None:
                        srv.shutdown()
                        srv.server_close()
                except Exception:
                    pass
                if old is None:
                    os.environ.pop("P1HUNT_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_ENGAGEMENTS"] = old

    def test_web_control_endpoint_queues_reload(self):
        import urllib.request
        from p1hunt.web.server import _Handler

        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("P1HUNT_ENGAGEMENTS")
            os.environ["P1HUNT_ENGAGEMENTS"] = d
            srv = None
            try:
                eng = Path(d) / "eng"
                eng.mkdir()
                (eng / "events.jsonl").write_text("", encoding="utf-8")
                srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
                thread = threading.Thread(target=srv.serve_forever, daemon=True)
                thread.start()
                port = srv.server_address[1]
                body = json.dumps({
                    "eng": "eng",
                    "kind": "reload",
                    "modules": ["p1hunt.agents.claude_hunter", "os"],
                }).encode("utf-8")
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/control",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                out = json.loads(urllib.request.urlopen(req, timeout=5).read().decode("utf-8"))
                self.assertTrue(out["ok"])
                rec = json.loads((eng / "control.jsonl").read_text(encoding="utf-8"))
                self.assertEqual(rec["kind"], "reload")
                self.assertEqual(rec["modules"], ["p1hunt.agents.claude_hunter"])
            finally:
                try:
                    if srv is not None:
                        srv.shutdown()
                        srv.server_close()
                except Exception:
                    pass
                if old is None:
                    os.environ.pop("P1HUNT_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_ENGAGEMENTS"] = old

    def test_web_control_endpoint_queues_pause_resume_stop(self):
        import urllib.request
        from p1hunt.web.server import _Handler

        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("P1HUNT_ENGAGEMENTS")
            os.environ["P1HUNT_ENGAGEMENTS"] = d
            srv = None
            try:
                eng = Path(d) / "eng"
                eng.mkdir()
                (eng / "events.jsonl").write_text("", encoding="utf-8")
                srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
                thread = threading.Thread(target=srv.serve_forever, daemon=True)
                thread.start()
                port = srv.server_address[1]
                for kind in ("pause", "resume", "stop"):
                    body = json.dumps({"eng": "eng", "kind": kind, "message": f"{kind} now"}).encode("utf-8")
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/control",
                        data=body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    out = json.loads(urllib.request.urlopen(req, timeout=5).read().decode("utf-8"))
                    self.assertTrue(out["ok"])
                rows = [
                    json.loads(line) for line in (eng / "control.jsonl").read_text(encoding="utf-8").splitlines()
                ]
                self.assertEqual([r["kind"] for r in rows], ["pause", "resume", "stop"])
                self.assertTrue(all(r["source"] == "web" for r in rows))
            finally:
                try:
                    if srv is not None:
                        srv.shutdown()
                        srv.server_close()
                except Exception:
                    pass
                if old is None:
                    os.environ.pop("P1HUNT_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_ENGAGEMENTS"] = old

    def test_web_engagement_list_orders_by_event_recency(self):
        from p1hunt.web.server import _list_engagements

        with tempfile.TemporaryDirectory() as d:
            old_env = os.environ.get("P1HUNT_ENGAGEMENTS")
            os.environ["P1HUNT_ENGAGEMENTS"] = d
            try:
                old = Path(d) / "old"
                new = Path(d) / "new"
                old.mkdir()
                new.mkdir()
                old_ev = old / "events.jsonl"
                new_ev = new / "events.jsonl"
                old_ev.write_text("", encoding="utf-8")
                new_ev.write_text("", encoding="utf-8")
                os.utime(old_ev, (100, 100))
                os.utime(new_ev, (200, 200))

                out = _list_engagements()
                self.assertGreaterEqual(len(out), 2)
                self.assertEqual(out[0]["id"], "new")
            finally:
                if old_env is None:
                    os.environ.pop("P1HUNT_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_ENGAGEMENTS"] = old_env

    def test_web_engagement_filter_hides_other_runs(self):
        from p1hunt.web.server import _list_engagements, _safe_eng_dir

        with tempfile.TemporaryDirectory() as d:
            old_root = os.environ.get("P1HUNT_ENGAGEMENTS")
            old_filter = os.environ.get("P1HUNT_WEB_ENGAGEMENTS")
            os.environ["P1HUNT_ENGAGEMENTS"] = d
            os.environ["P1HUNT_WEB_ENGAGEMENTS"] = "allowed"
            try:
                for name in ("allowed", "hidden"):
                    eng = Path(d) / name
                    eng.mkdir()
                    (eng / "events.jsonl").write_text("", encoding="utf-8")

                out = _list_engagements()
                self.assertEqual([x["id"] for x in out], ["allowed"])
                self.assertIsNotNone(_safe_eng_dir("allowed"))
                self.assertIsNone(_safe_eng_dir("hidden"))
            finally:
                if old_root is None:
                    os.environ.pop("P1HUNT_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_ENGAGEMENTS"] = old_root
                if old_filter is None:
                    os.environ.pop("P1HUNT_WEB_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_WEB_ENGAGEMENTS"] = old_filter

    def test_web_supervisor_status_reads_autopilot_heartbeat(self):
        from p1hunt.web.server import _supervisor_status

        with tempfile.TemporaryDirectory() as d:
            old_root = os.environ.get("P1HUNT_ENGAGEMENTS")
            old_filter = os.environ.get("P1HUNT_WEB_ENGAGEMENTS")
            os.environ["P1HUNT_ENGAGEMENTS"] = d
            os.environ["P1HUNT_WEB_ENGAGEMENTS"] = "eng"
            try:
                (Path(d) / "autopilot_state.json").write_text(json.dumps({
                    "supervisor": {
                        "pid": os.getpid(),
                        "updated_ts": 1000.0,
                        "engagements": ["eng"],
                        "interval_s": 30,
                        "candidate_stale_s": 300,
                        "hunt_stale_s": 120,
                        "triage_cooldown_s": 900,
                        "resume_hunts": True,
                        "supervise_web": True,
                        "web": {"host": "0.0.0.0", "port": 8787},
                    },
                    "engagements": {
                        "eng": {
                            "candidate_sweeper": {
                                "agent": "candidate_sweeper",
                                "status": "cooldown",
                                "candidate_count": 42,
                                "threshold": 10,
                                "title": "best candidate",
                                "target_agent": "exploit_developer",
                                "last_run_ts": 1000.0,
                            }
                        }
                    },
                }), encoding="utf-8")
                out = _supervisor_status()
                self.assertTrue(out["configured"])
                self.assertTrue(out["process_alive"])
                self.assertEqual(out["engagements"], ["eng"])
                self.assertEqual(out["web"]["port"], 8787)
                self.assertEqual(out["candidate_sweeper"]["status"], "cooldown")
                self.assertEqual(out["candidate_sweeper"]["title"], "best candidate")
            finally:
                if old_root is None:
                    os.environ.pop("P1HUNT_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_ENGAGEMENTS"] = old_root
                if old_filter is None:
                    os.environ.pop("P1HUNT_WEB_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_WEB_ENGAGEMENTS"] = old_filter

    def test_web_engagement_dead_process_is_not_reported_running(self):
        from p1hunt.web.server import _list_engagements

        with tempfile.TemporaryDirectory() as d:
            old_env = os.environ.get("P1HUNT_ENGAGEMENTS")
            os.environ["P1HUNT_ENGAGEMENTS"] = d
            try:
                eng = Path(d) / "dead"
                eng.mkdir()
                (eng / "events.jsonl").write_text("", encoding="utf-8")
                (eng / "process.json").write_text(json.dumps({
                    "kind": "hunt",
                    "pid": 999999999,
                    "argv": ["python3", "-m", "p1hunt.main", "hunt", "repo"],
                }), encoding="utf-8")

                out = _list_engagements()
                self.assertEqual(out[0]["id"], "dead")
                self.assertFalse(out[0]["running"])
                self.assertEqual(out[0]["health"], "stopped")
                self.assertFalse(out[0]["process_alive"])
            finally:
                if old_env is None:
                    os.environ.pop("P1HUNT_ENGAGEMENTS", None)
                else:
                    os.environ["P1HUNT_ENGAGEMENTS"] = old_env


if __name__ == "__main__":
    unittest.main()
