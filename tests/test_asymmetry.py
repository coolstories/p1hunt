"""Unit tests for the control-asymmetry hunter (p1hunt.agents.asymmetry).

Three concerns, in priority order:

  1. SAFETY — enumeration may propose any sibling host it discovers, but a probe to a host the
     operator did not authorize must never be issued. Tested at all three gates (the pure
     allowlist filter, the ScopeGuard chokepoint, and a transport that refuses).
  2. ENUMERATION — pure, deterministic, one-factor-at-a-time probe construction across the four
     dimensions (host, path, client, auth).
  3. DIFFERENTIAL — "control present at X, absent at Y", with escalation flagged only when the
     protected behavior is also reachable, and with "cannot tell" never reported as "absent".

No network: the transport is always injected.
"""

from __future__ import annotations

import asyncio
import os
import unittest

from p1hunt.agents.asymmetry import (
    AUTH_ANONYMOUS,
    AUTH_PRIVILEGED,
    AUTH_USER,
    DIM_AUTH,
    DIM_CLIENT,
    DIM_HOST,
    DIM_PATH,
    AsymmetryHunter,
    AsymmetryProbe,
    ClientVariant,
    ControlPresence,
    ControlSignature,
    Observation,
    SecurityControl,
    differential,
    enumerate_probes,
    guarded_http_transport,
    hosts_from_scope,
    max_probes,
    scope_filter,
    sibling_hosts,
)
from p1hunt.models import Asset, DynamicTarget, GuardDecision, Scope


def _control(kind: str = "header-present", key: str = "x-guard", value: str = "") -> SecurityControl:
    return SecurityControl(
        id="CTL1", name="the render gate",
        signature=ControlSignature(kind=kind, key=key, value=value),
        observed_at="https://app.example.com/share/{p}",
        protects="the rendered output",
    )


class SignatureTest(unittest.TestCase):
    """A signature must answer present / absent / CANNOT TELL — the third is what prevents a
    false escalation being written up from an unreachable probe."""

    def _obs(self, **kw) -> Observation:
        base = {"probe_id": "p", "reached": True, "status": 200, "headers": {}, "body": ""}
        base.update(kw)
        return Observation(**base)

    def test_header_present(self) -> None:
        sig = ControlSignature(kind="header-present", key="X-Guard")
        self.assertIs(sig.evaluate(self._obs(headers={"x-guard": "1"})), True)
        self.assertIs(sig.evaluate(self._obs(headers={})), False)

    def test_header_lookup_is_case_insensitive(self) -> None:
        sig = ControlSignature(kind="header-present", key="x-guard")
        self.assertIs(sig.evaluate(self._obs(headers={"X-GUARD": "1"})), True)

    def test_header_equals(self) -> None:
        sig = ControlSignature(kind="header-equals", key="x-mode", value="SAFE")
        self.assertIs(sig.evaluate(self._obs(headers={"x-mode": "safe"})), True)
        self.assertIs(sig.evaluate(self._obs(headers={"x-mode": "raw"})), False)
        self.assertIs(sig.evaluate(self._obs(headers={})), False)

    def test_marker_neutralized_is_the_generic_encoding_step(self) -> None:
        sig = ControlSignature(kind="marker-neutralized", key="MARKER123")
        self.assertIs(sig.evaluate(self._obs(body="all clean")), True)
        self.assertIs(sig.evaluate(self._obs(body="raw MARKER123 here")), False)

    def test_status_equals(self) -> None:
        sig = ControlSignature(kind="status-equals", value="403")
        self.assertIs(sig.evaluate(self._obs(status=403)), True)
        self.assertIs(sig.evaluate(self._obs(status=200)), False)

    def test_body_contains_and_absent(self) -> None:
        self.assertIs(ControlSignature(kind="body-contains", key="tok").evaluate(self._obs(body="a tok b")), True)
        self.assertIs(ControlSignature(kind="body-absent", key="tok").evaluate(self._obs(body="a b")), True)

    def test_unreachable_or_denied_is_undetermined(self) -> None:
        sig = ControlSignature(kind="header-present", key="x")
        self.assertIsNone(sig.evaluate(self._obs(reached=False)))
        self.assertIsNone(sig.evaluate(self._obs(denied=True)))
        self.assertIsNone(sig.evaluate(None))

    def test_unknown_kind_is_undetermined(self) -> None:
        self.assertIsNone(ControlSignature(kind="telepathy").evaluate(self._obs()))

    def test_marker_kinds_without_a_marker_are_undetermined(self) -> None:
        self.assertIsNone(ControlSignature(kind="marker-neutralized", key="").evaluate(self._obs()))


class EnumerationTest(unittest.TestCase):
    def test_baseline_is_always_first(self) -> None:
        probes = enumerate_probes(_control(), baseline_host="app.example.com", baseline_path="/share/x")
        self.assertEqual(len(probes), 1)
        self.assertTrue(probes[0].baseline)
        self.assertEqual(probes[0].url, "https://app.example.com/share/x")

    def test_one_factor_at_a_time_keeps_the_count_linear(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["m.example.com", "api.example.com"],
            paths=["/s/", "/alt"],
            clients=[ClientVariant("mobile", {"User-Agent": "m"})],
            auth_states=[AUTH_ANONYMOUS, AUTH_USER],
        )
        # 1 baseline + 2 hosts + 2 paths + 1 client + 2 auth = 8 (not a cross product)
        self.assertEqual(len(probes), 8)
        self.assertEqual(sum(1 for p in probes if p.dimension == DIM_HOST), 2)
        self.assertEqual(sum(1 for p in probes if p.dimension == DIM_PATH), 2)
        self.assertEqual(sum(1 for p in probes if p.dimension == DIM_CLIENT), 1)
        self.assertEqual(sum(1 for p in probes if p.dimension == DIM_AUTH), 2)

    def test_baseline_host_is_not_enumerated_as_its_own_sibling(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["app.example.com", "m.example.com"],
        )
        self.assertEqual([p.host for p in probes if p.dimension == DIM_HOST], ["m.example.com"])

    def test_baseline_path_is_not_enumerated_as_its_own_variant(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="h.example.com", baseline_path="/s", paths=["/s", "/t"],
        )
        self.assertEqual([p.url for p in probes if p.dimension == DIM_PATH],
                         ["https://h.example.com/t"])

    def test_duplicate_inputs_are_deduplicated(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="h.example.com", baseline_path="/s",
            hosts=["m.example.com", "M.example.com", " m.example.com "],
        )
        self.assertEqual(sum(1 for p in probes if p.dimension == DIM_HOST), 1)

    def test_client_variant_headers_are_carried(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="h.example.com", baseline_path="/s",
            clients=[ClientVariant("embed", {"Accept": "text/html", "X-Mode": "embed"})],
        )
        client = next(p for p in probes if p.dimension == DIM_CLIENT)
        self.assertEqual(client.headers["X-Mode"], "embed")

    def test_auth_states_map_to_identities(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="h.example.com", baseline_path="/s",
            auth_states=[AUTH_ANONYMOUS, AUTH_USER, AUTH_PRIVILEGED],
            identity_for={"user": "A", "privileged": "admin"},
        )
        by_state = {p.auth_state: p.identity for p in probes if p.dimension == DIM_AUTH}
        self.assertEqual(by_state[AUTH_ANONYMOUS], "")
        self.assertEqual(by_state[AUTH_USER], "A")
        self.assertEqual(by_state[AUTH_PRIVILEGED], "admin")

    def test_paths_are_normalized_to_absolute(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="h.example.com", baseline_path="/s", paths=["alt"],
        )
        self.assertEqual([p.url for p in probes if p.dimension == DIM_PATH],
                         ["https://h.example.com/alt"])

    def test_limit_caps_the_probe_set(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="h.example.com", baseline_path="/s",
            hosts=[f"h{i}.example.com" for i in range(50)], limit=5,
        )
        self.assertEqual(len(probes), 5)

    def test_max_probes_dial(self) -> None:
        prev = os.environ.get("P1HUNT_ASYMMETRY_MAX_PROBES")
        try:
            os.environ["P1HUNT_ASYMMETRY_MAX_PROBES"] = "7"
            self.assertEqual(max_probes(), 7)
            os.environ["P1HUNT_ASYMMETRY_MAX_PROBES"] = "nope"
            self.assertEqual(max_probes(), 200)
        finally:
            if prev is None:
                os.environ.pop("P1HUNT_ASYMMETRY_MAX_PROBES", None)
            else:
                os.environ["P1HUNT_ASYMMETRY_MAX_PROBES"] = prev


class ScopeEnforcementTest(unittest.TestCase):
    """THE safety property: a sibling-host sweep must not reach an unauthorized host."""

    def test_out_of_scope_host_is_dropped_with_a_reason(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["m.example.com", "evil.attacker.test"],
        )
        allowed, dropped = scope_filter(probes, ["example.com"])
        self.assertEqual([p.host for p in dropped and [d.probe for d in dropped]],
                         ["evil.attacker.test"])
        self.assertTrue(all("example.com" in p.host for p in allowed))
        self.assertIn("not in the authorized egress allowlist", dropped[0].reason)

    def test_subdomains_of_an_allowlisted_host_are_in_scope(self) -> None:
        probes = enumerate_probes(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["deep.nested.example.com"],
        )
        allowed, dropped = scope_filter(probes, ["example.com"])
        self.assertEqual(len(dropped), 0)
        self.assertEqual(len(allowed), 2)

    def test_empty_allowlist_denies_everything_remote(self) -> None:
        probes = enumerate_probes(_control(), baseline_host="app.example.com", baseline_path="/s")
        allowed, dropped = scope_filter(probes, [])
        self.assertEqual(allowed, [])
        self.assertEqual(len(dropped), 1)

    def test_build_hosts_are_not_accepted_as_targets(self) -> None:
        # A package registry is a build dependency, never a test target: accepting one would let
        # a probe leave the authorized perimeter through the build carve-out.
        probes = enumerate_probes(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["pypi.org", "github.com"],
        )
        _, dropped = scope_filter(probes, ["example.com"])
        self.assertEqual(sorted(d.probe.host for d in dropped), ["github.com", "pypi.org"])

    def test_loopback_stays_testable(self) -> None:
        probes = enumerate_probes(_control(), baseline_host="127.0.0.1:8080", baseline_path="/s")
        allowed, dropped = scope_filter(probes, [])
        self.assertEqual(len(allowed), 1)
        self.assertEqual(len(dropped), 0)

    def test_sibling_hosts_filters_discovered_candidates(self) -> None:
        authorized, refused = sibling_hosts(
            ["example.com"], ["example.com"],
            discovered=["m.example.com", "x.other.test", "app.example.com"],
        )
        self.assertEqual(authorized, ["m.example.com", "app.example.com"])
        self.assertEqual(refused, ["x.other.test"])

    def test_sibling_hosts_uses_an_injected_source(self) -> None:
        class Source:
            def hosts(self, seed: str) -> list[str]:
                return ["m.example.com", "evil.test"]

        authorized, refused = sibling_hosts(["example.com"], ["example.com"], source=Source())
        self.assertEqual(authorized, ["m.example.com"])
        self.assertEqual(refused, ["evil.test"])

    def test_a_failing_discovery_source_degrades_quietly(self) -> None:
        class Boom:
            def hosts(self, seed: str) -> list[str]:
                raise RuntimeError("no authorization for the CT endpoint")

        authorized, refused = sibling_hosts(["example.com"], ["example.com"], source=Boom())
        self.assertEqual(authorized, [])
        self.assertEqual(refused, [])

    def test_hosts_from_scope_only_yields_authorized_concrete_hosts(self) -> None:
        scope = Scope(
            program="P",
            in_scope=[
                Asset("a", "web", "domain", "https://app.example.com", "uat"),
                Asset("b", "wild", "domain", "*.example.com", "uat"),
            ],
            dynamic_targets=[DynamicTarget(base_url="https://api.example.com", environment="uat")],
        )
        hosts = hosts_from_scope(scope)
        # The wildcard is NOT expanded: a wildcard names a policy, not a host.
        self.assertEqual(sorted(hosts), ["api.example.com", "app.example.com"])

    def test_hosts_from_scope_tolerates_a_bare_object(self) -> None:
        self.assertEqual(hosts_from_scope(object()), [])


class _Guard:
    """Minimal ScopeGuard stand-in that records what it was asked to vet."""

    def __init__(self, allow_hosts: list[str]) -> None:
        self.allow_hosts = allow_hosts
        self.checked: list[str] = []

    def check_egress(self, agent: str, url: str, *, method: str = "GET") -> GuardDecision:
        self.checked.append(url)
        allow = any(h in url for h in self.allow_hosts)
        return GuardDecision(allow=allow, reason="ok" if allow else "out of scope",
                             tool="http", target=url, agent=agent)


class _Log:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict]] = []

    def emit(self, agent: str, kind: str, data: dict) -> None:
        self.events.append((agent, kind, data))

    def kinds(self) -> list[str]:
        return [k for _a, k, _d in self.events]


class HunterTest(unittest.TestCase):
    def test_no_transport_degrades_to_candidates(self) -> None:
        hunter = AsymmetryHunter(allowlist=["example.com"], event_log=_Log())
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["m.example.com"],
        ))
        self.assertFalse(report.executed)
        self.assertEqual(len(report.probes), 2)
        self.assertIn("no transport", report.note)

    def test_all_probes_refused_reports_not_executed(self) -> None:
        hunter = AsymmetryHunter(allowlist=[], event_log=_Log())
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
        ))
        self.assertFalse(report.executed)
        self.assertEqual(len(report.probes), 0)
        self.assertEqual(len(report.dropped), 1)

    def test_guard_denial_yields_undetermined_not_absent(self) -> None:
        # A guard-denied probe must never be read as "the control is missing there".
        guard = _Guard(allow_hosts=["app.example.com"])
        log = _Log()

        def transport(probe: AsymmetryProbe) -> Observation:
            return Observation(probe_id=probe.id, reached=True, status=200,
                               headers={"x-guard": "1"})

        hunter = AsymmetryHunter(allowlist=["example.com"], guard=guard, transport=transport,
                                 event_log=log)
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["m.example.com"],
        ))
        denied = [p for p in report.presence if p.probe.host == "m.example.com"]
        self.assertEqual(len(denied), 1)
        self.assertIsNone(denied[0].present)
        self.assertEqual(report.findings, ())

    def test_transport_scope_error_is_undetermined(self) -> None:
        def transport(probe: AsymmetryProbe) -> Observation:
            raise RuntimeError("refusing to contact out-of-scope host")

        hunter = AsymmetryHunter(allowlist=["example.com"], transport=transport, event_log=_Log())
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
        ))
        self.assertTrue(report.executed)
        self.assertTrue(all(p.undetermined for p in report.presence))

    def test_finds_the_one_host_missing_the_control(self) -> None:
        """The ground-truth shape: the gate runs everywhere except one sibling host."""

        log = _Log()

        def transport(probe: AsymmetryProbe) -> Observation:
            # Every host applies the gate except m.example.com.
            headers = {} if probe.host == "m.example.com" else {"x-guard": "1"}
            return Observation(probe_id=probe.id, reached=True, status=200, headers=headers)

        hunter = AsymmetryHunter(
            allowlist=["example.com"],
            guard=_Guard(allow_hosts=["example.com"]),
            transport=transport, event_log=log,
        )
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["api.example.com", "m.example.com"],
            sink_reachable_at=["m.example.com"],
        ))
        self.assertTrue(report.executed)
        self.assertEqual(len(report.findings), 1)
        finding = report.findings[0]
        self.assertEqual(finding.dimension, DIM_HOST)
        self.assertIn("m.example.com", finding.absent_at)
        self.assertIn("app.example.com", finding.present_at)
        self.assertTrue(finding.escalation)
        self.assertEqual(len(report.escalations), 1)
        self.assertIn("finding", log.kinds())

    def test_absence_without_a_reachable_sink_is_not_an_escalation(self) -> None:
        def transport(probe: AsymmetryProbe) -> Observation:
            headers = {} if probe.host == "m.example.com" else {"x-guard": "1"}
            return Observation(probe_id=probe.id, reached=True, status=200, headers=headers)

        hunter = AsymmetryHunter(allowlist=["example.com"], transport=transport, event_log=_Log())
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            hosts=["m.example.com"],
        ))
        self.assertEqual(len(report.findings), 1)
        self.assertFalse(report.findings[0].escalation)

    def test_async_transport_is_supported(self) -> None:
        async def transport(probe: AsymmetryProbe) -> Observation:
            headers = {} if probe.dimension == DIM_AUTH else {"x-guard": "1"}
            return Observation(probe_id=probe.id, reached=True, status=200, headers=headers)

        hunter = AsymmetryHunter(allowlist=["example.com"], transport=transport, event_log=_Log())
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
            auth_states=[AUTH_ANONYMOUS],
        ))
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].dimension, DIM_AUTH)

    def test_dropped_probes_are_emitted_as_guard_decisions(self) -> None:
        log = _Log()
        hunter = AsymmetryHunter(allowlist=["example.com"], event_log=log)
        hunter.plan(_control(), baseline_host="app.example.com", baseline_path="/s",
                    hosts=["evil.attacker.test"])
        denials = [d for a, k, d in log.events if k == "guard_decision"]
        self.assertEqual(len(denials), 1)
        self.assertFalse(denials[0]["allow"])
        self.assertIn("evil.attacker.test", denials[0]["target"])

    def test_a_broken_event_log_cannot_break_the_hunt(self) -> None:
        class Broken:
            def emit(self, *a, **k):
                raise RuntimeError("log is down")

        hunter = AsymmetryHunter(allowlist=["example.com"], event_log=Broken())
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
        ))
        self.assertIsNotNone(report)

    def test_malformed_brief_degrades_to_no_probes(self) -> None:
        hunter = AsymmetryHunter(allowlist=["example.com"], event_log=_Log())
        probes, dropped = hunter.plan(_control(), baseline_host="h.example.com")  # missing path kwarg
        self.assertEqual(probes, [])
        self.assertEqual(dropped, [])

    def test_summary_shape(self) -> None:
        hunter = AsymmetryHunter(allowlist=["example.com"], event_log=_Log())
        report = asyncio.run(hunter.run(
            _control(), baseline_host="app.example.com", baseline_path="/s",
        ))
        summary = report.summary()
        for key in ("control", "executed", "probes", "dropped_out_of_scope", "escalations"):
            self.assertIn(key, summary)


class DifferentialTest(unittest.TestCase):
    @staticmethod
    def _probe(pid: str, url: str, baseline: bool = False, dim: str = DIM_HOST) -> AsymmetryProbe:
        return AsymmetryProbe(id=pid, control_id="CTL1", dimension="baseline" if baseline else dim,
                              url=url, baseline=baseline, label="l")

    def test_no_determined_baseline_reports_nothing(self) -> None:
        # Without a verified reference, "absent here" is unfalsifiable — the signature may be wrong.
        presence = [
            ControlPresence(self._probe("b", "https://a.example.com/", baseline=True), None),
            ControlPresence(self._probe("p1", "https://m.example.com/"), False),
        ]
        self.assertEqual(differential(_control(), presence), [])

    def test_baseline_absent_reports_nothing(self) -> None:
        presence = [
            ControlPresence(self._probe("b", "https://a.example.com/", baseline=True), False),
            ControlPresence(self._probe("p1", "https://m.example.com/"), False),
        ]
        self.assertEqual(differential(_control(), presence), [])

    def test_undetermined_probe_is_never_an_asymmetry(self) -> None:
        presence = [
            ControlPresence(self._probe("b", "https://a.example.com/", baseline=True), True),
            ControlPresence(self._probe("p1", "https://m.example.com/"), None),
        ]
        self.assertEqual(differential(_control(), presence), [])

    def test_reports_every_absent_location(self) -> None:
        presence = [
            ControlPresence(self._probe("b", "https://a.example.com/", baseline=True), True),
            ControlPresence(self._probe("p1", "https://m.example.com/"), False),
            ControlPresence(self._probe("p2", "https://n.example.com/"), False),
            ControlPresence(self._probe("p3", "https://ok.example.com/"), True),
        ]
        findings = differential(_control(), presence)
        self.assertEqual(len(findings), 2)
        self.assertIn("present at", findings[0].statement.lower())

    def test_escalation_matches_a_full_url_too(self) -> None:
        presence = [
            ControlPresence(self._probe("b", "https://a.example.com/s", baseline=True), True),
            ControlPresence(self._probe("p1", "https://a.example.com/alt", dim=DIM_PATH), False),
        ]
        findings = differential(_control(), presence,
                                sink_reachable_at=["https://a.example.com/alt"])
        self.assertTrue(findings[0].escalation)

    def test_finding_as_dict_is_log_safe(self) -> None:
        presence = [
            ControlPresence(self._probe("b", "https://a.example.com/", baseline=True), True),
            ControlPresence(self._probe("p1", "https://m.example.com/"), False),
        ]
        doc = differential(_control(), presence)[0].as_dict()
        self.assertEqual(doc["dimension"], DIM_HOST)
        self.assertIn("statement", doc)


class TransportAdapterTest(unittest.TestCase):
    def test_guarded_http_transport_passes_url_under_the_url_key(self) -> None:
        """The guard's network branch keys off ``url`` — an asymmetry probe must always look
        like live contact to the egress jail, never like a plain 'target'."""

        seen: dict = {}

        class Tool:
            async def run(self, args: dict):
                seen.update(args)
                class R:
                    ok, denied, reason, summary = True, False, "", "ok"
                    data = {"performed": True, "status": 200, "headers": {"x-guard": "1"},
                            "body_excerpt": ""}
                return R()

        transport = guarded_http_transport(Tool(), identity_header="X-Test-Identity")
        probe = AsymmetryProbe(id="p", control_id="c", dimension=DIM_HOST,
                               url="https://m.example.com/s", identity="A")
        obs = asyncio.run(transport(probe))
        self.assertEqual(seen["url"], "https://m.example.com/s")
        self.assertTrue(seen["live"])
        self.assertEqual(seen["headers"]["X-Test-Identity"], "A")
        self.assertTrue(obs.reached)
        self.assertEqual(obs.status, 200)

    def test_denied_tool_result_becomes_a_denied_observation(self) -> None:
        class Tool:
            async def run(self, args: dict):
                class R:
                    ok, denied, reason, summary = False, True, "ScopeGuard denied: out of scope", ""
                    data: dict = {}
                return R()

        transport = guarded_http_transport(Tool())
        probe = AsymmetryProbe(id="p", control_id="c", dimension=DIM_HOST, url="https://x.test/")
        obs = asyncio.run(transport(probe))
        self.assertTrue(obs.denied)
        self.assertIn("out of scope", obs.reason)


if __name__ == "__main__":
    unittest.main()
