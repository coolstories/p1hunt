"""Control-asymmetry hunter — find the ONE place a control was forgotten.

The highest-yield escalation in authorized bug hunting is not finding another sink; it is
noticing that a control which *appears* to cover a sink is not applied **everywhere**. A finding
capped because "a gate makes this safe" is only capped where the gate runs. Enumerate every
location the gate SHOULD cover, test each one differentially, and a single location missing it
turns a conditional bug into an unconditional one.

This module models that as a mechanism, with NOTHING PRESET: it does not know what any control
is, which controls exist, or what a vulnerability looks like. It is handed a control that recon
or a finding already identified, plus the locations that control should cover, and it:

  1. ENUMERATES probes across four generic dimensions — sibling HOSTS, PATH/route families,
     CLIENT variants (how the response is rendered or negotiated), and AUTH STATES;
  2. FILTERS every probe against the authorized egress allowlist (pure, no I/O);
  3. OBSERVES each surviving probe through a scope-enforced transport; and
  4. DIFFERENTIALLY compares the observations: "control present at X, absent at Y."

A location missing the control is a candidate. A location missing it where the sink is also
reachable is a SEVERITY ESCALATION, which is the signal the escalation loop acts on.

SAFETY — three independent gates, in this order, and none of them is optional:
  * ``scope_filter`` drops any probe whose host is not in the operator's authorized egress
    allowlist, using the shared :mod:`p1hunt.dynamic.egress` definition of "allowed" (the same
    one the ScopeGuard and the bash jail use). Build/registry hosts are NOT accepted here — a
    package mirror is not a target.
  * ``ScopeGuard.check_egress`` re-decides every request at the chokepoint (dry-run block,
    host allowlist, method allowlist, rate limit) and the decision is logged to the audit trail.
  * the transport itself is the existing scope-enforced one (the guarded ``http_sandbox`` tool
    or ``dynamic.client.Client``), which refuses an out-of-scope host independently.

So an asymmetry hunt across sibling hosts CANNOT reach a host the operator did not authorize,
even though enumerating sibling hosts is exactly what the mechanism is for. Host DISCOVERY is
likewise injected, never performed here: this module has no network code at all. With no
transport supplied it degrades to returning the probe set as candidates for the operator.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Protocol

from ..dynamic.egress import normalize_host, url_allowed

# The four enumeration dimensions. These are *places a control can fail to be applied*, not bug
# classes: they describe the shape of a deployment, so they transfer to any target.
DIM_HOST = "host"      # sibling hosts of the same application (CT / subdomain sources)
DIM_PATH = "path"      # path variants and route families that reach the same handler
DIM_CLIENT = "client"  # how the client is served: negotiation / render / API-version variants
DIM_AUTH = "auth"      # which principal is asking: anonymous / user / privileged
DIMENSIONS = (DIM_HOST, DIM_PATH, DIM_CLIENT, DIM_AUTH)

# Generic auth states. Labels only — the orchestrator maps them to real test identities.
AUTH_ANONYMOUS = "anonymous"
AUTH_USER = "user"
AUTH_PRIVILEGED = "privileged"

_DEFAULT_MAX_PROBES = 200


def max_probes() -> int:
    """Probe ceiling for one asymmetry hunt.

    Dial: ``P1HUNT_ASYMMETRY_MAX_PROBES`` (default 200). Enumeration is one-factor-at-a-time, so
    the count grows linearly in each dimension; the cap is a throttle on live contact, not a stop."""

    raw = str(os.environ.get("P1HUNT_ASYMMETRY_MAX_PROBES", "")).strip()
    if raw.isdigit() and int(raw) >= 1:
        return int(raw)
    return _DEFAULT_MAX_PROBES


# ------------------------------------------------------------- observation --
@dataclass(frozen=True)
class Observation:
    """What a single probe saw. Deliberately minimal and transport-agnostic."""

    probe_id: str
    reached: bool = False          # did we actually get a response?
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    denied: bool = False           # a safety gate refused this probe (never an error)
    reason: str = ""

    def header(self, name: str) -> str:
        want = str(name or "").strip().lower()
        for key, value in self.headers.items():
            if str(key).strip().lower() == want:
                return str(value)
        return ""


@dataclass(frozen=True)
class ControlSignature:
    """How to TELL whether a control ran, as a predicate over one observation.

    The kinds are observation mechanics (is a header there, is a marker echoed, what status came
    back) — never a vulnerability pattern. Recon supplies ``key``/``value`` from what it actually
    saw at the location where the control WAS present; this module just evaluates them."""

    kind: str          # header-present | header-absent | header-equals | body-contains
                       # | body-absent | status-equals | marker-neutralized | marker-echoed
    key: str = ""      # header name, or the marker/token recon planted or observed
    value: str = ""    # expected header value / status, when the kind needs one

    def evaluate(self, obs: Observation) -> bool | None:
        """True = control present, False = control ABSENT, None = cannot tell from this
        observation (unreachable, denied, or a signature this observation cannot decide).

        None is a first-class answer: "we could not tell" must never be reported as "the control
        is missing", because that is exactly how a false escalation gets written up."""

        if obs is None or obs.denied or not obs.reached:
            return None
        kind = (self.kind or "").strip().lower()
        if kind == "header-present":
            return bool(obs.header(self.key))
        if kind == "header-absent":
            return not obs.header(self.key)
        if kind == "header-equals":
            got = obs.header(self.key)
            if not got:
                return False
            return got.strip().lower() == str(self.value or "").strip().lower()
        if kind == "body-contains":
            if not self.key:
                return None
            return self.key in (obs.body or "")
        if kind == "body-absent":
            if not self.key:
                return None
            return self.key not in (obs.body or "")
        if kind == "status-equals":
            want = str(self.value or "").strip()
            if not want.isdigit():
                return None
            return obs.status == int(want)
        if kind == "marker-neutralized":
            # The control ran iff the marker does NOT come back in its raw form. This is the
            # generic shape of any encoding/escaping/neutralizing step, with no opinion about
            # what the marker is — recon chose it.
            if not self.key:
                return None
            return self.key not in (obs.body or "")
        if kind == "marker-echoed":
            if not self.key:
                return None
            return self.key in (obs.body or "")
        return None


@dataclass(frozen=True)
class SecurityControl:
    """A control recon or a finding identified, plus how to observe it and where it was seen.

    ``name`` and ``signature`` are DERIVED per engagement and passed in. Nothing here encodes
    which controls a target ought to have."""

    id: str
    name: str                      # free-text label from recon ("the render gate", "the authz check")
    signature: ControlSignature
    observed_at: str = ""          # the URL/location where the control WAS observed working
    protects: str = ""             # what it is believed to neutralize (free text, from recon)
    note: str = ""


@dataclass(frozen=True)
class ClientVariant:
    """One way of being a client: headers that change negotiation, rendering, or API version.

    Values come from recon (what clients this target actually serves differently), never from a
    built-in list of user agents."""

    label: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AsymmetryProbe:
    """One differential test: a single location, with exactly ONE dimension varied."""

    id: str
    control_id: str
    dimension: str
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    identity: str = ""             # test-identity name the transport should authenticate as
    auth_state: str = ""
    label: str = ""                # human-readable "what is different here"
    baseline: bool = False         # the reference probe at the location the control WAS seen

    @property
    def host(self) -> str:
        return normalize_host(self.url)


@dataclass(frozen=True)
class DroppedProbe:
    """A probe refused before any packet left, with the reason. Recorded, not silently discarded —
    the operator must be able to see that an out-of-scope sibling host was enumerated and then
    REFUSED, which is the evidence that the hunt stayed inside its authorization."""

    probe: AsymmetryProbe
    reason: str


@dataclass(frozen=True)
class ControlPresence:
    """The verdict for one probe: did the control run here?"""

    probe: AsymmetryProbe
    present: bool | None           # None = undetermined
    observation: Observation | None = None

    @property
    def undetermined(self) -> bool:
        return self.present is None


@dataclass(frozen=True)
class AsymmetryFinding:
    """"Control present at X, absent at Y" — a differential result, with escalation flagged."""

    control_id: str
    control_name: str
    dimension: str
    present_at: str
    absent_at: str
    escalation: bool               # the sink is also reachable at the absent location
    statement: str
    probe_id: str = ""

    def as_dict(self) -> dict:
        return {
            "control": self.control_name,
            "control_id": self.control_id,
            "dimension": self.dimension,
            "present_at": self.present_at,
            "absent_at": self.absent_at,
            "escalation": self.escalation,
            "statement": self.statement,
            "probe_id": self.probe_id,
        }


@dataclass(frozen=True)
class AsymmetryReport:
    """Everything one asymmetry hunt produced — executed or not."""

    control_id: str
    control_name: str
    executed: bool
    probes: tuple[AsymmetryProbe, ...] = ()
    dropped: tuple[DroppedProbe, ...] = ()
    presence: tuple[ControlPresence, ...] = ()
    findings: tuple[AsymmetryFinding, ...] = ()
    note: str = ""

    @property
    def escalations(self) -> tuple[AsymmetryFinding, ...]:
        return tuple(f for f in self.findings if f.escalation)

    def summary(self) -> dict:
        return {
            "control": self.control_name,
            "executed": self.executed,
            "probes": len(self.probes),
            "dropped_out_of_scope": len(self.dropped),
            "undetermined": sum(1 for p in self.presence if p.undetermined),
            "asymmetries": len(self.findings),
            "escalations": len(self.escalations),
            "note": self.note,
        }


# ------------------------------------------------------------- enumeration --
def _url(scheme: str, host: str, path: str) -> str:
    sch = (scheme or "https").strip().rstrip(":/") or "https"
    h = str(host or "").strip().strip("/")
    p = str(path or "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    return f"{sch}://{h}{p}"


def _pid(control_id: str, dimension: str, index: int) -> str:
    return f"{control_id}-{dimension}-{index:03d}"


def enumerate_probes(
    control: SecurityControl,
    *,
    baseline_host: str,
    baseline_path: str,
    hosts: Iterable[str] = (),
    paths: Iterable[str] = (),
    clients: Iterable[ClientVariant] = (),
    auth_states: Iterable[str] = (),
    baseline_identity: str = "",
    identity_for: dict[str, str] | None = None,
    scheme: str = "https",
    method: str = "GET",
    limit: int | None = None,
) -> list[AsymmetryProbe]:
    """Build the probe set for one control. PURE — no I/O, fully deterministic, unit-testable.

    One-factor-at-a-time: every probe differs from the baseline in exactly ONE dimension. That is
    what makes the comparison a *differential* (an asymmetry is attributable to the dimension that
    changed) and it keeps the probe count linear instead of a combinatorial explosion of live
    requests against an authorized target.

    The baseline is the location where the control WAS observed; it is always probe 0, because a
    differential without a verified reference is just a guess."""

    cap = max_probes() if limit is None else max(1, int(limit))
    ident = {k.strip().lower(): v for k, v in (identity_for or {}).items()}
    probes: list[AsymmetryProbe] = [
        AsymmetryProbe(
            id=_pid(control.id, "baseline", 0),
            control_id=control.id,
            dimension="baseline",
            url=_url(scheme, baseline_host, baseline_path),
            method=method,
            identity=baseline_identity,
            auth_state=AUTH_USER if baseline_identity else AUTH_ANONYMOUS,
            label=f"baseline: where '{control.name}' was observed",
            baseline=True,
        )
    ]

    base_h = normalize_host(baseline_host)
    for index, host in enumerate(_clean_seq(hosts), start=1):
        if normalize_host(host) == base_h:
            continue  # the baseline host is not a sibling of itself
        probes.append(AsymmetryProbe(
            id=_pid(control.id, DIM_HOST, index),
            control_id=control.id,
            dimension=DIM_HOST,
            url=_url(scheme, host, baseline_path),
            method=method,
            identity=baseline_identity,
            auth_state=AUTH_USER if baseline_identity else AUTH_ANONYMOUS,
            label=f"sibling host {normalize_host(host)}",
        ))
        if len(probes) >= cap:
            return probes

    for index, path in enumerate(_clean_seq(paths), start=1):
        if path.strip() == str(baseline_path or "").strip():
            continue
        probes.append(AsymmetryProbe(
            id=_pid(control.id, DIM_PATH, index),
            control_id=control.id,
            dimension=DIM_PATH,
            url=_url(scheme, baseline_host, path),
            method=method,
            identity=baseline_identity,
            auth_state=AUTH_USER if baseline_identity else AUTH_ANONYMOUS,
            label=f"path variant {path}",
        ))
        if len(probes) >= cap:
            return probes

    for index, client in enumerate(clients, start=1):
        if client is None or not getattr(client, "label", ""):
            continue
        probes.append(AsymmetryProbe(
            id=_pid(control.id, DIM_CLIENT, index),
            control_id=control.id,
            dimension=DIM_CLIENT,
            url=_url(scheme, baseline_host, baseline_path),
            method=method,
            headers=dict(client.headers or {}),
            identity=baseline_identity,
            auth_state=AUTH_USER if baseline_identity else AUTH_ANONYMOUS,
            label=f"client variant {client.label}",
        ))
        if len(probes) >= cap:
            return probes

    for index, state in enumerate(_clean_seq(auth_states), start=1):
        probes.append(AsymmetryProbe(
            id=_pid(control.id, DIM_AUTH, index),
            control_id=control.id,
            dimension=DIM_AUTH,
            url=_url(scheme, baseline_host, baseline_path),
            method=method,
            identity=ident.get(state.strip().lower(), ""),
            auth_state=state.strip().lower(),
            label=f"auth state {state.strip().lower()}",
        ))
        if len(probes) >= cap:
            return probes
    return probes


def _clean_seq(values: Iterable[str]) -> list[str]:
    """Order-preserving, de-duplicated, blank-stripped."""

    out: list[str] = []
    seen: set[str] = set()
    for value in values or ():
        text = str(value or "").strip()
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append(text)
    return out


# ------------------------------------------------------- scope enforcement --
def scope_filter(
    probes: Iterable[AsymmetryProbe], allowlist: Iterable[str]
) -> tuple[list[AsymmetryProbe], list[DroppedProbe]]:
    """Split probes into (authorized, refused) against the operator's egress allowlist. PURE.

    This is GATE 1 of three and the reason a sibling-host sweep is safe: enumeration is allowed
    to *propose* any host it discovers, and this function refuses every one the operator did not
    authorize before a transport ever sees it. It reuses :func:`p1hunt.dynamic.egress.url_allowed`
    so there is exactly one definition of "in scope" shared with the ScopeGuard and the bash jail.

    ``allow_build_hosts=False``: a package registry is a build dependency, never a test target —
    accepting one here would let a probe leave the authorized perimeter. ``allow_loopback=True``
    keeps a locally stood-up instance testable, matching the rest of the package."""

    allow = [str(a) for a in (allowlist or ())]
    ok: list[AsymmetryProbe] = []
    dropped: list[DroppedProbe] = []
    for probe in probes or ():
        permitted, reason = url_allowed(
            probe.url, allow, allow_loopback=True, allow_build_hosts=False
        )
        if permitted:
            ok.append(probe)
        else:
            dropped.append(DroppedProbe(probe=probe, reason=reason))
    return ok, dropped


class HostSource(Protocol):
    """Injected sibling-host discovery (certificate transparency, a subdomain list, recon output).

    Implementations live OUTSIDE this module and must route any network call through the
    scope-enforced transport. Keeping discovery behind this protocol is what lets the enumeration
    layer stay pure and offline-testable."""

    def hosts(self, seed: str) -> list[str]: ...


def sibling_hosts(
    seed_hosts: Iterable[str],
    allowlist: Iterable[str],
    *,
    source: HostSource | None = None,
    discovered: Iterable[str] = (),
) -> tuple[list[str], list[str]]:
    """Resolve the HOST dimension: (authorized siblings, refused siblings). Never raises.

    Candidates come from an injected ``source`` and/or an already-``discovered`` list, then every
    one is checked against the allowlist. A discovery source that fails (no authorization, no
    network, a bad response) contributes nothing instead of breaking the hunt."""

    candidates: list[str] = list(_clean_seq(discovered))
    if source is not None:
        for seed in _clean_seq(seed_hosts):
            try:
                found = source.hosts(seed) or []
            except Exception:
                found = []  # discovery is best-effort; degrade, never raise
            candidates.extend(str(h) for h in found)
    authorized: list[str] = []
    refused: list[str] = []
    seen: set[str] = set()
    allow = [str(a) for a in (allowlist or ())]
    for raw in candidates:
        host = normalize_host(raw)
        if not host or host in seen:
            continue
        seen.add(host)
        permitted, _ = url_allowed(host, allow, allow_loopback=True, allow_build_hosts=False)
        (authorized if permitted else refused).append(host)
    return authorized, refused


def hosts_from_scope(scope: object) -> list[str]:
    """Concrete hosts the operator already authorized, from the engagement scope itself.

    The always-available fallback for the host dimension when no discovery source is authorized:
    it can only ever yield hosts that are in scope by construction. A wildcard scope entry is not
    expanded — a wildcard names a *policy*, not a host, and inventing members of it would be
    exactly the unauthorized guessing this module refuses to do."""

    out: list[str] = []
    seen: set[str] = set()
    for attr in ("in_scope", "dynamic_targets"):
        for asset in getattr(scope, attr, ()) or ():
            raw = getattr(asset, "value", "") or getattr(asset, "base_url", "")
            host = normalize_host(str(raw))
            if not host or "*" in host or host in seen:
                continue
            seen.add(host)
            out.append(host)
    return out


# ------------------------------------------------------------- differential --
def differential(
    control: SecurityControl,
    presence: Iterable[ControlPresence],
    *,
    sink_reachable_at: Iterable[str] = (),
) -> list[AsymmetryFinding]:
    """Compare presence verdicts and report every "present at X, absent at Y". PURE.

    Requires a determined baseline: without a reference location where the control demonstrably
    RAN, "absent here" is unfalsifiable (the signature may simply be wrong), so the function
    reports nothing rather than manufacturing asymmetries. Undetermined probes are never treated
    as absent for the same reason.

    ``sink_reachable_at`` marks locations where the thing the control protects is also reachable;
    an absence there is the severity ESCALATION the loop acts on, rather than a cosmetic gap."""

    items = [p for p in (presence or ())]
    baseline = next((p for p in items if p.probe.baseline and p.present is True), None)
    if baseline is None:
        return []
    reachable = {normalize_host(h) for h in (sink_reachable_at or ()) if h}
    reachable |= {str(h).strip() for h in (sink_reachable_at or ()) if h}
    present_at = baseline.probe.url
    out: list[AsymmetryFinding] = []
    for item in items:
        if item.probe.baseline or item.present is not False:
            continue
        absent_at = item.probe.url
        escalation = bool(
            reachable
            and (normalize_host(absent_at) in reachable or absent_at in reachable
                 or item.probe.host in reachable)
        )
        statement = (
            f"Control '{control.name}' is PRESENT at {present_at} but ABSENT at {absent_at} "
            f"(dimension: {item.probe.dimension}; varied: {item.probe.label}). "
            + (
                "The protected behavior is also reachable there, so the condition that capped "
                "this finding does not hold at that location — this is a severity escalation."
                if escalation else
                "Confirm whether the protected behavior is reachable there; if it is, the cap on "
                "this finding does not hold at that location."
            )
        )
        out.append(AsymmetryFinding(
            control_id=control.id,
            control_name=control.name,
            dimension=item.probe.dimension,
            present_at=present_at,
            absent_at=absent_at,
            escalation=escalation,
            statement=statement,
            probe_id=item.probe.id,
        ))
    return out


# ----------------------------------------------------------------- the hunt --
# A transport takes one probe and returns an Observation. The orchestrator injects the
# scope-enforced one (guarded http_sandbox tool / dynamic.client.Client).
Transport = Callable[[AsymmetryProbe], "Awaitable[Observation] | Observation"]


class AsymmetryHunter:
    """Runs an asymmetry hunt end-to-end: enumerate, scope-filter, observe, differentiate.

    Offline-graceful by construction. With no transport it returns the probe set as candidates;
    with a transport, any probe that the guard refuses or that cannot be reached becomes an
    UNDETERMINED presence rather than an exception or a false "control missing". No public method
    raises, and every decision is emitted to the event log."""

    def __init__(
        self,
        *,
        allowlist: Iterable[str] = (),
        guard: object | None = None,
        transport: Transport | None = None,
        event_log: object | None = None,
        agent: str = "asymmetry",
    ) -> None:
        self.allowlist = [str(a) for a in (allowlist or ())]
        self.guard = guard
        self.transport = transport
        self.log = event_log
        self.agent = agent

    # --- observability ----------------------------------------------------
    def _emit(self, kind: str, data: dict) -> None:
        if self.log is None:
            return
        try:
            self.log.emit(self.agent, kind, data)
        except Exception:
            return  # the log must never be able to break a hunt

    # --- planning ---------------------------------------------------------
    def plan(self, control: SecurityControl, **kwargs) -> tuple[list[AsymmetryProbe], list[DroppedProbe]]:
        """Enumerate probes and apply GATE 1 (the egress allowlist). Never raises."""

        try:
            probes = enumerate_probes(control, **kwargs)
        except Exception as exc:  # a malformed brief degrades to "no probes", never a crash
            self._emit("lifecycle", {"event": "asymmetry_plan_failed", "control": control.name,
                                     "reason": str(exc)[:200]})
            return [], []
        allowed, dropped = scope_filter(probes, self.allowlist)
        self._emit("message", {
            "phase": "asymmetry_plan",
            "control": control.name,
            "enumerated": len(probes),
            "authorized": len(allowed),
            "refused_out_of_scope": len(dropped),
            "dimensions": sorted({p.dimension for p in allowed}),
        })
        for drop in dropped:
            # Visible refusal: the operator sees that an out-of-scope sibling was enumerated and
            # then denied BEFORE any contact. This is the audit evidence for staying in scope.
            self._emit("guard_decision", {
                "allow": False, "tool": "asymmetry_probe", "agent": self.agent,
                "target": drop.probe.url, "reason": drop.reason,
            })
        return allowed, dropped

    # --- execution --------------------------------------------------------
    async def run(
        self,
        control: SecurityControl,
        *,
        sink_reachable_at: Iterable[str] = (),
        **kwargs,
    ) -> AsymmetryReport:
        """Plan, observe, and differentiate. Returns a report; never raises."""

        probes, dropped = self.plan(control, **kwargs)
        if not probes:
            return AsymmetryReport(
                control_id=control.id, control_name=control.name, executed=False,
                dropped=tuple(dropped),
                note="no authorized probe remained after the egress allowlist was applied",
            )
        if self.transport is None:
            # Degrade to a candidate set (the package's offline posture): the enumeration IS the
            # product even with no live access — the operator can drive it by hand.
            self._emit("message", {"phase": "asymmetry_candidates", "control": control.name,
                                   "probes": len(probes),
                                   "detail": "no transport attached; emitting probes as candidates"})
            return AsymmetryReport(
                control_id=control.id, control_name=control.name, executed=False,
                probes=tuple(probes), dropped=tuple(dropped),
                note="no transport attached — probe set surfaced as candidates for the operator",
            )

        presence: list[ControlPresence] = []
        for probe in probes:
            obs = await self._observe(probe)
            verdict = control.signature.evaluate(obs)
            presence.append(ControlPresence(probe=probe, present=verdict, observation=obs))
            self._emit("message", {
                "phase": "asymmetry_probe",
                "control": control.name,
                "probe": probe.id,
                "dimension": probe.dimension,
                "target": probe.url,
                "varied": probe.label,
                "control_present": verdict,
                "reached": bool(obs and obs.reached),
                "denied": bool(obs and obs.denied),
            })

        findings = differential(control, presence, sink_reachable_at=sink_reachable_at)
        for finding in findings:
            self._emit("finding" if finding.escalation else "message", {
                "event": "control_asymmetry",
                **finding.as_dict(),
            })
        report = AsymmetryReport(
            control_id=control.id, control_name=control.name, executed=True,
            probes=tuple(probes), dropped=tuple(dropped), presence=tuple(presence),
            findings=tuple(findings),
            note="" if findings else "no asymmetry observed across the authorized locations",
        )
        self._emit("lifecycle", {"event": "asymmetry_done", **report.summary()})
        return report

    async def _observe(self, probe: AsymmetryProbe) -> Observation:
        """GATE 2 (the ScopeGuard chokepoint) then the scope-enforced transport (GATE 3)."""

        if self.guard is not None:
            try:
                decision = self.guard.check_egress(self.agent, probe.url, method=probe.method)
            except Exception as exc:
                return Observation(probe_id=probe.id, denied=True,
                                   reason=f"guard error, treated as deny: {str(exc)[:160]}")
            if not getattr(decision, "allow", False):
                return Observation(probe_id=probe.id, denied=True,
                                   reason=getattr(decision, "reason", "denied by ScopeGuard"))
        try:
            result = self.transport(probe)  # type: ignore[misc]
            if hasattr(result, "__await__"):
                result = await result  # type: ignore[assignment]
        except Exception as exc:
            # Includes the transport's own ScopeError — an out-of-scope host refused at the
            # transport is an UNDETERMINED observation, never an "absent control".
            return Observation(probe_id=probe.id, denied=True, reason=str(exc)[:200])
        if isinstance(result, Observation):
            return result
        return _coerce_observation(probe.id, result)


def _coerce_observation(probe_id: str, result: object) -> Observation:
    """Accept a ToolResult / Response / dict from whichever transport was injected."""

    if result is None:
        return Observation(probe_id=probe_id, reason="transport returned nothing")
    # ToolResult (p1hunt.tools.base): denial is explicit, payload lives in .data
    if hasattr(result, "denied") and hasattr(result, "ok"):
        data = dict(getattr(result, "data", {}) or {})
        if getattr(result, "denied", False):
            return Observation(probe_id=probe_id, denied=True,
                               reason=str(getattr(result, "reason", "") or "denied"))
        status = data.get("status")
        return Observation(
            probe_id=probe_id,
            reached=bool(data.get("performed")) and bool(getattr(result, "ok", False)),
            status=int(status) if isinstance(status, int) else 0,
            headers={k: str(v) for k, v in (data.get("headers") or {}).items()},
            body=str(data.get("body_excerpt") or data.get("body") or ""),
            reason=str(getattr(result, "summary", "") or ""),
        )
    # Response (p1hunt.dynamic.client) or anything status/text shaped
    if hasattr(result, "status") and hasattr(result, "text"):
        return Observation(
            probe_id=probe_id, reached=True, status=int(getattr(result, "status", 0) or 0),
            headers={k: str(v) for k, v in (getattr(result, "headers", {}) or {}).items()},
            body=str(getattr(result, "text", "") or ""),
        )
    if isinstance(result, dict):
        status = result.get("status", 0)
        return Observation(
            probe_id=probe_id,
            reached=bool(result.get("reached", True)),
            status=int(status) if isinstance(status, int) else 0,
            headers={k: str(v) for k, v in (result.get("headers") or {}).items()},
            body=str(result.get("body") or ""),
            denied=bool(result.get("denied", False)),
            reason=str(result.get("reason") or ""),
        )
    return Observation(probe_id=probe_id, reason="unrecognized transport result")


def guarded_http_transport(tool: object, *, identity_header: str = "") -> Transport:
    """Adapt a guarded ``http_sandbox`` tool into a :data:`Transport`.

    The tool is already ScopeGuard-wrapped, so this keeps the hunt on the package's existing
    scope-enforced path instead of opening a socket of its own. The URL is passed under ``url``
    (not ``target``) because that is the key the guard's network branch keys off — the egress jail
    must always see an asymmetry probe as live contact."""

    async def _send(probe: AsymmetryProbe) -> Observation:
        headers = dict(probe.headers or {})
        if identity_header and probe.identity:
            headers.setdefault(identity_header, probe.identity)
        args = {
            "url": probe.url,
            "http_method": probe.method,
            "headers": headers,
            "read_only": probe.method.upper() in ("GET", "HEAD", "OPTIONS"),
            "live": True,
        }
        result = await tool.run(args)  # type: ignore[attr-defined]
        return _coerce_observation(probe.id, result)

    return _send
