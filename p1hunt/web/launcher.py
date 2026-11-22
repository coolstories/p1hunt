"""Start a hunt from the operations console, safely.

WHY THIS IS ITS OWN MODULE, AND WHY IT IS PARANOID
--------------------------------------------------
This turns an HTTP request into a spawned process with operator-supplied arguments. That
is the most dangerous thing in this package, so the rules are explicit and narrow:

  * NO SHELL, EVER. argv is built here from a fixed template. Operator values only ever
    land in VALUE positions, and a value that could be read as a flag is refused outright
    -- otherwise "--something" typed into the target field becomes a CLI option.
  * TOKENS NEVER TOUCH argv OR DISK. Process arguments are world-readable via `ps`, so
    credentials go into the child's environment only. The Scope persists the env var NAME,
    never the value (that is the existing design and this preserves it), and the launch
    response echoes lengths, never values.
  * THE OPERATOR ATTESTS AUTHORIZATION. A hunt touches someone else's system, and a web
    form makes that one click. The attestation is required, recorded in the engagement
    folder, and is a deliberate speed bump rather than a formality.
  * LOOPBACK ONLY. The console binds 127.0.0.1; nothing here changes that.

It also refuses to launch when `p1hunt doctor` says NO-GO, because the whole lesson of
this project is that a run on a broken machine reports success and finds nothing. The
operator can override with an explicit force, which is recorded.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# A program name becomes a directory name, so keep it to characters that cannot traverse
# or surprise a filesystem. main.py derives the folder the same way; mirrored here so the
# console and the CLI agree on where a run lands.
_PROGRAM_OK = re.compile(r"^[A-Za-z0-9 ._-]{1,60}$")
_URL_OK = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{3,400}$")
_IDENT_NAME_OK = re.compile(r"^[A-Za-z0-9_]{1,24}$")
_ENGINES = ("claude", "codex")
_PLATFORMS = ("local", "bugcrowd", "hackerone", "intigriti", "yeswehack", "immunefi", "other")
_MAX_ROUNDS = 50


class LaunchError(ValueError):
    """A refusal with an operator-readable reason. Never leaks a token value."""


@dataclass
class LaunchSpec:
    # The in-scope hosts, DERIVED from the pasted scope (see web/scope_parse.py) and
    # confirmed by the operator. This replaced a single free-text "target URL" field,
    # which invited pasting the program PAGE and pointed a hunt at a bug-bounty platform's
    # own website.
    hosts: list[str] = field(default_factory=list)
    # The program page, for the record only. NEVER a target.
    program_url: str = ""
    # Legacy single-target form, still accepted so the API stays usable directly.
    target: str = ""
    program: str = ""
    scope_note: str = ""
    engine: str = "claude"
    platform: str = "local"
    rounds: int = 3
    authorized: bool = False
    force: bool = False
    # name -> secret. Kept out of argv and off disk; see _child_env.
    identities: dict[str, str] = field(default_factory=dict)
    out_of_scope: str = ""
    # The operator explicitly confirmed a flagged host (a platform's own domain). Off by
    # default: HackerOne does run a program for hackerone.com, so this is possible, but it
    # must be a decision rather than an accident.
    confirm_flagged: bool = False

    @staticmethod
    def from_dict(d: dict) -> "LaunchSpec":
        if not isinstance(d, dict):
            raise LaunchError("expected a JSON object")
        idents = d.get("identities") or {}
        if not isinstance(idents, dict):
            raise LaunchError("identities must be an object of name -> token")
        raw_hosts = d.get("hosts") or []
        if isinstance(raw_hosts, str):
            raw_hosts = [h for h in re.split(r"[\s,]+", raw_hosts) if h]
        if not isinstance(raw_hosts, list):
            raise LaunchError("hosts must be a list of hostnames")
        return LaunchSpec(
            hosts=[str(h).strip() for h in raw_hosts if str(h).strip()],
            program_url=str(d.get("program_url") or "").strip(),
            target=str(d.get("target") or "").strip(),
            program=str(d.get("program") or "").strip(),
            scope_note=str(d.get("scope_note") or ""),
            engine=str(d.get("engine") or "claude").strip().lower(),
            platform=str(d.get("platform") or "local").strip().lower(),
            rounds=_rounds(d.get("rounds")),
            authorized=bool(d.get("authorized")),
            force=bool(d.get("force")),
            identities={str(k): str(v) for k, v in idents.items()},
            out_of_scope=str(d.get("out_of_scope") or "").strip(),
            confirm_flagged=bool(d.get("confirm_flagged")),
        )


def _rounds(raw: object) -> int:
    """Parse the round count, distinguishing ABSENT from ZERO.

    `int(raw or 3)` silently turns an explicit 0 into 3, because 0 is falsey. Defaulting
    when the field is missing is helpful; defaulting when the operator typed a number is
    not -- they should be told the value is out of range rather than quietly given a
    different run than they asked for.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return 3
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise LaunchError("rounds must be a whole number") from None


def _no_flag(value: str, field_name: str) -> str:
    """Refuse a value that argparse would read as an option.

    This is the actual injection boundary. There is no shell involved, so the only way an
    operator value can change the MEANING of the command is by being parsed as a flag.
    """
    if value.startswith("-"):
        raise LaunchError(f"{field_name} may not begin with '-'")
    return value


# A bare hostname, as the scope parser emits. Validated separately from a full URL so the
# operator can confirm "api.example.com" without having to type a scheme.
_HOSTNAME_OK = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")
# An IPv4 literal or a bare local name. Needed because a self-owned target is often a
# local app on 127.0.0.1 -- which is how this whole launcher was tested -- and the
# alphabetic-TLD rule above correctly rejects "127.0.0.1".
_IPV4_OK = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_LOCAL_NAMES = frozenset({"localhost", "::1"})


def _normalize_host_entry(raw: str) -> str:
    """One scope entry -> the https:// origin a hunt is confined to.

    Accepts a bare host, a wildcard, or a full URL, because all three appear in real scope
    tables. A loopback host keeps http, since a local range does not serve TLS.
    """
    h = raw.strip().rstrip("/")
    if not h:
        return ""
    _no_flag(h, "host")
    if "://" in h:
        if not _URL_OK.match(h):
            raise LaunchError(f"{raw!r} is not an http(s) URL")
        return h
    h = h.lstrip("*.")
    host_only = h.split("/", 1)[0].split(":", 1)[0]
    is_local = host_only in _LOCAL_NAMES or (
        _IPV4_OK.match(host_only) is not None
        and all(0 <= int(o) <= 255 for o in host_only.split(".")))
    if not is_local and not _HOSTNAME_OK.match(host_only):
        raise LaunchError(
            f"{raw!r} is not a hostname. Paste the program's scope and press "
            f"\u201cParse scope\u201d rather than typing targets by hand.")
    # A local target does not serve TLS; a public one must.
    scheme = "http" if is_local else "https"
    return f"{scheme}://{h}"


def validate(spec: LaunchSpec) -> LaunchSpec:
    """Normalize and refuse anything unsafe. Raises LaunchError with a readable reason."""
    if not spec.authorized:
        raise LaunchError(
            "authorization not attested. A hunt sends real traffic to someone else's "
            "system; confirm the hosts are in scope for a program you are authorized to "
            "test, or that you own them.")
    # A single legacy target folds into the host list, so one code path validates both.
    if spec.target and not spec.hosts:
        spec.hosts = [spec.target]
    if not spec.hosts:
        raise LaunchError(
            "no in-scope hosts. Paste the program's scope, press \u201cParse scope\u201d, "
            "and confirm the hosts it finds.")
    if len(spec.hosts) > 40:
        raise LaunchError("more than 40 hosts; narrow the scope for one run")

    from .scope_parse import is_platform_host

    normalized: list[str] = []
    for raw in spec.hosts:
        origin = _normalize_host_entry(raw)
        if not origin:
            continue
        if is_platform_host(origin) and not spec.confirm_flagged:
            raise LaunchError(
                f"{raw!r} is a bug-bounty PLATFORM's own domain, not an asset of the "
                f"program listed on it. This is the mistake that points a hunt at the "
                f"site where you read the policy. If the platform itself really is your "
                f"authorized target, confirm the flagged host explicitly.")
        normalized.append(origin)
    spec.hosts = list(dict.fromkeys(normalized))
    if not spec.hosts:
        raise LaunchError("no usable hosts after validation")
    spec.target = ",".join(spec.hosts)
    if spec.program_url:
        _no_flag(spec.program_url, "program URL")
        if not _URL_OK.match(spec.program_url):
            raise LaunchError("program URL must be an http(s) URL, or left blank")
    if not _PROGRAM_OK.match(spec.program):
        raise LaunchError("program name must be 1-60 chars of letters, digits, space, "
                          "dot, underscore or hyphen")
    _no_flag(spec.program, "program")
    if spec.engine not in _ENGINES:
        raise LaunchError(f"engine must be one of {', '.join(_ENGINES)}")
    if spec.platform not in _PLATFORMS:
        raise LaunchError(f"platform must be one of {', '.join(_PLATFORMS)}")
    if not 1 <= spec.rounds <= _MAX_ROUNDS:
        raise LaunchError(f"rounds must be between 1 and {_MAX_ROUNDS}")
    if len(spec.scope_note) > 20_000:
        raise LaunchError("scope note is too long (20000 char limit)")
    if spec.out_of_scope:
        _no_flag(spec.out_of_scope, "out-of-scope list")
        if len(spec.out_of_scope) > 2000:
            raise LaunchError("out-of-scope list is too long")
    clean: dict[str, str] = {}
    for name, token in spec.identities.items():
        name = name.strip().lower()
        if not token:
            continue
        if not _IDENT_NAME_OK.match(name):
            raise LaunchError(f"identity name {name!r} must be letters, digits or underscore")
        if len(token) > 8000:
            raise LaunchError(f"identity {name!r} token is implausibly long")
        clean[name] = token
    spec.identities = clean
    return spec


def engagement_name(program: str) -> str:
    """The folder a run lands in. Mirrors p1hunt.main's derivation exactly."""
    return "".join(c if c.isalnum() else "-" for c in program.lower())[:40] or "engagement"


def _child_env(spec: LaunchSpec) -> dict:
    """The child's environment: where credentials go, because argv is world-readable.

    `_identities_from_env` in main.py turns each P1HUNT_TOKEN_<NAME> into a TestIdentity
    that references the variable by NAME, so the token value is never written into
    scope.json or any other artifact.
    """
    env = dict(os.environ)
    env["P1HUNT_ENGINE"] = spec.engine
    env["P1HUNT_RUN_MODE"] = "active"
    for name, token in spec.identities.items():
        key = "P1HUNT_TOKEN" if name in ("", "default") else f"P1HUNT_TOKEN_{name.upper()}"
        env[key] = token
    # A broken third-party pytest plugin would kill every proof harness. The runner
    # already self-heals per-subprocess; this makes the hunt's own preflight agree.
    return env


def build_argv(spec: LaunchSpec, *, scope_note_file: Path | None = None) -> list[str]:
    """The exact command. A fixed template -- operator values only in value positions.

    The scope note is passed as a FILE PATH, never as text. `ps` shows every argument to
    every user on the machine, and a note pasted from a program page can carry account
    details or internal hostnames. A smoke test of this launcher put the note in argv and
    a grep for the test's own token strings matched it, which is how this got noticed.
    """
    argv = [
        sys.executable, "-m", "p1hunt.main", "hunt", spec.target,
        "--web",
        "--program", spec.program,
        "--platform", spec.platform,
        "--live-env", "bounty",
        "--engine", spec.engine,
        "--max-rounds", str(spec.rounds),
    ]
    if scope_note_file is not None:
        argv += ["--scope-note-file", str(scope_note_file)]
    if spec.out_of_scope:
        argv += ["--out-of-scope", spec.out_of_scope]
    return argv


def preflight(engine: str = "") -> dict:
    """`p1hunt doctor` as JSON, for the console to render before anything is spent."""
    from ..doctor import run_doctor

    try:
        rep = run_doctor(engine=engine or None, skip_browser=False)
    except Exception as exc:  # a diagnostic must never be the thing that breaks
        return {"go": False, "error": str(exc)[:300], "checks": []}
    return {
        "go": rep.go,
        "engine": engine,
        "checks": [
            {"name": c.name, "verdict": c.verdict, "detail": c.detail,
             "fix": c.fix, "impact": c.impact}
            for c in rep.checks
        ],
        "failures": [c.name for c in rep.failures],
        "warnings": [c.name for c in rep.warnings],
    }


def launch(spec_dict: dict, *, root: Path | None = None) -> dict:
    """Validate, preflight, spawn. Returns what the console needs to follow the run."""
    spec = validate(LaunchSpec.from_dict(spec_dict))

    pre = preflight(spec.engine)
    if not pre.get("go") and not spec.force:
        return {
            "ok": False, "blocked": "preflight",
            "error": "preflight says NO-GO: a hunt started now could not produce a "
                     "confirmed finding, and it would still report success. Fix the "
                     "failing checks, or re-submit with force to run anyway.",
            "preflight": pre,
        }

    root = Path(root or os.environ.get("P1HUNT_ENGAGEMENTS", "engagements"))
    name = engagement_name(spec.program)
    eng_dir = root / name
    # Refuse to silently resume into or overwrite a live engagement: the operator would
    # read the mixed event stream as one run.
    events = eng_dir / "events.jsonl"
    if events.is_file() and (time.time() - events.stat().st_mtime) < 90:
        raise LaunchError(
            f"engagement {name!r} looks live (its event stream was written to in the last "
            f"90 seconds). Stop it first, or use a different program name.")

    repo = Path(__file__).resolve().parents[2]
    eng_dir.mkdir(parents=True, exist_ok=True)
    # Written with owner-only permissions: it is the operator's rules-of-engagement text,
    # which can name internal hosts and test accounts.
    note_file: Path | None = None
    if spec.scope_note.strip():
        note_file = eng_dir / "scope_note.txt"
        try:
            note_file.write_text(spec.scope_note, encoding="utf-8")
            note_file.chmod(0o600)
        except OSError as exc:
            raise LaunchError(f"cannot write {note_file}: {exc}") from exc

    argv = build_argv(spec, scope_note_file=note_file)
    if not shutil.which(argv[0]) and not Path(argv[0]).exists():
        raise LaunchError(f"python interpreter not found at {argv[0]}")
    log_path = eng_dir / "launch.log"
    try:
        log = log_path.open("ab")
    except OSError as exc:
        raise LaunchError(f"cannot write {log_path}: {exc}") from exc
    try:
        proc = subprocess.Popen(  # noqa: S603 — fixed argv, shell=False, flags refused
            argv, cwd=str(repo), env=_child_env(spec),
            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True,   # survives the console being closed
        )
    except OSError as exc:
        log.close()
        raise LaunchError(f"could not start the hunt: {exc}") from exc

    # The attestation and the redacted launch record, for the engagement's own history.
    # Token VALUES are never written; only which identity names were supplied.
    record = {
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": proc.pid,
        "target": spec.target,
        "hosts": list(spec.hosts),
        "program_url": spec.program_url,
        "program": spec.program,
        "platform": spec.platform,
        "engine": spec.engine,
        "rounds": spec.rounds,
        "identities": sorted(spec.identities),
        "identity_token_lengths": {k: len(v) for k, v in spec.identities.items()},
        "authorized_attested": True,
        "forced_past_preflight": bool(spec.force and not pre.get("go")),
        "preflight_go": bool(pre.get("go")),
        "preflight_failures": pre.get("failures", []),
        "source": "web console",
    }
    try:
        (eng_dir / "launch.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    except OSError:
        pass
    return {"ok": True, "engagement": name, "pid": proc.pid,
            "log": str(log_path), "launch": record, "preflight": pre}
