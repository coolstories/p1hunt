"""Entrypoint enumeration for the round-over-round coverage loop — for EVERY target class.

The coverage ledger (:mod:`p1hunt.corpus`) is what makes rounds COMPOUND: it remembers which
entrypoints a campaign already reached and ``uncovered_hint`` steers the next round at the ones
still dark. That loop only ever worked for EVM targets, because only EVM had an enumerator
(``detect_evm_entrypoints``). For a web/API target the entrypoint list came back empty, so
``uncovered_hint`` returned "" and every round re-explored whatever it happened to look at first.
Nothing accumulated — the exact failure the corpus exists to prevent.

This module supplies the missing half: a generic, PURE, static enumeration of the entrypoints a
non-EVM target exposes, plus one dispatcher (:func:`entrypoints_for`) that returns the right
attack surface for whatever class the target is.

What it reads is DECLARED SURFACE, not bug classes: an HTTP verb plus a path literal, an
operation in an API schema, a file-system route. It carries no vulnerability patterns, no CWE
list, and no target literals — the same category of plumbing as grepping Solidity for
``external``/``public``, which is the precedent it follows.

Pure (reads files only, never raises), bounded, and deterministic.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

# Directories that are not the in-scope deployed surface.
_IGNORE_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "out", "target",
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache",
    "coverage", ".next", ".nuxt", "bower_components", "site-packages", ".p1hunt-poc",
    "test", "tests", "spec", "specs", "__tests__", "fixtures", "mocks", "examples",
})

_SRC_EXTS = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java",
    ".kt", ".cs", ".rs", ".ex", ".exs", ".scala", ".swift",
})
_SCHEMA_EXTS = frozenset({".json", ".yaml", ".yml", ".graphql", ".gql"})

_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options", "all", "any")

# --- generic route-declaration shapes -------------------------------------------------------
# Each pattern matches "an HTTP verb bound to a path literal" in one of the broad syntactic
# families frameworks use. They are grammar, not product knowledge.

# router.get("/a/b", ...) / app.post('/x', ...) / r.Handle("/y") — method-call style
_CALL_ROUTE = re.compile(
    r"""(?:^|[\s.;({\[])(?P<verb>get|post|put|patch|delete|head|options|all|any)\s*\(\s*"""
    r"""(?P<quote>['"`])(?P<path>/[^'"`\s]*)(?P=quote)""",
    re.IGNORECASE | re.VERBOSE,
)

# @app.get("/a") / @GetMapping("/b") / #[get("/c")] — decorator/annotation/attribute style
_DECORATED_ROUTE = re.compile(
    # NOTE: '#' is escaped — re.VERBOSE would otherwise read it as a comment and swallow the rest.
    r"""(?:@|\#\[)\s*[\w.]*?(?P<verb>get|post|put|patch|delete|head|options)\w*\s*"""
    r"""(?:Mapping)?\s*\(\s*(?:(?:path|value|route)\s*=\s*)?(?P<quote>['"`])(?P<path>/[^'"`\s]*)(?P=quote)""",
    re.IGNORECASE | re.VERBOSE,
)

# path("a/b", view) / route("/c", ...) / Route::get('/d', ...) — table/registration style
_TABLE_ROUTE = re.compile(
    r"""(?:^|[\s.;({\[])(?:path|route|url|add_route|add_url_rule|handle|handleFunc)\s*\(\s*"""
    r"""(?P<quote>['"`])(?P<path>/?[A-Za-z0-9_\-./:{}<>*]+)(?P=quote)""",
    re.IGNORECASE | re.VERBOSE,
)

# GraphQL schema operations: the root types ARE the API surface.
_GQL_BLOCK = re.compile(
    r"\b(?:type|extend\s+type)\s+(?P<root>Query|Mutation|Subscription)\b[^{]*\{(?P<body>[^}]*)\}",
    re.IGNORECASE,
)
_GQL_FIELD = re.compile(r"^\s*(?P<name>[A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:", re.MULTILINE)

# File-system routing: a directory tree where the PATH is the route.
_FS_ROUTE_ROOTS = ("pages/api", "app/api", "src/pages/api", "src/app/api", "routes", "src/routes")
_FS_ROUTE_FILES = frozenset({"route", "index", "handler", "server", "+server", "page"})

_DEFAULT_LIMIT = 60
_MAX_FILES = 1200
_MAX_BYTES = 400_000


def _norm_path(raw: str) -> str:
    """Normalize a route path for stable, de-duplicated coverage keys.

    Parameter names are collapsed to a single placeholder so ``/doc/:id``, ``/doc/{docId}`` and
    ``/doc/[slug]`` are ONE entrypoint. Without this, coverage would never match across rounds
    and the hint would keep re-steering at code already covered."""

    text = str(raw or "").strip()
    if not text:
        return ""
    text = text.split("?")[0].split("#")[0]
    if not text.startswith("/"):
        text = "/" + text
    text = re.sub(r":[A-Za-z_]\w*", "{p}", text)
    text = re.sub(r"\{[^}]*\}", "{p}", text)
    text = re.sub(r"<[^>]*>", "{p}", text)
    text = re.sub(r"\[\.{3}[^\]]*\]", "{p}", text)
    text = re.sub(r"\[[^\]]*\]", "{p}", text)
    text = re.sub(r"\*+", "{p}", text)
    text = re.sub(r"/{2,}", "/", text)
    if len(text) > 1:
        text = text.rstrip("/")
    return text or "/"


def _candidate_files(
    repo_path: str, focus_files: Iterable[str] | None, exts: frozenset[str]
) -> list[Path]:
    """In-scope files with a matching extension. Honors ``focus_files`` when it yields anything."""

    root = Path(repo_path)
    if focus_files:
        picked: list[Path] = []
        for name in focus_files:
            try:
                path = Path(name) if Path(name).is_absolute() else (root / name)
            except (OSError, ValueError):
                continue
            try:
                if path.suffix.lower() in exts and path.is_file():
                    picked.append(path)
            except OSError:
                continue
        if picked:
            return picked
    try:
        if not root.exists():
            return []
    except OSError:
        return []
    out: list[Path] = []
    try:
        for path in sorted(root.rglob("*")):
            if len(out) >= _MAX_FILES:
                break
            try:
                if not path.is_file() or path.suffix.lower() not in exts:
                    continue
                rel = path.relative_to(root)
            except (OSError, ValueError):
                continue
            if any(part in _IGNORE_DIRS or part.startswith(".") for part in rel.parts[:-1]):
                continue
            out.append(path)
    except OSError:
        return out
    return out


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > _MAX_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def detect_route_entrypoints(
    repo_path: str, focus_files: Iterable[str] | None = None, *, limit: int = _DEFAULT_LIMIT
) -> list[str]:
    """Declared HTTP routes in the in-scope source, as ``VERB /normalized/path``. PURE.

    De-duplicated and deterministic. Returns [] on a missing path or a target with no declared
    routes; never raises."""

    cap = max(1, int(limit))
    found: list[str] = []
    seen: set[str] = set()
    for path in _candidate_files(repo_path, focus_files, _SRC_EXTS):
        text = _read(path)
        if not text or "/" not in text:
            continue
        for pattern in (_DECORATED_ROUTE, _CALL_ROUTE, _TABLE_ROUTE):
            for match in pattern.finditer(text):
                raw = match.group("path")
                route = _norm_path(raw)
                if not route:
                    continue
                try:
                    verb = (match.group("verb") or "").upper()
                except IndexError:
                    verb = ""
                if not verb:
                    verb = "ANY"
                if verb.lower() not in _HTTP_VERBS:
                    continue
                entry = f"{verb} {route}"
                if entry in seen:
                    continue
                seen.add(entry)
                found.append(entry)
                if len(found) >= cap:
                    return found
    return found


def detect_schema_entrypoints(
    repo_path: str, focus_files: Iterable[str] | None = None, *, limit: int = _DEFAULT_LIMIT
) -> list[str]:
    """Operations declared in an API schema shipped with the target: OpenAPI paths and GraphQL
    root fields. PURE; tolerates malformed schemas by skipping them."""

    cap = max(1, int(limit))
    found: list[str] = []
    seen: set[str] = set()
    for path in _candidate_files(repo_path, focus_files, _SCHEMA_EXTS):
        text = _read(path)
        if not text:
            continue
        for entry in _openapi_entries(text) + _graphql_entries(text):
            if entry in seen:
                continue
            seen.add(entry)
            found.append(entry)
            if len(found) >= cap:
                return found
    return found


def _openapi_entries(text: str) -> list[str]:
    """``VERB /path`` for each operation in an OpenAPI/Swagger document (JSON only — parsed, not
    guessed, so a YAML schema is simply skipped rather than mis-read without a YAML dependency)."""

    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return []
    if '"paths"' not in text and "'paths'" not in text:
        return []
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(doc, dict):
        return []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    out: list[str] = []
    for raw_path, operations in paths.items():
        route = _norm_path(str(raw_path))
        if not route:
            continue
        if isinstance(operations, dict):
            verbs = [v for v in operations if str(v).lower() in _HTTP_VERBS]
        else:
            verbs = []
        if not verbs:
            out.append(f"ANY {route}")
            continue
        for verb in verbs:
            out.append(f"{str(verb).upper()} {route}")
    return out


def _graphql_entries(text: str) -> list[str]:
    """``GQL Query.field`` for each root operation in a GraphQL SDL document."""

    if "type" not in text.lower():
        return []
    out: list[str] = []
    for block in _GQL_BLOCK.finditer(text):
        root = (block.group("root") or "").strip().title()
        for field in _GQL_FIELD.finditer(block.group("body") or ""):
            name = (field.group("name") or "").strip()
            if not name or name.lower() in ("type", "extend"):
                continue
            out.append(f"GQL {root}.{name}")
    return out


def detect_fs_route_entrypoints(
    repo_path: str, *, limit: int = _DEFAULT_LIMIT
) -> list[str]:
    """Routes declared by FILE SYSTEM position (a directory tree whose paths are the routes). PURE."""

    cap = max(1, int(limit))
    root = Path(repo_path)
    out: list[str] = []
    seen: set[str] = set()
    for route_root in _FS_ROUTE_ROOTS:
        base = root / route_root
        try:
            if not base.is_dir():
                continue
        except OSError:
            continue
        try:
            for path in sorted(base.rglob("*")):
                try:
                    if not path.is_file() or path.suffix.lower() not in _SRC_EXTS:
                        continue
                    rel = path.relative_to(base)
                except (OSError, ValueError):
                    continue
                if any(part in _IGNORE_DIRS or part.startswith(".") for part in rel.parts[:-1]):
                    continue
                parts = list(rel.parts[:-1])
                stem = rel.stem
                if stem.lower() not in _FS_ROUTE_FILES:
                    parts.append(stem)
                route = _norm_path("/" + "/".join(parts))
                entry = f"ANY {route}"
                if entry in seen:
                    continue
                seen.add(entry)
                out.append(entry)
                if len(out) >= cap:
                    return out
        except OSError:
            continue
    return out


def detect_web_entrypoints(
    repo_path: str, focus_files: Iterable[str] | None = None, *, limit: int = _DEFAULT_LIMIT
) -> list[str]:
    """The full declared HTTP/API surface of a non-EVM target. PURE; never raises.

    Combines explicit route declarations, API-schema operations, and file-system routing, in that
    order of trust: an explicitly declared route is the most reliable statement of surface."""

    cap = max(1, int(limit))
    out: list[str] = []
    seen: set[str] = set()
    for source in (
        lambda: detect_route_entrypoints(repo_path, focus_files, limit=cap),
        lambda: detect_schema_entrypoints(repo_path, focus_files, limit=cap),
        lambda: detect_fs_route_entrypoints(repo_path, limit=cap),
    ):
        try:
            entries = source()
        except Exception:
            entries = []
        for entry in entries:
            if entry in seen:
                continue
            seen.add(entry)
            out.append(entry)
            if len(out) >= cap:
                return out
    return out


def entrypoints_for(
    target_class: object,
    repo_path: str,
    focus_files: Iterable[str] | None = None,
    *,
    limit: int = _DEFAULT_LIMIT,
    live_surface: dict | None = None,
    leads: list | None = None,
) -> list[str]:
    """The attack surface for ANY target class — the dispatcher the coverage loop should call.

    EVM targets keep the existing Solidity signature enumeration; every other class now gets a
    real surface list instead of ``[]``, which is what lets ``CorpusStore.uncovered_hint`` steer
    round N+1 at what round N never reached. Offline-graceful: an unreadable repo or an import
    problem degrades to [] rather than raising into the hunt loop."""

    name = getattr(target_class, "value", target_class)
    cls = str(name or "").strip().upper()
    focus = list(focus_files or [])
    # A BLACK-BOX target has no repository, so every source below yields nothing and the
    # coverage loop starves: there is nothing to mark uncovered, nothing for the ledger to
    # retire, nowhere for escalation to go. Persistence needs something to be persistent
    # ABOUT. A surface derived from the LIVE target (dynamic.recon.discover) fills that
    # gap in the same "METHOD /path" shape, so every existing mechanism works unchanged.
    #
    # It is checked FIRST because when it exists it is strictly better evidence than a
    # repo guess: these are paths the application was observed serving.
    if live_surface or leads:
        try:
            from ..dynamic.recon import entrypoints_from_surface

            live = entrypoints_from_surface(live_surface or {}, limit=limit, leads=leads)
        except Exception:
            live = []
        if live:
            return live
    if cls == "EVM_CONTRACT":
        try:
            from .harness_scaffold import detect_evm_entrypoints

            return detect_evm_entrypoints(repo_path, focus or None, limit=limit)
        except Exception:
            return []
    try:
        return detect_web_entrypoints(repo_path, focus or None, limit=limit)
    except Exception:
        return []


def covered_from_paths(paths: Iterable[str]) -> list[str]:
    """Turn observed route/file touches into coverage symbols the corpus can match.

    A ROUTE-shaped touch (``GET /doc/{p}``) is passed through VERBATIM, because the corpus keys
    routes on the whole normalized string — contributing only its path segments would mark every
    route sharing a segment as covered. Anything else contributes its identifier tokens, which is
    what a fuzzer's free-form symbol report looks like."""

    out: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        key = value.lower()
        if not value or key in seen:
            return
        seen.add(key)
        out.append(value)

    for raw in paths or ():
        text = " ".join(str(raw or "").split())
        if not text:
            continue
        if "/" in text:
            _add(text)
        for token in re.split(r"[^A-Za-z0-9_]+", text):
            if len(token) < 2:
                continue
            _add(token)
    return out
