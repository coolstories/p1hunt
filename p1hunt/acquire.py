"""Target acquisition (spec §2.1 step 3, §15.1).

Read-only fetch of the program/scope page and a shallow git clone of the in-scope repo
into the engagement's artifacts/ folder. This is the only place the system reaches the
network, and it does so non-destructively: an HTTP GET of a public program brief and a
read-only clone of an authorized in-scope repository. Nothing else is contacted.
"""

from __future__ import annotations

import re
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class Acquisition:
    artifact_dir: str
    cloned: list[str]
    fetched: list[str]
    notes: list[str]


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t]+")


def looks_like_repo(value: str) -> bool:
    v = value.strip()
    return (
        v.endswith(".git")
        or v.startswith("git@")
        or bool(re.search(r"(github|gitlab|bitbucket|sourcehut|codeberg)\.[a-z]+[:/]", v))
        or (v.startswith(("http://", "https://")) and v.rstrip("/").count("/") >= 4 and "github" in v)
    )


def fetch_text(url: str, *, timeout: float = 15.0, max_bytes: int = 400_000) -> str:
    """Read-only GET of a public page; returns de-tagged text. http/https only."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"refusing non-http(s) fetch: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "p1hunt/0.1 (+safe-harbor research)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (http/https enforced above)
        raw = resp.read(max_bytes)
    text = raw.decode("utf-8", errors="ignore")
    text = _TAG_RE.sub(" ", text)
    text = _WS_RE.sub(" ", text)
    lines = [ln.strip() for ln in text.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def clone_repo(repo_url: str, dest: str | Path, *, depth: int = 1, timeout: float = 180.0) -> str:
    """Shallow, read-only clone. Returns the local path. Raises on failure.

    Submodules are fetched in the same shallow pass (``--recurse-submodules
    --shallow-submodules``). Hardened Solidity/native projects vendor their dependencies as
    git submodules; without them the target cannot compile, and a non-compiling target yields
    nothing from the fuzz/PoC stages. (``build_env.bootstrap_environment`` also runs
    ``git submodule update --init --recursive`` as a belt-and-suspenders for local-path or
    partially-fetched targets.)"""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return str(dest)
    result = subprocess.run(
        ["git", "clone", "--depth", str(depth), "--recurse-submodules", "--shallow-submodules",
         "--quiet", repo_url, str(dest)],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip() or result.stdout.strip()}")
    return str(dest)


def acquire_target(
    in_scope_values: list[str],
    engagement_folder: str | Path,
    *,
    progress=None,
) -> Acquisition:
    """Clone any in-scope repos and resolve local paths into one artifact directory."""
    folder = Path(engagement_folder)
    artifacts = folder / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    cloned: list[str] = []
    notes: list[str] = []

    def _say(msg: str) -> None:
        if progress:
            progress(msg)

    for value in in_scope_values:
        value = value.strip()
        if not value:
            continue
        if looks_like_repo(value):
            name = re.sub(r"[^A-Za-z0-9_.-]", "-", value.rstrip("/").split("/")[-1] or "repo").removesuffix(".git")
            dest = artifacts / name
            try:
                _say(f"cloning {value} ...")
                clone_repo(value, dest)
                cloned.append(str(dest))
                _say(f"cloned -> {dest}")
            except Exception as exc:  # surface, don't crash the engagement
                notes.append(f"clone failed for {value}: {exc}")
                _say(f"clone failed for {value}: {exc}")
        elif Path(value).exists():
            cloned.append(str(Path(value).resolve()))
            notes.append(f"using local path {value}")
        else:
            notes.append(f"asset '{value}' is not a repo URL or local path — treated as a label")

    # The artifact dir is the single clone if there's exactly one, else the artifacts folder.
    artifact_dir = cloned[0] if len(cloned) == 1 else str(artifacts)
    return Acquisition(artifact_dir=artifact_dir, cloned=cloned, fetched=[], notes=notes)
