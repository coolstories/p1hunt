"""Stdlib HTTP server for the P1HUNT Threat Operations Center (read-only, loopback).

Endpoints:
  GET /                         -> the dashboard (static/index.html)
  GET /app.css /app.js          -> static assets
  GET /api/engagements          -> [{id, program, mtime, confirmed, candidates, running}]
  GET /api/tail?eng=ID&offset=N -> {offset, events:[{ts,agent,kind,data}], findings, running}

The UI does all aggregation/formatting client-side from the raw event stream, so the server stays
thin: it only tails ``events.jsonl`` from a byte offset and ships ``findings.json``. Nothing here
mutates an engagement; it is a viewer. Bind address defaults to 127.0.0.1.
"""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

_STATIC = Path(__file__).parent / "static"
# Cap how much of events.jsonl we ship in one tail (bytes) so a huge backlog can't stall the page.
_MAX_TAIL_BYTES = 4_000_000
_RUNNING_WINDOW_S = 90.0  # events.jsonl touched within this window => engagement is "live"


def _engagements_root() -> Path:
    return Path(os.environ.get("P1HUNT_ENGAGEMENTS", "engagements"))


def _safe_eng_dir(eng: str) -> Path | None:
    """Resolve an engagement id to its folder, refusing any path escape."""
    root = _engagements_root().resolve()
    if not eng:
        return None
    cand = (root / eng).resolve()
    try:
        cand.relative_to(root)
    except ValueError:
        return None
    return cand if (cand / "events.jsonl").exists() else None


def _list_engagements() -> list[dict]:
    root = _engagements_root()
    out: list[dict] = []
    if not root.exists():
        return out
    for d in sorted(root.iterdir(), key=lambda p: -p.stat().st_mtime if p.exists() else 0):
        ev = d / "events.jsonl"
        if not ev.is_file():
            continue
        program, confirmed, candidates = d.name, 0, 0
        fj = d / "findings.json"
        if fj.is_file():
            try:
                doc = json.loads(fj.read_text(encoding="utf-8"))
                program = doc.get("program", d.name)
                c = doc.get("counts", {})
                confirmed = c.get("confirmed_critical", 0)
                candidates = c.get("candidates", 0)
            except (OSError, ValueError):
                pass
        mtime = ev.stat().st_mtime
        out.append({"id": d.name, "program": program, "mtime": mtime,
                    "confirmed": confirmed, "candidates": candidates,
                    "running": (time.time() - mtime) < _RUNNING_WINDOW_S})
    return out


def _tail(eng_dir: Path, offset: int) -> dict:
    ev = eng_dir / "events.jsonl"
    size = ev.stat().st_size
    if offset <= 0 or offset > size:
        # First load (or rotated): jump near the end so the page paints fast, not from byte 0.
        offset = max(0, size - _MAX_TAIL_BYTES)
    events: list[dict] = []
    try:
        with ev.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            chunk = fh.read(_MAX_TAIL_BYTES)
            new_offset = fh.tell()
        # Drop a possible partial last line (no trailing newline yet).
        lines = chunk.split("\n")
        if chunk and not chunk.endswith("\n"):
            partial = lines.pop()
            new_offset -= len(partial.encode("utf-8", "replace"))
        for ln in lines:
            ln = ln.strip()
            if ln:
                try:
                    events.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
    except OSError:
        new_offset = offset
    findings = None
    fj = eng_dir / "findings.json"
    if fj.is_file():
        try:
            doc = json.loads(fj.read_text(encoding="utf-8"))
            # Bound candidate payload so the tail stays light.
            if isinstance(doc.get("candidates"), list):
                doc["candidates"] = doc["candidates"][-60:]
            findings = doc
        except (OSError, ValueError):
            findings = None
    running = (time.time() - ev.stat().st_mtime) < _RUNNING_WINDOW_S
    return {"offset": new_offset, "events": events, "findings": findings, "running": running}


_CT = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
       ".js": "application/javascript; charset=utf-8", ".svg": "image/svg+xml"}


class _Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _static(self, name: str) -> None:
        p = (_STATIC / name).resolve()
        try:
            p.relative_to(_STATIC.resolve())
        except ValueError:
            return self._send(403, b"forbidden", "text/plain")
        if not p.is_file():
            return self._send(404, b"not found", "text/plain")
        self._send(200, p.read_bytes(), _CT.get(p.suffix, "application/octet-stream"))

    def _stream(self, eng_dir: Path, offset: int) -> None:
        """Server-Sent Events: push each new line of events.jsonl in ~real time, plus findings.json
        when it changes. Each line carries ``id:`` = the byte offset AFTER it, so an EventSource
        reconnect (Last-Event-ID) resumes exactly where it left off — no gaps, no replays."""
        ev = eng_dir / "events.jsonl"
        fj = eng_dir / "findings.json"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")  # disable any proxy buffering
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

        def w(s: str) -> None:
            self.wfile.write(s.encode("utf-8", "replace"))
            self.wfile.flush()

        try:
            size = ev.stat().st_size
            if offset <= 0 or offset > size:
                offset = max(0, size - _MAX_TAIL_BYTES)  # first paint: jump near the tail
            last_fmtime = 0.0
            idle = 0
            while True:
                cur = ev.stat().st_size
                if cur > offset:
                    with ev.open("r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(offset)
                        chunk = fh.read(min(cur - offset, _MAX_TAIL_BYTES))
                    parts = chunk.split("\n")
                    pos = offset
                    for ln in parts[:-1]:  # last element is "" (complete) or a partial line — skip it
                        pos += len((ln + "\n").encode("utf-8", "replace"))
                        s = ln.strip()
                        if s:
                            w(f"id: {pos}\ndata: {s}\n\n")
                    offset = pos
                    idle = 0
                else:
                    idle += 1
                try:  # ship findings.json when it changes
                    m = fj.stat().st_mtime
                    if m > last_fmtime:
                        last_fmtime = m
                        doc = json.loads(fj.read_text(encoding="utf-8"))
                        if isinstance(doc.get("candidates"), list):
                            doc["candidates"] = doc["candidates"][-60:]
                        w("event: findings\ndata: " + json.dumps(doc) + "\n\n")
                except (OSError, ValueError):
                    pass
                running = (time.time() - ev.stat().st_mtime) < _RUNNING_WINDOW_S
                w(f"event: meta\ndata: {{\"running\":{str(running).lower()},\"offset\":{offset}}}\n\n")
                w(": ping\n\n")  # keep-alive
                time.sleep(0.4)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return  # client disconnected — end the stream thread

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path
        if path == "/" or path == "/index.html":
            return self._static("index.html")
        if path in ("/app.css", "/app.js"):
            return self._static(path.lstrip("/"))
        if path == "/api/engagements":
            return self._json(_list_engagements())
        if path == "/api/stream":
            eng_dir = _safe_eng_dir(q.get("eng", [""])[0])
            if eng_dir is None:
                return self._json({"error": "unknown engagement"}, 404)
            lei = self.headers.get("Last-Event-ID")  # browser resume marker (byte offset)
            try:
                offset = int(lei) if lei is not None else int(q.get("offset", ["0"])[0])
            except ValueError:
                offset = 0
            return self._stream(eng_dir, offset)
        if path == "/api/tail":
            eng = (q.get("eng", [""])[0])
            eng_dir = _safe_eng_dir(eng)
            if eng_dir is None:
                return self._json({"error": "unknown engagement"}, 404)
            try:
                offset = int(q.get("offset", ["0"])[0])
            except ValueError:
                offset = 0
            return self._json(_tail(eng_dir, offset))
        self._send(404, b"not found", "text/plain")

    def log_message(self, *_a) -> None:  # silence default access log
        return


def serve(host: str = "127.0.0.1", port: int = 8787) -> int:
    """Run the dashboard until Ctrl-C. Returns a process exit code."""
    root = _engagements_root()
    srv = ThreadingHTTPServer((host, port), _Handler)
    print("\n  P1HUNT // THREAT OPERATIONS CENTER")
    print(f"  ├─ engagements : {root.resolve()}")
    print(f"  ├─ serving     : http://{host}:{port}")
    print("  └─ read-only · loopback · Ctrl-C to stop\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down…")
    finally:
        srv.server_close()
    return 0
