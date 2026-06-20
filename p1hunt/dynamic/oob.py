"""Out-of-band interaction listener — confirms BLIND vulnerabilities (spec §10).

Blind SSRF, blind injection, XXE, and webhook/callback bugs leave no trace in the HTTP response;
the proof is that the *target* reached back out to an attacker-controlled endpoint. This module
runs a tiny loopback HTTP server (127.0.0.1 only) that records every callback it receives, keyed
by the unique token embedded in the path. A harness gives the target an OOB URL carrying a token,
performs the action, then asserts (via the shipped client's ``oob_received``) that the token was
hit — turning a blind bug into a deterministically reproduced one.

Loopback-only and append-only: it never makes an outbound request and stores only the callback's
path/time/source (least-data, §9). Offline-graceful — if it cannot bind, arming continues without
OOB and blind-only findings simply stay candidates.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class OOBListener:
    """A running loopback callback collector. ``url`` is the base an OOB token is appended to."""

    def __init__(self, server: ThreadingHTTPServer, hits_path: Path, thread: threading.Thread) -> None:
        self._server = server
        self.hits_path = hits_path
        self._thread = thread
        host, port = server.server_address[:2]
        self.url = f"http://127.0.0.1:{port}"

    def stop(self) -> None:
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass


def start_oob_listener(hits_path: str | Path) -> OOBListener | None:
    """Start the loopback OOB collector writing one JSON line per callback to ``hits_path``.
    Returns the listener, or None if it cannot bind (the hunt proceeds without OOB)."""
    hits = Path(hits_path)
    try:
        hits.parent.mkdir(parents=True, exist_ok=True)
        hits.touch(exist_ok=True)
    except OSError:
        return None

    class _Handler(BaseHTTPRequestHandler):
        def _record(self) -> None:
            rec = {
                "path": self.path,
                "method": self.command,
                "time": time.time(),
                "remote": self.client_address[0] if self.client_address else "",
                "user_agent": self.headers.get("User-Agent", ""),
            }
            try:
                with hits.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec) + "\n")
            except OSError:
                pass
            self.send_response(200)
            self.end_headers()
            try:
                self.wfile.write(b"ok")
            except OSError:
                pass

        do_GET = do_POST = do_PUT = do_HEAD = _record  # any verb is a valid callback

        def log_message(self, *_a) -> None:  # silence the default stderr access log
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    except OSError:
        return None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return OOBListener(server, hits, thread)
