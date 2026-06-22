"""`python -m p1hunt.web [--host H] [--port P]` — launch the Threat Operations Center."""

from __future__ import annotations

import argparse
import sys

from .server import serve


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="p1hunt.web", description="P1HUNT Threat Operations Center (read-only web dashboard).")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default loopback)")
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args(argv)
    return serve(a.host, a.port)


if __name__ == "__main__":
    sys.exit(main())
