"""A deliberately vulnerable application, for measuring whether p1hunt actually finds bugs.

BINDS 127.0.0.1 ONLY AND MUST NEVER BE DEPLOYED. It exists so the hunt can be scored
against KNOWN ground truth on a machine the operator owns, with no third party involved
and nothing to authorize.

WHY GROUND TRUTH AND DECOYS, TOGETHER
-------------------------------------
Recall alone is a vanity metric: a tool that reports every endpoint "finds" every bug and
is useless, because triage cost is the real constraint in a bounty workflow and a wall of
false positives is indistinguishable from noise. So this range plants nine real defects
AND five decoys that look superficially identical to a keyword matcher but are correctly
implemented. A run is only good if it finds the first set and leaves the second alone.

The planted set deliberately includes the class that a keyword list cannot reach: a
RENDER GATE applied on one host and missed on another. Nothing about the path, the
parameters or the response in isolation looks wrong; only a COMPARISON of two renders
exposes it. That is the shape of the critical this whole design was rebuilt around, and
it is the single most important thing to measure.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# GROUND TRUTH. "planted" = a real defect. "decoy" = correct, must NOT be reported.
# ---------------------------------------------------------------------------
PLANTED = [
    {"id": "idor-account", "path": "/api/v1/accounts/{id}", "class": "idor",
     "insight": "returns any account's data regardless of the session's own account",
     "keys": ["idor", "another", "other account", "second", "identity", "authoriz",
              "object", "horizontal"]},
    {"id": "idor-invoice", "path": "/api/v1/invoices/{id}", "class": "idor",
     "insight": "sequential integer identifier, enumerable with no authorization check",
     "keys": ["enumerat", "sequential", "increment", "idor", "authoriz"]},
    {"id": "authz-admin", "path": "/internal/admin/users", "class": "authz",
     "insight": "privileged endpoint answers with no authentication at all",
     "keys": ["unauthenticat", "anonymous", "no auth", "privileg", "admin", "authoriz"]},
    {"id": "gate-host", "path": "/share/{id}", "class": "render_gate",
     "insight": "the apex gates the unsafe renderer on cookie presence; the mobile host "
                "does not, so the unescaped render is reachable with a session present",
     "keys": ["host", "differen", "compar", "gate", "cookie", "render", "m."]},
    {"id": "xss-reflect", "path": "/search", "class": "injection",
     "insight": "the q parameter is reflected unescaped into character data",
     "keys": ["reflect", "escap", "inject", "xss", "census", "text node", "q="]},
    {"id": "xss-dom", "path": "/preview", "class": "dom_injection",
     "insight": "the fragment/query is written to innerHTML by client script",
     "keys": ["dom", "innerhtml", "client", "sink", "script"]},
    {"id": "redirect-open", "path": "/go", "class": "redirect",
     "insight": "the next parameter accepts an absolute off-origin URL",
     "keys": ["redirect", "off-origin", "off origin", "external", "next", "absolute"]},
    {"id": "ssrf-fetch", "path": "/api/v1/fetch", "class": "ssrf",
     "insight": "the server fetches a caller-supplied URL",
     "keys": ["ssrf", "server-side", "server side", "fetch", "oob", "callback", "internal"]},
    {"id": "secret-session", "path": "/api/v1/session", "class": "secret",
     "insight": "hands the client a long-lived bearer that script on the origin can read",
     "keys": ["token", "bearer", "credential", "secret", "session", "readable"]},
]

DECOYS = [
    # Looks like the IDOR above; actually scoped to the caller.
    {"id": "decoy-scoped", "path": "/api/v1/me/orders/{id}", "why": "scoped to the caller"},
    # Path says admin, but it enforces a role.
    {"id": "decoy-admin", "path": "/admin/reports",
     "why": "enforces a role from the AUTHENTICATED PRINCIPAL, not from a client header"},
    # Reflects input, but into a quoted attribute with the quote escaped: INERT.
    {"id": "decoy-attr", "path": "/profile", "why": "raw <> in a quoted attribute is inert"},
    # A redirect parameter that only accepts relative paths.
    {"id": "decoy-redirect", "path": "/logout", "why": "only accepts a relative path"},
    # A URL-valued parameter the server never fetches.
    {"id": "decoy-url", "path": "/share/link", "why": "url param is echoed, never fetched"},
]

_ACCOUNTS = {
    "550e8400-e29b-41d4-a716-446655440000": {"owner": "alice", "ban": "9981234",
                                              "balance": "412.19"},
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8": {"owner": "bob", "ban": "9985678",
                                              "balance": "88.00"},
}
_SESSION_COOKIE = "range_session"

# REAL PRINCIPALS. The first version of this range had no notion of a caller at all --
# every endpoint answered anyone -- which made the IDOR defects trivially "provable"
# without ever establishing two identities. That is the one thing a real authorization
# proof must do, so a confirmed IDOR here would have meant nothing.
#
# A principal is now named by either `Cookie: range_session=<user>` or
# `Authorization: Bearer <user>`. The bearer form exists so the pipeline's existing
# P1HUNT_TOKEN_A / P1HUNT_TOKEN_B identity plumbing and the web authz harness scaffold
# plug in unchanged.
#
# NONE OF THE PLANTED DEFECTS OR DECOYS CHANGED. /api/v1/accounts/{id} still has no
# ownership check; what changed is that a harness can now SHOW the crossing, by
# establishing which account the caller owns and reading a different one.
_PRINCIPALS = {
    "alice": "550e8400-e29b-41d4-a716-446655440000",
    "bob": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
}
# Roles belong to the PRINCIPAL, never to a request header. See the decoy-admin note.
_ROLES = {"alice": "admin", "bob": "user"}


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;").replace("'", "&#39;"))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # -- helpers ----------------------------------------------------------
    def _send(self, body, status=200, ctype="text/html; charset=utf-8", extra=None):
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj), status, "application/json; charset=utf-8")

    def _q(self, name, default=""):
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        return qs.get(name, [default])[0]

    def _has_session(self):
        # Presence only, deliberately: this is what the gate-host defect keys on, and it
        # is the real behaviour being modelled -- an edge worker routing on the mere
        # presence of a cookie whose value it never validates.
        return _SESSION_COOKIE in (self.headers.get("Cookie") or "")

    def _principal(self):
        """The authenticated user, or "" for anonymous. Bearer OR session cookie."""
        auth = (self.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            if tok in _PRINCIPALS:
                return tok
        cookie = self.headers.get("Cookie") or ""
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == _SESSION_COOKIE and v.strip() in _PRINCIPALS:
                return v.strip()
        return ""

    def _is_mobile_host(self):
        # The range fakes "a sibling host" with a header, because a loopback server
        # cannot own two real hostnames. The DEFECT is identical in shape: one route
        # applies the gate, the other does not.
        host = (self.headers.get("X-Range-Host") or self.headers.get("Host") or "")
        return host.startswith("m.")

    def _page(self, body, extra_head=""):
        return ("<!doctype html><html><head><meta charset=utf-8><title>Range</title>"
                f"{extra_head}</head><body>{body}</body></html>")

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        page = urllib.parse.urlsplit(self.path).path

        if page == "/":
            return self._send(self._page(
                '<h1>Range</h1>'
                '<script src="/static/app.js"></script>'
                '<a href="/search?q=hello">search</a> '
                '<a href="/profile?name=me">profile</a> '
                '<a href="/preview">preview</a> '
                '<a href="/share/550e8400-e29b-41d4-a716-446655440000">a share</a> '
                '<a href="/login?user=alice">sign in</a> '
                '<a href="/go?next=/">continue</a> '
                '<a href="/logout?next=/">logout</a>'
                '<form action="/api/v1/pay" method="post">'
                '<input name="amount"><input name="account_id"></form>'))

        if page == "/static/app.js":
            # The bundle: the application's real API client. This is the richest
            # recon source and it names endpoints no link exposes.
            js = (
                'const B="";'
                'export const getAccount=(id)=>fetch("/api/v1/accounts/"+id);'
                'export const getInvoice=(n)=>fetch("/api/v1/invoices/"+n);'
                'export const myOrder=(id)=>fetch("/api/v1/me/orders/"+id);'
                'export const session=()=>fetch("/api/v1/session");'
                'export const me=()=>fetch("/api/v1/me");'
                'export const grab=(u)=>fetch("/api/v1/fetch?url="+encodeURIComponent(u));'
                'const ADMIN="/internal/admin/users", REPORTS="/admin/reports";'
                'const SHARELINK="/share/link";'
                'routes=[{path:"/search"},{path:"/preview"},{path:"/profile"},'
                '{path:"/share/:id"}];'
                'query AccountSummary($id:ID){balance}'
                'mutation TransferFunds($to:ID,$amt:Float){ok}'
            )
            return self._send(js, 200, "application/javascript; charset=utf-8")

        # Sign in as a named principal. Not a defect: it is how a harness establishes
        # the two identities an authorization proof needs.
        if page == "/login":
            who = self._q("user")
            if who not in _PRINCIPALS:
                return self._json({"error": "unknown user", "users": sorted(_PRINCIPALS)}, 400)
            return self._send(self._page(f"<p>signed in as {_esc(who)}</p>"), 200,
                              "text/html; charset=utf-8",
                              {"Set-Cookie": f"{_SESSION_COOKIE}={who}; Path=/"})

        # Who am I, and which account do I own? The baseline a crossing is measured against.
        if page == "/api/v1/me":
            who = self._principal()
            if not who:
                return self._json({"error": "unauthenticated"}, 401)
            return self._json({"user": who, "account_id": _PRINCIPALS[who]})

        # PLANTED idor-account: no check that the session owns this account.
        if page.startswith("/api/v1/accounts/"):
            acct = page.rsplit("/", 1)[-1]
            data = _ACCOUNTS.get(acct)
            if not data:
                return self._json({"error": "not found"}, 404)
            return self._json({"account_id": acct, **data})

        # PLANTED idor-invoice: sequential integers, no authorization.
        if page.startswith("/api/v1/invoices/"):
            n = page.rsplit("/", 1)[-1]
            if not n.isdigit():
                return self._json({"error": "bad id"}, 400)
            return self._json({"invoice": int(n), "owner": "alice" if int(n) % 2 else "bob",
                               "amount": "120.00", "card_last4": "4242"})

        # DECOY decoy-scoped: same shape as the IDOR above, but CORRECTLY scoped. Order
        # ids are "<user>-<n>", and the server refuses one that is not the caller's. A
        # keyword matcher cannot tell this apart from /api/v1/accounts/{id}; only an
        # actual two-principal request can.
        if page.startswith("/api/v1/me/orders/"):
            who = self._principal()
            if not who:
                return self._json({"error": "unauthenticated"}, 401)
            oid = page.rsplit("/", 1)[-1]
            if not oid.startswith(who + "-"):
                return self._json({"error": "forbidden"}, 403)
            return self._json({"order": oid, "owner": who})

        # PLANTED authz-admin: privileged data with no authentication.
        if page == "/internal/admin/users":
            return self._json({"users": [{"u": "alice", "role": "admin",
                                          "email": "a@example.invalid"},
                                         {"u": "bob", "role": "user"}]})

        # DECOY decoy-admin: enforces a role PROPERLY, from the authenticated principal.
        #
        # THIS WAS A BUG IN THE RANGE, NOT IN THE HUNT, and a real run found it. The first
        # version authorized on `X-Role: admin` -- a CLIENT-SUPPLIED HEADER -- so anyone
        # could send it and get in. A hunter reported exactly that ("trusts spoofable
        # X-Role: admin header ... every real principal is refused") and it was correct:
        # the endpoint was genuinely vulnerable, so it was never a valid decoy, and
        # scoring that report as a false positive would have penalized the tool for being
        # right. A decoy has to actually be safe, or it measures nothing.
        #
        # The role now comes from the principal the request authenticated as, which is not
        # attacker-controlled. The endpoint still LOOKS like the authz-admin defect at
        # /internal/admin/users -- admin in the path, privileged-sounding data -- so it
        # still does its job against a keyword matcher. Only an actual two-principal
        # request can tell them apart.
        if page == "/admin/reports":
            who = self._principal()
            if not who:
                return self._json({"error": "unauthenticated"}, 401)
            if _ROLES.get(who) != "admin":
                return self._json({"error": "forbidden"}, 403)
            return self._json({"reports": []})

        # PLANTED gate-host: the apex gates the unsafe renderer on cookie presence.
        # The mobile host does not gate at all. Only a COMPARISON reveals it.
        if page.startswith("/share/") and page != "/share/link":
            sid = page.rsplit("/", 1)[-1]
            note = _ACCOUNTS.get(sid, {}).get("owner", "guest")
            payload = self._q("note") or f"shared by {note}"
            if self._is_mobile_host() or not self._has_session():
                # UNSAFE renderer: note is emitted raw.
                return self._send(self._page(
                    f'<div id=share><p>{payload}</p></div>'
                    '<script src="/unauth-mweb/light.js"></script>'))
            # SAFE renderer on the apex for a session-bearing viewer.
            return self._send(self._page(f'<div id=share><p>{_esc(payload)}</p></div>'))

        # DECOY decoy-url: echoes a URL, never fetches it.
        if page == "/share/link":
            return self._send(self._page(f'<p>link: {_esc(self._q("url"))}</p>'))

        # PLANTED xss-reflect: reflected unescaped into character data.
        if page == "/search":
            q = self._q("q")
            return self._send(self._page(f'<h2>Results for {q}</h2><p>none</p>'))

        # DECOY decoy-attr: raw <> inside a quoted attribute with the quote escaped.
        #
        # `<` and `>` are left RAW on purpose -- inside a quoted attribute value they are
        # ordinary characters, not tag syntax, so this is inert and a naive `<script>`
        # probe "succeeds" here while proving nothing. That is the whole point of the decoy.
        #
        # ORDER MATTERS, and it was wrong. The first version replaced '"' before '&', so
        # the ampersand it had just introduced got re-escaped and a supplied quote came
        # out as the literal text `&amp;quot;`. Harmless in this direction -- MORE escaped,
        # not less -- but wrong, and worth fixing because the same mistake in the other
        # order is a real double-decode bypass: escape the quote first and then DECODE
        # later, and a supplied `&quot;` becomes a real quote that closes the attribute.
        if page == "/profile":
            name = self._q("name").replace("&", "&amp;").replace('"', "&quot;")
            return self._send(self._page(f'<input id=n value="{name}" readonly>'))

        # PLANTED xss-dom: client script writes the query into innerHTML.
        if page == "/preview":
            return self._send(self._page(
                '<div id=out></div>'
                '<script>var p=new URLSearchParams(location.search);'
                'document.getElementById("out").innerHTML=p.get("body")||"";</script>'))

        # PLANTED redirect-open: accepts an absolute off-origin URL.
        if page == "/go":
            nxt = self._q("next", "/")
            return self._send("", 302, "text/html", {"Location": nxt})

        # DECOY decoy-redirect: relative paths only.
        if page == "/logout":
            nxt = self._q("next", "/")
            if "//" in nxt or ":" in nxt or not nxt.startswith("/"):
                nxt = "/"
            return self._send("", 302, "text/html", {"Location": nxt})

        # PLANTED ssrf-fetch: the SERVER fetches a caller-supplied URL.
        if page == "/api/v1/fetch":
            url = self._q("url")
            if not url:
                return self._json({"error": "url required"}, 400)
            try:
                # NOTE: urllib is imported at MODULE level. A function-local
                # `import urllib.request` here makes `urllib` local to the whole
                # function, so the urllib.parse call on do_GET's first line raises
                # UnboundLocalError and every route 500s.
                with urllib.request.urlopen(url, timeout=3) as r:  # noqa: S310 - the defect
                    body = r.read(400).decode("utf-8", "replace")
                return self._json({"fetched": url, "preview": body})
            except Exception as exc:
                return self._json({"fetched": url, "error": str(exc)[:200]})

        # PLANTED secret-session: hands the client a long-lived bearer.
        if page == "/api/v1/session":
            return self._json({
                "user": "alice",
                "accessToken": "rng_" + "a" * 180,
                "sessionToken": "rngs_" + "b" * 300,
                "expires": "2027-02-13T00:00:00Z",
                "WARNING": "THIS INFORMATION IS SENSITIVE",
            })

        if page == "/unauth-mweb/light.js":
            return self._send("/*lightweight renderer*/", 200,
                              "application/javascript; charset=utf-8")

        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        page = urllib.parse.urlsplit(self.path).path
        try:
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
        except Exception:
            pass
        if page == "/api/v1/pay":
            return self._json({"ok": True, "note": "range stub; nothing charged"})
        return self._json({"error": "not found"}, 404)


class Range:
    def __init__(self, port: int = 0):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    r = Range(8771)
    r._t.start()
    print(f"range on {r.base}  (loopback only; {len(PLANTED)} planted, {len(DECOYS)} decoys)")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        r.stop()
