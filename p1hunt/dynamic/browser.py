"""A scope-jailed real browser for RECON, not just for verifying a guessed PoC.

WHY THIS EXISTS
---------------
``dynamic/client.py`` speaks HTTP. It cannot execute JavaScript, so it cannot see a
single-page application's rendered output, a DOM-based sink, a ``postMessage`` handler,
or a client-side route. An agent limited to it can PROVE a browser bug it already
hypothesized (``runners/web.py`` dispatches a Playwright spec and reads the verdict) but
it cannot DISCOVER one -- it is blind in exactly the class that stored and DOM XSS live
in.

This module closes that gap, and it is built around the specific method that works:

  * BOTH LAYERS, SEPARATELY. ``raw_html`` is the bytes the server sent; ``dom_html`` is
    the document after scripts ran. Server-side escaping is judged on the first and
    DOM-based injection on the second, and conflating them is how a reflected finding
    gets misfiled as DOM or missed entirely.
  * DIFFERENTIAL RENDERING. ``differential()`` fetches the same resource under several
    identities or hosts and reports what CHANGED. A render that differs by host or by
    session state is how a host-level gate miss, an authorization render leak, or an
    unauthenticated funnel surfaces -- and it is a comparison, so it does not depend on
    guessing a payload.
  * AN EXECUTION ORACLE, NOT AN INFERENCE. An init script records calls to ``alert``,
    ``Function``, string ``setTimeout``, ``document.write`` and writes to ``innerHTML``,
    so "script ran" is an observation rather than something deduced from escaping. It
    also captures ``message`` listeners, which are their own bug class.
  * CONTEXT-AWARE VERDICTS via ``htmlctx``: a raw ``<`` is a finding in a text node and
    inert inside a quoted attribute.

SAFETY POSTURE -- READ BEFORE CHANGING THE ROUTE HANDLER
--------------------------------------------------------
A browser is the widest egress primitive in this codebase. It resolves its own DNS,
follows its own redirects, and loads subresources from any origin a page names, none of
which passes through ``client.py``'s jail. ``page.route("**/*")`` is the ONLY chokepoint,
so:

  * It is installed on the CONTEXT before any page exists, so no navigation can precede
    it.
  * It FAILS CLOSED. Any exception inside the handler aborts the request. A handler that
    raised and let the request proceed would be a silent hole.
  * Every request is checked, including subresources and each redirect hop, because the
    allowlist is about packets leaving the machine, not about the address bar.
  * The allowlist is a CEILING, never widened here. A ``base_url`` the operator did not
    authorize raises at construction instead of being added.

The jail is VENDORED (``_norm_host`` / ``_allowed``) for the same reason as in
``client.py``: this file is shipped standalone into the PoC sandbox where no ``p1hunt``
package is importable, and a ``try/except ImportError`` around a jail is a fail-OPEN
path. ``tests/test_browser.py::TestVendoredJailParity`` pins the copy to
``dynamic/egress.py`` so it cannot drift.

Config comes from the environment, same names as ``client.py``:
  P1HUNT_EGRESS_ALLOWLIST, P1HUNT_BASE_URL, P1HUNT_USER_AGENT, P1HUNT_ID_HEADER,
  P1HUNT_EXTRA_HEADERS, P1HUNT_RATE_LIMIT, P1HUNT_BROWSER (chromium|firefox|webkit),
  P1HUNT_BROWSER_HEADLESS (0 to watch it work), P1HUNT_SETTLE_MS.
"""

from __future__ import annotations

import os
import threading
import time
import urllib.parse

try:  # analysis helper; shipped alongside this file into the sandbox
    from . import htmlctx as _H
except ImportError:  # pragma: no cover - standalone (sandbox) import path
    try:
        import htmlctx as _H  # type: ignore
    except ImportError as exc:  # fail CLOSED on a missing analyzer, never silently
        raise RuntimeError(
            "htmlctx is required by browser.py and was not importable. Ship htmlctx.py "
            "alongside this file; do not continue without the escaping analyzer."
        ) from exc


class BrowserScopeError(RuntimeError):
    """A navigation or request was refused because its host is not authorized."""


class BrowserUnavailable(RuntimeError):
    """Playwright or a browser binary is not installed."""


# ---------------------------------------------------------------------------
# Vendored egress jail. Must stay byte-for-byte equivalent in BEHAVIOUR to
# p1hunt.dynamic.egress.normalize_host / url_allowed (pinned by a parity test).
# ---------------------------------------------------------------------------
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"})


def _norm_host(url_or_host: str) -> str:
    """Lowercased hostname, port/userinfo/brackets stripped. VENDORED from egress."""
    if not url_or_host:
        return ""
    s = str(url_or_host).strip()
    if "://" in s:
        s = urllib.parse.urlparse(s).hostname or ""
    else:
        s = s.split("/")[0]
        if "@" in s:
            s = s.rsplit("@", 1)[1]
        if s.startswith("["):
            s = s[1: s.find("]")] if "]" in s else s[1:]
        elif s.count(":") == 1:
            s = s.split(":")[0]
    return s.strip().lower().rstrip(".")


def _allowed(host: str, allowlist) -> bool:
    """True when ``host`` is loopback or equals/is a subdomain of an allowlist entry."""
    h = _norm_host(host)
    if not h:
        return False
    if h in _LOOPBACK or h.endswith(".localhost"):
        return True
    for entry in allowlist or ():
        e = _norm_host(entry)
        if e and (h == e or h.endswith("." + e)):
            return True
    return False


_SAFE_SCHEMES = ("http://", "https://")


def url_allowed(url: str, allowlist) -> tuple[bool, str]:
    """Scope decision for one URL. Fail-closed on anything unparseable or non-HTTP."""
    u = (url or "").strip()
    if not u:
        return False, "empty URL"
    low = u.lower()
    # about:/blank/data:/blob: never leave the machine; they are the browser's own.
    if low.startswith(("about:", "data:", "blob:", "javascript:", "chrome:", "devtools:")):
        return True, "browser-internal scheme (no network egress)"
    if not low.startswith(_SAFE_SCHEMES):
        return False, f"non-HTTP scheme refused: {u.split(':', 1)[0][:20]}"
    host = _norm_host(u)
    if not host:
        return False, "no host in URL"
    if _allowed(host, allowlist):
        return True, f"{host} authorized"
    return False, f"{host} not in egress allowlist"


# ---------------------------------------------------------------------------
# Rate limiting (per host), mirroring client.py's intent: pace to the program's
# stated rate of engagement rather than hammering it.
# ---------------------------------------------------------------------------
class _Bucket:
    def __init__(self, per_minute: float) -> None:
        self.rate = max(0.0, float(per_minute)) / 60.0
        self.cap = max(1.0, min(5.0, max(0.0, float(per_minute))))
        self._tokens: dict[str, float] = {}
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def take(self, host: str, *, sleep=time.sleep, now=time.monotonic) -> float:
        if self.rate <= 0:
            return 0.0
        key = _norm_host(host)
        if key in _LOOPBACK or key.endswith(".localhost"):
            return 0.0
        with self._lock:
            t = now()
            last = self._last.get(key, t)
            tok = min(self.cap, self._tokens.get(key, self.cap) + (t - last) * self.rate)
            self._last[key] = t
            if tok >= 1.0:
                self._tokens[key] = tok - 1.0
                return 0.0
            wait = (1.0 - tok) / self.rate
            self._tokens[key] = 0.0
            self._last[key] = t + wait
        sleep(wait)
        return wait


# ---------------------------------------------------------------------------
# The in-page oracle. Observation, not inference.
# ---------------------------------------------------------------------------
_ORACLE_JS = r"""
(() => {
  if (window.__p1hunt) return;
  const rec = { exec: [], sinks: [], listeners: [], errors: [] };
  try {
    Object.defineProperty(window, '__p1hunt', {
      value: rec, writable: false, enumerable: false, configurable: false
    });
  } catch (e) { window.__p1hunt = rec; }

  const cap = (v) => { try { return String(v).slice(0, 400); } catch (e) { return '<unstringifiable>'; } };
  const note = (kind, detail) => { try { rec.exec.push({ kind: kind, detail: cap(detail) }); } catch (e) {} };
  const sink = (name, value) => { try { rec.sinks.push({ sink: name, value: cap(value) }); } catch (e) {} };

  // --- execution proof -----------------------------------------------------
  ['alert', 'confirm', 'prompt'].forEach((fn) => {
    try {
      window[fn] = function () {
        note('dialog:' + fn, arguments[0]);
        return fn === 'confirm' ? true : (fn === 'prompt' ? '' : undefined);
      };
    } catch (e) {}
  });
  try {
    const OF = window.Function;
    const WF = function () { note('Function', arguments[arguments.length - 1]); return OF.apply(this, arguments); };
    WF.prototype = OF.prototype;
    window.Function = WF;
  } catch (e) {}
  ['setTimeout', 'setInterval'].forEach((fn) => {
    try {
      const orig = window[fn];
      window[fn] = function (h) {
        if (typeof h === 'string') note(fn + '(string)', h);
        return orig.apply(window, arguments);
      };
    } catch (e) {}
  });

  // --- dangerous write sinks ----------------------------------------------
  const hookProp = (obj, prop, label) => {
    try {
      const d = Object.getOwnPropertyDescriptor(obj, prop);
      if (!d || !d.set) return;
      Object.defineProperty(obj, prop, {
        configurable: true, enumerable: d.enumerable, get: d.get,
        set: function (v) { sink(label, v); return d.set.call(this, v); }
      });
    } catch (e) {}
  };
  hookProp(Element.prototype, 'innerHTML', 'Element.innerHTML');
  hookProp(Element.prototype, 'outerHTML', 'Element.outerHTML');
  try { hookProp(HTMLIFrameElement.prototype, 'srcdoc', 'iframe.srcdoc'); } catch (e) {}
  try {
    const ow = document.write;
    document.write = function () { sink('document.write', arguments[0]); return ow.apply(document, arguments); };
    const owln = document.writeln;
    document.writeln = function () { sink('document.writeln', arguments[0]); return owln.apply(document, arguments); };
  } catch (e) {}
  try {
    const oia = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function () {
      sink('insertAdjacentHTML', arguments[1]); return oia.apply(this, arguments);
    };
  } catch (e) {}

  // --- cross-origin message handlers are their own bug class --------------
  try {
    const oael = window.addEventListener;
    window.addEventListener = function (type, fn) {
      if (type === 'message') { try { rec.listeners.push({ src: cap(fn) }); } catch (e) {} }
      return oael.apply(window, arguments);
    };
  } catch (e) {}

  window.addEventListener('error', (e) => {
    try { rec.errors.push(cap(e && e.message)); } catch (x) {}
  });
})();
"""


class Observation:
    """One rendered snapshot. Both layers are kept, because they answer different bugs."""

    __slots__ = ("url", "final_url", "status", "raw_html", "dom_html", "text", "title",
                 "console", "errors", "requests", "blocked", "cookies", "storage",
                 "exec_events", "sinks", "message_listeners", "identity", "elapsed")

    def __init__(self, **kw) -> None:
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def execution_proof(self) -> list:
        """Recorded evidence that injected script actually RAN (not inferred)."""
        return list(self.exec_events or [])

    @property
    def executed(self) -> bool:
        return bool(self.exec_events)

    def census(self, marker: str, *, layer: str = "raw") -> list[dict]:
        """Context-aware escaping census of ``marker``.

        ``layer="raw"`` judges the SERVER's escaping (reflected/stored server-side).

        ``layer="dom"`` has a HARD LIMIT: ``dom_html`` is a SERIALIZATION of the DOM, and
        serializing a text node always re-escapes "<" to "&lt;". Character evidence
        therefore cannot exist in the DOM layer -- its absence proves nothing. What the
        DOM layer can still show is STRUCTURE: an attribute or element that our input
        created survives serialization. For DOM-based injection use
        ``Browser.dom_injection()``, which asks the live document whether our input
        became nodes.
        """
        html = self.raw_html if layer == "raw" else self.dom_html
        return _H.census(html or "", marker)

    def findings(self, marker: str, *, layer: str = "raw") -> list[dict]:
        return _H.breakouts(self.census(marker, layer=layer))

    def __repr__(self) -> str:
        return (f"<Observation {self.status} {self.final_url!r} "
                f"raw={len(self.raw_html or '')}B dom={len(self.dom_html or '')}B "
                f"exec={len(self.exec_events or [])} blocked={len(self.blocked or [])}>")


def _env_headers(raw: str) -> dict:
    out: dict[str, str] = {}
    for part in (raw or "").replace("\n", ";").split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


_DEFAULT_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")


class Browser:
    """A scope-jailed Playwright browser.

    Use as a context manager so the browser process is always torn down::

        with Browser(allowlist=["example.com"]) as b:
            obs = b.goto("https://example.com/p?q=p1hZ<>p1hZ")
            print(obs.findings("p1hZ"))
    """

    def __init__(self, *, allowlist=None, base_url: str | None = None,
                 engine: str | None = None, headless: bool | None = None,
                 user_agent: str | None = None, extra_headers: dict | None = None,
                 rate_limit: float | None = None, settle_ms: int | None = None,
                 identity: str | None = None) -> None:
        env_allow = [a for a in (os.environ.get("P1HUNT_EGRESS_ALLOWLIST", "").split(",")) if a.strip()]
        self.allowlist = [_norm_host(a) for a in (allowlist if allowlist is not None else env_allow) if _norm_host(a)]
        self.base_url = (base_url if base_url is not None else os.environ.get("P1HUNT_BASE_URL", "")) or ""
        if self.base_url:
            ok, why = url_allowed(self.base_url, self.allowlist)
            if not ok:
                # The allowlist is a CEILING. An unauthorized base_url is an error,
                # never a new allowlist entry.
                raise BrowserScopeError(
                    f"base_url {self.base_url!r} is not authorized: {why}. "
                    "Add the host to P1HUNT_EGRESS_ALLOWLIST only if the program's scope "
                    "actually covers it."
                )
        self.engine = (engine or os.environ.get("P1HUNT_BROWSER", "chromium")).strip().lower()
        if headless is None:
            headless = os.environ.get("P1HUNT_BROWSER_HEADLESS", "1").strip() != "0"
        self.headless = bool(headless)
        self.user_agent = user_agent or os.environ.get("P1HUNT_USER_AGENT", "") or _DEFAULT_UA
        hdrs = dict(extra_headers or {})
        hdrs.update(_env_headers(os.environ.get("P1HUNT_EXTRA_HEADERS", "")))
        idh = os.environ.get("P1HUNT_ID_HEADER", "")
        if ":" in idh:
            k, v = idh.split(":", 1)
            hdrs[k.strip()] = v.strip()
        self.extra_headers = hdrs
        rl = rate_limit if rate_limit is not None else float(os.environ.get("P1HUNT_RATE_LIMIT", "30") or 30)
        self._bucket = _Bucket(rl)
        self.settle_ms = int(settle_ms if settle_ms is not None
                             else os.environ.get("P1HUNT_SETTLE_MS", "1200") or 1200)
        self.identity = identity

        self._pw = None
        self._browser = None
        self._ctx = None
        self._page = None
        # Per-navigation recorders, reset by _reset_recorders().
        self._console: list = []
        self._requests: list = []
        self._blocked: list = []
        self._raw_bodies: dict = {}
        self._pageerrors: list = []
        self._dialogs: list = []

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "Browser":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> "Browser":
        if self._page is not None:
            return self
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserUnavailable(
                "playwright is not installed. `pip install playwright && playwright install "
                "chromium` (the browser binaries are a separate download)."
            ) from exc
        self._pw = sync_playwright().start()
        launcher = getattr(self._pw, self.engine, None)
        if launcher is None:
            raise BrowserUnavailable(f"unknown browser engine {self.engine!r}")
        try:
            self._browser = launcher.launch(headless=self.headless)
        except Exception as exc:  # binary missing / sandbox refusal
            raise BrowserUnavailable(
                f"could not launch {self.engine}: {exc}. Run `playwright install {self.engine}`."
            ) from exc
        # NOTE: bypass_csp is deliberately NOT set. A page's CSP is part of what is
        # under test -- disabling it would manufacture findings that do not exist in a
        # real victim's browser. The ChatGPT finding turned on script-src being
        # report-only; a CSP-bypassing browser could not have told the difference.
        self._ctx = self._browser.new_context(
            user_agent=self.user_agent,
            extra_http_headers=self.extra_headers or None,
        )
        # The oracle must exist before any document script runs.
        self._ctx.add_init_script(script=_ORACLE_JS)
        # THE CHOKEPOINT. Installed on the CONTEXT, before any page exists, so no
        # navigation can precede it.
        self._ctx.route("**/*", self._guard)
        self._page = self._ctx.new_page()
        self._page.on("console", lambda m: self._console.append(
            {"type": getattr(m, "type", ""), "text": (getattr(m, "text", "") or "")[:600]}))
        self._page.on("pageerror", lambda e: self._pageerrors.append(str(e)[:600]))
        # A real dialog would BLOCK the page. The oracle replaces alert/confirm/prompt,
        # but a frame or a payload that undoes that can still raise one, so dismiss and
        # record rather than hang.
        self._page.on("dialog", self._on_dialog)
        self._page.on("response", self._on_response)
        return self

    def close(self) -> None:
        for obj, meth in ((self._ctx, "close"), (self._browser, "close"), (self._pw, "stop")):
            try:
                if obj is not None:
                    getattr(obj, meth)()
            except Exception:
                pass
        self._pw = self._browser = self._ctx = self._page = None

    # -- the jail ----------------------------------------------------------
    def _guard(self, route) -> None:
        """Scope-check EVERY request. FAILS CLOSED: any exception aborts the request."""
        try:
            req = route.request
            url = req.url
            ok, why = url_allowed(url, self.allowlist)
            if not ok:
                self._blocked.append({"url": url[:400], "method": getattr(req, "method", ""),
                                      "reason": why,
                                      "type": getattr(req, "resource_type", "")})
                route.abort("blockedbyclient")
                return
            host = _norm_host(url)
            if host and not (host in _LOOPBACK or host.endswith(".localhost")):
                self._bucket.take(host)
            self._requests.append({"url": url[:400], "method": getattr(req, "method", ""),
                                   "type": getattr(req, "resource_type", ""),
                                   "redirected_from": bool(getattr(req, "redirected_from", None))})
            route.continue_()
        except Exception as exc:
            # Never let a handler fault become an uncontrolled request.
            try:
                self._blocked.append({"url": "<handler-fault>", "reason": f"guard error: {exc}"})
                route.abort("failed")
            except Exception:
                pass

    def _on_dialog(self, dialog) -> None:
        try:
            self._dialogs.append({"type": getattr(dialog, "type", ""),
                                  "message": (getattr(dialog, "message", "") or "")[:400]})
            dialog.dismiss()
        except Exception:
            pass

    def _on_response(self, response) -> None:
        """Keep the SERVER's bytes for the main document: the DOM is not the same thing."""
        try:
            req = response.request
            if getattr(req, "resource_type", "") != "document":
                return
            self._raw_bodies[response.url] = response.text()
        except Exception:
            pass

    def _reset_recorders(self) -> None:
        self._console = []
        self._requests = []
        self._blocked = []
        self._raw_bodies = {}
        self._pageerrors = []
        self._dialogs = []

    # -- identities --------------------------------------------------------
    def set_identity(self, name: str | None, *, cookies: list | None = None,
                     headers: dict | None = None) -> None:
        """Adopt an identity: its cookies and headers. Cookies are scope-checked too."""
        self.start()
        self._ctx.clear_cookies()
        for c in (cookies or []):
            dom = c.get("domain") or _norm_host(c.get("url", "") or self.base_url)
            if dom and not _allowed(dom, self.allowlist):
                raise BrowserScopeError(
                    f"refusing to set a cookie for {dom!r}: not in the egress allowlist"
                )
        if cookies:
            self._ctx.add_cookies(cookies)
        if headers:
            self._ctx.set_extra_http_headers({**self.extra_headers, **headers})
        self.identity = name

    # -- navigation and observation ---------------------------------------
    def _abs(self, path_or_url: str) -> str:
        if "://" in path_or_url:
            return path_or_url
        return urllib.parse.urljoin(self.base_url or "", path_or_url)

    def goto(self, path_or_url: str, *, wait_until: str = "domcontentloaded",
             settle_ms: int | None = None, timeout_ms: int = 30000) -> Observation:
        """Navigate and observe. Refuses an out-of-scope URL before any packet leaves."""
        self.start()
        url = self._abs(path_or_url)
        ok, why = url_allowed(url, self.allowlist)
        if not ok:
            raise BrowserScopeError(f"refusing to navigate to {url!r}: {why}")
        self._reset_recorders()
        t0 = time.monotonic()
        status = None
        try:
            resp = self._page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            status = getattr(resp, "status", None) if resp is not None else None
        except Exception as exc:
            self._pageerrors.append(f"navigation: {exc}")
        settle = self.settle_ms if settle_ms is None else settle_ms
        if settle > 0:
            # Hydration happens AFTER domcontentloaded. Without this, a server-rendered
            # shell gets compared against a hydrated one and every diff is noise.
            try:
                self._page.wait_for_timeout(settle)
            except Exception:
                pass
        return self.observe(requested=url, status=status, elapsed=time.monotonic() - t0)

    def observe(self, *, requested: str = "", status=None, elapsed: float | None = None) -> Observation:
        """Snapshot the current page: both HTML layers, the oracle, and the network log."""
        self.start()
        page = self._page
        final = ""
        dom = text = title = ""
        try:
            final = page.url
        except Exception:
            pass
        try:
            dom = page.content()
        except Exception:
            pass
        try:
            text = page.inner_text("body")
        except Exception:
            pass
        try:
            title = page.title()
        except Exception:
            pass
        oracle = {"exec": [], "sinks": [], "listeners": [], "errors": []}
        try:
            got = page.evaluate(
                "() => window.__p1hunt ? JSON.parse(JSON.stringify(window.__p1hunt)) : null")
            if isinstance(got, dict):
                oracle.update(got)
        except Exception:
            pass
        storage = {}
        try:
            storage = page.evaluate(
                "() => { const d={local:{},session:{}};"
                " try { for (let i=0;i<localStorage.length;i++){const k=localStorage.key(i);"
                " d.local[k]=String(localStorage.getItem(k)).slice(0,300);} } catch(e){}"
                " try { for (let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);"
                " d.session[k]=String(sessionStorage.getItem(k)).slice(0,300);} } catch(e){}"
                " return d; }") or {}
        except Exception:
            pass
        cookies = []
        try:
            cookies = [{"name": c.get("name"), "domain": c.get("domain"),
                        "httpOnly": c.get("httpOnly"), "secure": c.get("secure"),
                        "len": len(str(c.get("value") or ""))}
                       for c in (self._ctx.cookies() or [])]
        except Exception:
            pass
        raw = self._raw_bodies.get(final) or self._raw_bodies.get(requested) or ""
        if not raw and self._raw_bodies:
            raw = next(iter(self._raw_bodies.values()))
        # A dismissed native dialog is execution proof just as much as a hooked alert.
        exec_events = list(oracle.get("exec") or [])
        for d in self._dialogs:
            exec_events.append({"kind": "native-dialog:" + str(d.get("type")),
                                "detail": d.get("message")})
        return Observation(
            url=requested or final, final_url=final, status=status,
            raw_html=raw, dom_html=dom, text=text, title=title,
            console=list(self._console), errors=list(self._pageerrors) + list(oracle.get("errors") or []),
            requests=list(self._requests), blocked=list(self._blocked),
            cookies=cookies, storage=storage,
            exec_events=exec_events, sinks=list(oracle.get("sinks") or []),
            message_listeners=list(oracle.get("listeners") or []),
            identity=self.identity, elapsed=elapsed,
        )

    # -- interaction -------------------------------------------------------
    def click(self, selector: str, *, timeout_ms: int = 10000) -> Observation:
        self.start()
        self._page.click(selector, timeout=timeout_ms)
        if self.settle_ms:
            self._page.wait_for_timeout(self.settle_ms)
        return self.observe()

    def fill(self, selector: str, value: str, *, timeout_ms: int = 10000) -> Observation:
        self.start()
        self._page.fill(selector, value, timeout=timeout_ms)
        return self.observe()

    def eval_js(self, expression: str):
        self.start()
        return self._page.evaluate(expression)

    def screenshot(self, path: str, *, full_page: bool = True) -> str:
        self.start()
        self._page.screenshot(path=path, full_page=full_page)
        return path

    # -- DOM-level injection: did our input become NODES? -----------------
    _DOM_PROBE_JS = r"""
    (mk) => {
      const out = { textNodes: 0, attrValues: [], attrNames: [], elementsBetween: [],
                    split: false, scriptNodes: 0 };
      const cap = (s) => String(s).slice(0, 120);
      try {
        const tw = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
        const hits = [];
        let n;
        while ((n = tw.nextNode())) {
          if (n.nodeValue && n.nodeValue.indexOf(mk) !== -1) hits.push(n);
        }
        out.textNodes = hits.length;
        document.querySelectorAll('*').forEach((el) => {
          const tag = el.tagName.toLowerCase();
          for (let i = 0; i < el.attributes.length; i++) {
            const a = el.attributes[i];
            if (a.value && a.value.indexOf(mk) !== -1) {
              out.attrValues.push({ tag: tag, name: a.name });
            }
            if (a.name && a.name.indexOf(mk.toLowerCase()) !== -1) {
              out.attrNames.push({ tag: tag, name: cap(a.name) });
            }
          }
        });
        // Our marker is self-delimiting. If its two tokens land in DIFFERENT text
        // nodes, the parser built nodes out of what we put between them -- the DOM
        // equivalent of a parse-state change, and proof regardless of serialization.
        if (hits.length >= 2) {
          out.split = true;
          const r = document.createRange();
          r.setStartAfter(hits[0]);
          r.setEndBefore(hits[hits.length - 1]);
          const frag = r.cloneContents();
          const els = frag.querySelectorAll ? frag.querySelectorAll('*') : [];
          out.elementsBetween = Array.prototype.slice.call(els, 0, 30)
            .map((e) => e.tagName.toLowerCase());
          out.scriptNodes = out.elementsBetween.filter(
            (t) => t === 'script' || t === 'iframe' || t === 'object' || t === 'embed').length;
        }
      } catch (e) {}
      return out;
    }
    """

    def dom_injection(self, marker: str) -> dict:
        """Ask the LIVE document whether ``marker``'s payload became nodes.

        Returns the raw observations plus ``finding`` / ``why``. A finding means one of:

          * ``elementsBetween`` is non-empty -- the parser built elements from the text
            between our two marker tokens. This is the DOM analog of a parse-state
            change and it survives serialization, unlike a raw "<".
          * ``attrNames`` is non-empty -- our input created an ATTRIBUTE NAME, which is
            how ``onerror=``/``onfocus=`` injection looks after parsing.

        A payload that stays a text node (``<>`` alone builds nothing) is correctly not
        a finding.
        """
        self.start()
        try:
            res = self._page.evaluate(self._DOM_PROBE_JS, marker) or {}
        except Exception as exc:
            return {"finding": False, "why": f"probe failed: {exc}", "error": str(exc)}
        els = list(res.get("elementsBetween") or [])
        names = list(res.get("attrNames") or [])
        finding, why = False, "input remained inert text in the DOM"
        if names:
            finding = True
            why = ("our input created an attribute NAME ("
                   + ", ".join(f"{a.get('tag')}@{a.get('name')}" for a in names[:5]) + ")")
        elif els:
            finding = True
            why = "our input was parsed into elements: " + ", ".join(els[:8])
        res["finding"] = finding
        res["why"] = why
        return res

    # -- the differential: the mechanism, not a payload guess --------------
    def differential(self, path_or_url: str, variants: list[dict], **kw) -> dict:
        """Render the SAME resource under several variants and report what CHANGED.

        Each variant is ``{"name":..., "host":..., "cookies":[...], "headers":{...},
        "identity":...}``; ``host`` swaps the host while keeping the path, which is how
        a host-level gate miss shows up.

        This is the comparison that finds render-gate and authorization-render bugs
        without guessing a payload: two renders of one resource that differ in what
        they expose.
        """
        results: dict[str, Observation] = {}
        for v in variants:
            name = str(v.get("name") or v.get("host") or v.get("identity") or len(results))
            target = path_or_url
            if v.get("host"):
                parts = urllib.parse.urlsplit(self._abs(path_or_url))
                target = urllib.parse.urlunsplit(
                    (parts.scheme or "https", v["host"], parts.path, parts.query, parts.fragment))
            self.set_identity(v.get("identity") or name,
                              cookies=v.get("cookies"), headers=v.get("headers"))
            results[name] = self.goto(target, **kw)
        names = list(results)
        diffs = []
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                a, b = results[names[i]], results[names[j]]
                diffs.append({
                    "pair": (names[i], names[j]),
                    "status": (a.status, b.status) if a.status != b.status else None,
                    "raw_len": (len(a.raw_html or ""), len(b.raw_html or "")),
                    "raw_differs": (a.raw_html or "") != (b.raw_html or ""),
                    "title": (a.title, b.title) if a.title != b.title else None,
                    "executed": (a.executed, b.executed) if a.executed != b.executed else None,
                    "only_a_requests": sorted({r["url"] for r in (a.requests or [])}
                                              - {r["url"] for r in (b.requests or [])})[:25],
                    "only_b_requests": sorted({r["url"] for r in (b.requests or [])}
                                              - {r["url"] for r in (a.requests or [])})[:25],
                })
        return {"observations": results, "diffs": diffs}

    def escaping_differential(self, render, control_marker: str, probe_marker: str,
                              *, layer: str = "raw") -> dict:
        """Full differential census: benign control render vs metacharacter probe render.

        ``render`` is a callable ``render(marker) -> Observation`` supplied by the caller,
        because only the caller knows how to get a marker into the application (a query
        parameter, a profile field, a conversation title, a filename). Returns
        ``htmlctx.differential_census``'s verdict, so a sink layout the application
        already had with a benign marker is not reported as an injection.
        """
        control = render(control_marker)
        probe = render(probe_marker)
        control_html = (control.raw_html if layer == "raw" else control.dom_html) or ""
        probe_html = (probe.raw_html if layer == "raw" else probe.dom_html) or ""
        out = _H.differential_census(control_html, probe_html, control_marker, probe_marker)
        out["control"] = control
        out["probe"] = probe
        out["layer"] = layer
        out["executed"] = probe.executed
        out["execution_proof"] = probe.execution_proof
        if layer == "dom":
            # Character evidence cannot exist in a serialized DOM, so ask the live
            # document for structure instead. The probe render is the current page.
            out["dom_injection"] = self.dom_injection(probe_marker)
            if out["dom_injection"].get("finding") and not out["confirmed"]:
                out["confirmed"] = [{
                    "context": "dom", "verdict": "BREAKOUT", "evidence": "dom_structural",
                    "why": out["dom_injection"]["why"],
                    "snippet": "", "attr": "", "tag": "",
                }]
        return out


# A marker with no metacharacters, for the control render.
CONTROL_MARKER = "p1hCTRL"
# The metacharacter probe. Self-delimiting: the characters under test sit BETWEEN the
# two tokens, so htmlctx.census can bound the span it is entitled to judge.
PROBE_MARKER = _H.PROBE_TOKEN
PROBE = _H.PROBE
