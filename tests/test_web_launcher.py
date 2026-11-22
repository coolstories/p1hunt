"""Starting a hunt from the web console: the most dangerous thing in this package.

This turns an HTTP request into a spawned process with operator-supplied arguments, so
these tests are mostly about what the launcher REFUSES and what it keeps out of places
other users can read. The properties held here:

  * NO SHELL, and operator values never land in flag positions. There is no shell, so the
    only way an operator value can change the MEANING of the command is by being parsed as
    an option -- which is the whole injection surface, and it is closed by refusal.
  * CREDENTIALS NEVER REACH argv OR DISK. `ps` shows every argument to every user on the
    machine. Tokens go into the child's environment; the Scope persists the env var NAME.
  * THE SCOPE NOTE NEVER REACHES argv EITHER. Found during a smoke test of this very
    launcher: the note was passed inline, and a grep for the test's own marker matched the
    process listing. A note pasted from a program page can name internal hosts and test
    accounts, so it goes through a 0600 file.
  * AUTHORIZATION IS ATTESTED. A hunt sends real traffic to someone else's system and a
    web form makes that one click. The attestation is required and recorded.
  * A NO-GO MACHINE DOES NOT SILENTLY LAUNCH. A run that cannot produce a confirmed
    finding still reports success, so preflight gates the launch unless forced, and the
    force is recorded.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from p1hunt.web import launcher as L


def _spec(**over) -> dict:
    """A valid launch payload in the CURRENT shape: a confirmed host LIST.

    Deliberately carries no `target`. An earlier version of this helper set one, so a
    subtest passing `hosts=[]` silently fell back to it and the "no hosts" refusal never
    fired -- the fixture was hiding the behaviour under test.
    """
    base = {"hosts": ["api.example.com"], "program": "example-prog",
            "scope_note": "in scope: api.example.com", "engine": "claude",
            "platform": "local", "rounds": 2, "authorized": True,
            "identities": {"a": "tok-a", "b": "tok-b"}}
    base.update(over)
    return base


class TestItRefusesWhatItShould(unittest.TestCase):
    def _refuses(self, **over):
        with self.assertRaises(L.LaunchError) as ctx:
            L.validate(L.LaunchSpec.from_dict(_spec(**over)))
        return str(ctx.exception)

    def test_authorization_must_be_attested(self):
        msg = self._refuses(authorized=False)
        self.assertIn("authorization not attested", msg)
        # The message has to say WHY, because this is the one guard a human must think about.
        self.assertIn("someone else's", msg)

    def test_a_value_that_argparse_would_read_as_a_flag_is_refused(self):
        """The actual injection boundary: there is no shell, so a flag is the only lever.

        Exercised through `hosts`, which is the field a launch actually uses. Passing a
        flag as the legacy `target` while valid hosts are present is simply ignored --
        `target` is consulted only when `hosts` is empty, and then through this same
        check -- so that combination is covered separately below.
        """
        for bad in ("--version", "-h", "--engine=codex"):
            with self.subTest(host=bad):
                self.assertIn("may not begin with '-'", self._refuses(hosts=[bad]))
        self.assertIn("may not begin with '-'", self._refuses(out_of_scope="--out-of-scope=x"))
        self.assertIn("may not begin with '-'",
                      self._refuses(hosts=[], target="--dangerously-something"))
        self.assertIn("may not begin with '-'",
                      self._refuses(program_url="--not-a-url"))

    def test_a_flag_in_the_legacy_target_is_ignored_when_real_hosts_are_given(self):
        """Not a hole: `target` is a fallback, so a valid host list simply wins."""
        spec = L.validate(L.LaunchSpec.from_dict(
            _spec(hosts=["api.example.com"], target="--version")))
        self.assertEqual(spec.hosts, ["https://api.example.com"])
        self.assertNotIn("--version", " ".join(L.build_argv(spec)))

    def test_only_http_hosts(self):
        """A non-http value is refused whichever field it arrives in.

        The messages differ by shape now, and that is deliberate: a value WITH a scheme is
        told it is not an http(s) URL, a bare value is told it is not a hostname and
        pointed at Parse scope, and an EMPTY one is told there are no hosts at all. The
        single free-text `target` field these used to go through is gone -- removing it is
        what stopped a program page becoming a target.
        """
        for bad in ("file:///etc/passwd", "ftp://x.example", "gopher://x"):
            with self.subTest(host=bad):
                self.assertIn("http(s) URL", self._refuses(hosts=[bad]))
        for bad in ("javascript:alert(1)", "not a host", "@@@"):
            with self.subTest(host=bad):
                self.assertIn("not a hostname", self._refuses(hosts=[bad]))
        for empty in ([], [""], ["   "]):
            with self.subTest(hosts=empty):
                self.assertIn("no in-scope hosts", self._refuses(hosts=empty))

    def test_the_legacy_single_target_field_still_validates(self):
        """The API stays usable directly, so `target` folds into the same host checks."""
        self.assertIn("not a hostname",
                      self._refuses(hosts=[], target="javascript:alert(1)"))
        self.assertIn("http(s) URL",
                      self._refuses(hosts=[], target="file:///etc/passwd"))

    def test_a_legacy_target_is_accepted_when_it_is_valid(self):
        spec = L.validate(L.LaunchSpec.from_dict(
            _spec(hosts=[], target="https://api.example.com")))
        self.assertEqual(spec.hosts, ["https://api.example.com"])

    def test_a_program_name_cannot_traverse_the_filesystem(self):
        """The program name becomes a directory name."""
        for bad in ("../../etc", "a/b", "x\x00y", "a;rm -rf /", "a$(whoami)"):
            with self.subTest(program=bad):
                self.assertTrue(self._refuses(program=bad))

    def test_engine_and_platform_are_enums(self):
        self.assertIn("engine must be one of", self._refuses(engine="sh"))
        self.assertIn("platform must be one of", self._refuses(platform="../x"))

    def test_rounds_are_bounded(self):
        self.assertIn("between 1 and", self._refuses(rounds=0))
        self.assertIn("between 1 and", self._refuses(rounds=10_000))

    def test_an_identity_name_becomes_an_env_var_so_it_is_constrained(self):
        for bad in ("a b", "a-b", "PATH=x", "a;b"):
            with self.subTest(name=bad):
                self.assertTrue(self._refuses(identities={bad: "t"}))

    def test_absurd_sizes_are_refused(self):
        self.assertIn("too long", self._refuses(scope_note="x" * 20_001))
        self.assertIn("implausibly long", self._refuses(identities={"a": "x" * 8001}))

    def test_a_non_object_body_is_refused(self):
        with self.assertRaises(L.LaunchError):
            L.LaunchSpec.from_dict(["not", "an", "object"])
        with self.assertRaises(L.LaunchError):
            L.LaunchSpec.from_dict({"identities": "not-an-object"})

    def test_an_empty_identity_token_is_dropped_not_sent_as_empty(self):
        spec = L.validate(L.LaunchSpec.from_dict(_spec(identities={"a": "t", "b": ""})))
        self.assertEqual(sorted(spec.identities), ["a"])


class TestNothingSensitiveReachesArgv(unittest.TestCase):
    """`ps` shows every argument to every user on this machine."""

    def test_no_shell_is_ever_used(self):
        import inspect
        src = inspect.getsource(L)
        self.assertNotIn("shell=True", src)
        self.assertNotIn("os.system", src)
        self.assertNotIn("subprocess.call(", src)

    def test_tokens_are_not_in_argv(self):
        spec = L.validate(L.LaunchSpec.from_dict(
            _spec(identities={"a": "SECRET_AAA", "b": "SECRET_BBB"})))
        argv = L.build_argv(spec)
        joined = " ".join(argv)
        self.assertNotIn("SECRET_AAA", joined)
        self.assertNotIn("SECRET_BBB", joined)

    def test_the_scope_note_is_passed_as_a_path_not_as_text(self):
        spec = L.validate(L.LaunchSpec.from_dict(
            _spec(scope_note="SECRET_INTERNAL_HOST m.example.com")))
        argv = L.build_argv(spec, scope_note_file=Path("/tmp/eng/scope_note.txt"))
        self.assertNotIn("SECRET_INTERNAL_HOST", " ".join(argv))
        self.assertIn("--scope-note-file", argv)

    def test_tokens_go_into_the_child_environment_under_the_expected_names(self):
        spec = L.validate(L.LaunchSpec.from_dict(
            _spec(identities={"a": "SECRET_AAA", "low": "SECRET_LOW"})))
        env = L._child_env(spec)
        self.assertEqual(env["P1HUNT_TOKEN_A"], "SECRET_AAA")
        self.assertEqual(env["P1HUNT_TOKEN_LOW"], "SECRET_LOW")
        self.assertEqual(env["P1HUNT_ENGINE"], "claude")
        self.assertEqual(env["P1HUNT_RUN_MODE"], "active")

    def test_a_default_identity_maps_to_the_unsuffixed_variable(self):
        spec = L.validate(L.LaunchSpec.from_dict(_spec(identities={"default": "T"})))
        self.assertEqual(L._child_env(spec)["P1HUNT_TOKEN"], "T")

    def test_argv_starts_with_this_interpreter_and_the_module(self):
        """A fixed template: the command is not assembled from operator input."""
        spec = L.validate(L.LaunchSpec.from_dict(_spec()))
        argv = L.build_argv(spec)
        import sys
        self.assertEqual(argv[:4], [sys.executable, "-m", "p1hunt.main", "hunt"])
        self.assertIn("--web", argv)


class TestThePreflightGate(unittest.TestCase):
    def test_a_no_go_machine_does_not_launch(self):
        nogo = {"go": False, "checks": [], "failures": ["pytest: runs a test"]}
        with mock.patch.object(L, "preflight", lambda *a, **k: nogo):
            res = L.launch(_spec())
        self.assertFalse(res["ok"])
        self.assertEqual(res["blocked"], "preflight")
        # The operator's likeliest misreading, pre-empted in the refusal itself.
        self.assertIn("would still report success", res["error"])

    def test_force_overrides_the_gate_and_is_recorded(self):
        nogo = {"go": False, "checks": [], "failures": ["x"]}
        tmp = tempfile.mkdtemp()
        started = {}

        class _P:
            pid = 4242

        def _popen(argv, **kw):
            started["argv"] = argv
            started["env"] = kw.get("env")
            return _P()

        with mock.patch.object(L, "preflight", lambda *a, **k: nogo), \
             mock.patch.object(L.subprocess, "Popen", _popen):
            res = L.launch(_spec(force=True), root=Path(tmp))
        self.assertTrue(res["ok"])
        self.assertTrue(res["launch"]["forced_past_preflight"])
        self.assertFalse(res["launch"]["preflight_go"])

    def test_the_launch_record_keeps_names_and_lengths_never_values(self):
        tmp = tempfile.mkdtemp()

        class _P:
            pid = 99

        with mock.patch.object(L, "preflight", lambda *a, **k: {"go": True, "checks": []}), \
             mock.patch.object(L.subprocess, "Popen", lambda *a, **k: _P()):
            res = L.launch(_spec(identities={"a": "SECRET_AAA"}), root=Path(tmp))
        rec = res["launch"]
        blob = json.dumps(rec)
        self.assertNotIn("SECRET_AAA", blob)
        self.assertEqual(rec["identities"], ["a"])
        self.assertEqual(rec["identity_token_lengths"], {"a": len("SECRET_AAA")})
        self.assertTrue(rec["authorized_attested"])
        # And the same must hold for what landed on disk.
        on_disk = (Path(tmp) / "example-prog" / "launch.json").read_text(encoding="utf-8")
        self.assertNotIn("SECRET_AAA", on_disk)

    def test_the_scope_note_file_is_owner_only(self):
        tmp = tempfile.mkdtemp()

        class _P:
            pid = 7

        with mock.patch.object(L, "preflight", lambda *a, **k: {"go": True, "checks": []}), \
             mock.patch.object(L.subprocess, "Popen", lambda *a, **k: _P()):
            L.launch(_spec(scope_note="internal host m.example.com"), root=Path(tmp))
        note = Path(tmp) / "example-prog" / "scope_note.txt"
        self.assertTrue(note.is_file())
        self.assertEqual(stat.S_IMODE(note.stat().st_mode), 0o600)
        self.assertIn("internal host", note.read_text(encoding="utf-8"))

    def test_it_refuses_to_launch_into_a_live_engagement(self):
        """Two runs writing one event stream would be read as a single run."""
        import time
        tmp = Path(tempfile.mkdtemp())
        eng = tmp / "example-prog"
        eng.mkdir(parents=True)
        (eng / "events.jsonl").write_text('{"x":1}\n', encoding="utf-8")
        os.utime(eng / "events.jsonl", (time.time(), time.time()))
        with mock.patch.object(L, "preflight", lambda *a, **k: {"go": True, "checks": []}):
            with self.assertRaises(L.LaunchError) as ctx:
                L.launch(_spec(), root=tmp)
        self.assertIn("looks live", str(ctx.exception))


class TestEngagementNaming(unittest.TestCase):
    def test_it_matches_the_cli_derivation(self):
        """The console and the CLI must agree on where a run lands."""
        for program in ("example-prog", "Example Program", "a.b_c", "x" * 80):
            with self.subTest(program=program):
                expected = "".join(c if c.isalnum() else "-" for c in program.lower())[:40]
                self.assertEqual(L.engagement_name(program), expected or "engagement")


class TestTheScopeNoteFileFlagIsWired(unittest.TestCase):
    def test_the_cli_accepts_a_scope_note_file_and_it_wins(self):
        import argparse

        from p1hunt.main import _resolve_scope_note

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("from the file")
            path = fh.name
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        args = argparse.Namespace(scope_note="inline", scope_note_file=path)
        _resolve_scope_note(args)
        # The file wins: the only reason to use it is to keep the text out of argv, so
        # preferring the inline copy would defeat the point.
        self.assertEqual(args.scope_note, "from the file")

    def test_a_missing_file_is_a_clean_usage_error(self):
        import argparse

        from p1hunt.main import _resolve_scope_note
        args = argparse.Namespace(scope_note="", scope_note_file="/definitely/not/here")
        with self.assertRaises(SystemExit):
            _resolve_scope_note(args)

    def test_no_file_leaves_the_inline_note_alone(self):
        import argparse

        from p1hunt.main import _resolve_scope_note
        args = argparse.Namespace(scope_note="inline", scope_note_file="")
        _resolve_scope_note(args)
        self.assertEqual(args.scope_note, "inline")


class TestTheConsoleServesTheLaunchPage(unittest.TestCase):
    def test_the_routes_are_registered(self):
        import inspect

        from p1hunt.web.server import _Handler
        get_src = inspect.getsource(_Handler.do_GET)
        post_src = inspect.getsource(_Handler.do_POST)
        self.assertIn("/launch", get_src)
        self.assertIn("/api/preflight", get_src)
        self.assertIn("/api/launch", post_src)

    def test_the_page_has_every_control_the_launcher_needs(self):
        page = (Path(L.__file__).parent / "static" / "launch.html").read_text(encoding="utf-8")
        for control in ("id=\"programUrl\"", "id=\"scope\"", "id=\"parseBtn\"",
                        "id=\"scopeOut\"", "id=\"program\"", "id=\"tokA\"",
                        "id=\"tokB\"", "id=\"engine\"", "id=\"rounds\"", "id=\"auth\"",
                        "id=\"checkBtn\"", "id=\"goBtn\"", "launch.js"):
            with self.subTest(control=control):
                self.assertIn(control, page)

    def test_the_token_fields_are_password_inputs(self):
        page = (Path(L.__file__).parent / "static" / "launch.html").read_text(encoding="utf-8")
        for field in ("tokA", "tokB"):
            idx = page.index(f'id="{field}"')
            self.assertIn('type="password"', page[max(0, idx - 120):idx + 40],
                          f"{field} must not render its value in plain text")

    def test_there_is_no_free_text_target_field(self):
        """The regression that matters. A "target URL" box is what let the operator paste
        a HackerOne program page and point a hunt at HackerOne's own website. Hosts are
        derived from the pasted scope and confirmed; there is nowhere to type one blind."""
        page = (Path(L.__file__).parent / "static" / "launch.html").read_text(encoding="utf-8")
        self.assertNotIn('id="target"', page)
        self.assertIn("never used as a target", page)

    def test_the_page_states_the_engine_measurement(self):
        """An operator picking 'codex' would get recon only. Say so where they choose."""
        page = (Path(L.__file__).parent / "static" / "launch.html").read_text(encoding="utf-8")
        self.assertIn("7 of 8", page)
        self.assertIn("reconnaissance", page)

    def test_the_page_explains_why_two_identities_matter(self):
        page = (Path(L.__file__).parent / "static" / "launch.html").read_text(encoding="utf-8")
        self.assertIn("comparison between two", page)


if __name__ == "__main__":
    unittest.main()


class TestTheLaunchPageScrolls(unittest.TestCase):
    """app.css is written for the console's FIXED-PANEL layout and sets
    `html,body{height:100%}` with `body{overflow:hidden}`, each column scrolling
    internally. The launch page is a long ordinary form, so inheriting that made the
    bottom of it -- including the Launch button -- simply unreachable. Reported by the
    operator as "you cant scrol up and down on the new hunt".
    """

    @classmethod
    def setUpClass(cls):
        cls.page = (Path(L.__file__).parent / "static"
                    / "launch.html").read_text(encoding="utf-8")

    def test_the_page_re_enables_document_scrolling(self):
        self.assertIn("overflow-y:auto", self.page)
        self.assertIn("html,body{height:auto", self.page)

    def test_the_console_still_hides_overflow(self):
        """The fix must be page-local: the console depends on the opposite behaviour."""
        css = (Path(L.__file__).parent / "static" / "app.css").read_text(encoding="utf-8")
        self.assertIn("overflow:hidden", css)

    def test_content_clears_the_fixed_header(self):
        """classbar (20px) + cmdbar (56px at top:20px) are position:fixed, so content
        starting at the top would sit underneath them."""
        self.assertRegex(self.page, r"\.wrap\{[^}]*padding:\s*9\dpx")

    def test_the_comment_explains_why_rather_than_just_what(self):
        """A bare `overflow:auto` would look like a style tweak and get 'cleaned up'."""
        self.assertIn("FIXED-PANEL", self.page)
        self.assertIn("unreachable", self.page)

    def test_it_really_scrolls_in_a_browser(self):
        """The assertion that actually matters. CSS can be present and still not work."""
        try:
            import playwright  # noqa: F401
        except ImportError:
            self.skipTest("playwright not installed")
        import threading
        from http.server import ThreadingHTTPServer

        from p1hunt.web.server import _Handler
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)

        from p1hunt.dynamic.browser import Browser
        with Browser(allowlist=["127.0.0.1"], base_url=f"http://127.0.0.1:{port}",
                     rate_limit=0) as b:
            b.goto(f"http://127.0.0.1:{port}/launch")
            m = b.eval_js("""
              (() => {
                const d = document.documentElement, bd = document.body;
                window.scrollTo(0, 99999);
                const btn = document.getElementById('goBtn');
                const r = btn ? btn.getBoundingClientRect() : null;
                return {h: Math.max(d.scrollHeight, bd.scrollHeight),
                        vp: window.innerHeight, y: window.scrollY,
                        btnReachable: !!r && r.top >= 0 && r.bottom <= window.innerHeight + 2,
                        headerPinned: getComputedStyle(
                          document.querySelector('.cmdbar')).position};
              })()
            """)
        self.assertGreater(m["h"], m["vp"], "the form should be taller than the viewport")
        self.assertGreater(m["y"], 0, "the page did not scroll")
        self.assertTrue(m["btnReachable"], "the Launch button is not reachable by scrolling")
        self.assertEqual(m["headerPinned"], "fixed", "the header should stay pinned")
