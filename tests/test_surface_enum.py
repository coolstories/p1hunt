"""Unit tests for entrypoint enumeration (p1hunt.agents.surface_enum).

This is the half that was missing from the coverage loop: EVM targets had
``detect_evm_entrypoints``, every other class got ``[]``, so ``CorpusStore.uncovered_hint``
returned "" and rounds never compounded on web/API targets. The decisive test here is
``CompoundingTest`` — enumerate, record coverage, and confirm the hint now steers at what is
still dark and goes quiet once everything is covered.

Pure: reads files only, no network.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from p1hunt.agents.surface_enum import (
    covered_from_paths,
    detect_fs_route_entrypoints,
    detect_route_entrypoints,
    detect_schema_entrypoints,
    detect_web_entrypoints,
    entrypoints_for,
)
from p1hunt.corpus import CorpusStore
from p1hunt.models import TargetClass


class _Repo:
    """Tiny helper that writes files into a temp dir."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def write(self, rel: str, text: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def cleanup(self) -> None:
        self._tmp.cleanup()


class RouteDetectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = _Repo()

    def tearDown(self) -> None:
        self.repo.cleanup()

    def test_method_call_style_routes(self) -> None:
        self.repo.write("src/server.js", """
            app.get("/doc/:id", handler);
            router.post('/orders', create);
            app.delete("/orders/:oid", remove);
        """)
        found = detect_route_entrypoints(str(self.repo.root))
        self.assertIn("GET /doc/{p}", found)
        self.assertIn("POST /orders", found)
        self.assertIn("DELETE /orders/{p}", found)

    def test_decorator_style_routes(self) -> None:
        self.repo.write("app/views.py", """
            @app.get("/users/{user_id}")
            def read_user(user_id): ...

            @router.post("/transfer")
            def transfer(): ...
        """)
        found = detect_route_entrypoints(str(self.repo.root))
        self.assertIn("GET /users/{p}", found)
        self.assertIn("POST /transfer", found)

    def test_annotation_style_routes(self) -> None:
        self.repo.write("Api.java", """
            @GetMapping("/accounts/{id}")
            public Account get(...) {}
            @PostMapping(path = "/accounts")
            public void create(...) {}
        """)
        found = detect_route_entrypoints(str(self.repo.root))
        self.assertIn("GET /accounts/{p}", found)
        self.assertIn("POST /accounts", found)

    def test_rust_attribute_style_routes(self) -> None:
        # '#' inside a VERBOSE regex is a comment unless escaped — this guards that fix.
        self.repo.write("main.rs", '#[get("/health")]\nfn health() {}\n')
        self.assertIn("GET /health", detect_route_entrypoints(str(self.repo.root)))

    def test_parameter_styles_normalize_to_one_entrypoint(self) -> None:
        self.repo.write("a.ts", 'app.get("/doc/:id", h);')
        self.repo.write("b.py", '@app.get("/doc/{docId}")\ndef d(): ...')
        self.repo.write("c.js", 'app.get("/doc/[slug]", h);')
        found = detect_route_entrypoints(str(self.repo.root))
        self.assertEqual([f for f in found if f.startswith("GET /doc")], ["GET /doc/{p}"])

    def test_trailing_slash_is_not_a_separate_entrypoint(self) -> None:
        self.repo.write("a.js", 'app.get("/orders/", h); app.get("/orders", h);')
        found = detect_route_entrypoints(str(self.repo.root))
        self.assertEqual([f for f in found if "orders" in f], ["GET /orders"])

    def test_ignored_directories_are_skipped(self) -> None:
        self.repo.write("node_modules/dep/index.js", 'app.get("/vendor", h);')
        self.repo.write("tests/test_api.js", 'app.get("/fixture", h);')
        self.repo.write("src/real.js", 'app.get("/real", h);')
        found = detect_route_entrypoints(str(self.repo.root))
        self.assertEqual(found, ["GET /real"])

    def test_focus_files_narrow_the_scan(self) -> None:
        self.repo.write("src/a.js", 'app.get("/a", h);')
        self.repo.write("src/b.js", 'app.get("/b", h);')
        found = detect_route_entrypoints(str(self.repo.root), ["src/b.js"])
        self.assertEqual(found, ["GET /b"])

    def test_limit_is_respected(self) -> None:
        self.repo.write("a.js", "\n".join(f'app.get("/r{i}", h);' for i in range(40)))
        self.assertEqual(len(detect_route_entrypoints(str(self.repo.root), limit=5)), 5)

    def test_missing_repo_returns_empty(self) -> None:
        self.assertEqual(detect_route_entrypoints("/no/such/path/xyz"), [])

    def test_non_route_source_yields_nothing(self) -> None:
        self.repo.write("math.py", "def add(a, b):\n    return a + b\n")
        self.assertEqual(detect_route_entrypoints(str(self.repo.root)), [])


class SchemaDetectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = _Repo()

    def tearDown(self) -> None:
        self.repo.cleanup()

    def test_openapi_paths_and_verbs(self) -> None:
        self.repo.write("openapi.json", json.dumps({
            "openapi": "3.0.0",
            "paths": {
                "/pets": {"get": {}, "post": {}},
                "/pets/{petId}": {"get": {}},
            },
        }))
        found = detect_schema_entrypoints(str(self.repo.root))
        self.assertIn("GET /pets", found)
        self.assertIn("POST /pets", found)
        self.assertIn("GET /pets/{p}", found)

    def test_openapi_path_without_verbs_is_any(self) -> None:
        self.repo.write("api.json", json.dumps({"paths": {"/thing": None}}))
        self.assertIn("ANY /thing", detect_schema_entrypoints(str(self.repo.root)))

    def test_malformed_schema_is_skipped(self) -> None:
        self.repo.write("broken.json", '{"paths": {oops}')
        self.assertEqual(detect_schema_entrypoints(str(self.repo.root)), [])

    def test_unrelated_json_is_ignored(self) -> None:
        self.repo.write("package.json", json.dumps({"name": "x", "version": "1.0.0"}))
        self.assertEqual(detect_schema_entrypoints(str(self.repo.root)), [])

    def test_graphql_root_fields(self) -> None:
        self.repo.write("schema.graphql", """
            type Query {
              me: User
              document(id: ID!): Document
            }
            type Mutation {
              shareDocument(id: ID!, to: String!): Boolean
            }
            type User { id: ID! }
        """)
        found = detect_schema_entrypoints(str(self.repo.root))
        self.assertIn("GQL Query.me", found)
        self.assertIn("GQL Query.document", found)
        self.assertIn("GQL Mutation.shareDocument", found)
        # A non-root type is not an entrypoint.
        self.assertNotIn("GQL User.id", found)


class FsRouteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = _Repo()

    def tearDown(self) -> None:
        self.repo.cleanup()

    def test_file_system_routing(self) -> None:
        self.repo.write("pages/api/users/[id].ts", "export default h;")
        self.repo.write("pages/api/health.ts", "export default h;")
        self.repo.write("app/api/orders/route.ts", "export const GET = h;")
        found = detect_fs_route_entrypoints(str(self.repo.root))
        self.assertIn("ANY /users/{p}", found)
        self.assertIn("ANY /health", found)
        self.assertIn("ANY /orders", found)

    def test_no_route_dirs_returns_empty(self) -> None:
        self.repo.write("src/index.ts", "x")
        self.assertEqual(detect_fs_route_entrypoints(str(self.repo.root)), [])


class DispatcherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = _Repo()

    def tearDown(self) -> None:
        self.repo.cleanup()

    def test_web_class_gets_routes(self) -> None:
        self.repo.write("src/server.js", 'app.get("/doc/:id", h);')
        found = entrypoints_for(TargetClass.WEB_API, str(self.repo.root))
        self.assertEqual(found, ["GET /doc/{p}"])

    def test_evm_class_uses_the_solidity_enumerator(self) -> None:
        self.repo.write("src/Token.sol", """
            contract Token {
              function transfer(address to, uint256 amount) external returns (bool) {}
              function _internal() internal {}
            }
        """)
        found = entrypoints_for(TargetClass.EVM_CONTRACT, str(self.repo.root))
        self.assertTrue(any("transfer" in f for f in found))
        self.assertFalse(any("_internal" in f for f in found))

    def test_evm_class_does_not_pick_up_web_routes(self) -> None:
        self.repo.write("src/server.js", 'app.get("/doc/:id", h);')
        self.assertEqual(entrypoints_for(TargetClass.EVM_CONTRACT, str(self.repo.root)), [])

    def test_accepts_a_plain_string_class(self) -> None:
        self.repo.write("src/server.js", 'app.get("/x", h);')
        self.assertEqual(entrypoints_for("WEB_API", str(self.repo.root)), ["GET /x"])

    def test_unknown_class_still_enumerates_web_surface(self) -> None:
        # OTHER/unknown must not regress to [] — that is the bug being fixed.
        self.repo.write("src/server.js", 'app.get("/x", h);')
        self.assertEqual(entrypoints_for(TargetClass.OTHER, str(self.repo.root)), ["GET /x"])
        self.assertEqual(entrypoints_for(None, str(self.repo.root)), ["GET /x"])

    def test_missing_repo_degrades_to_empty(self) -> None:
        self.assertEqual(entrypoints_for(TargetClass.WEB_API, "/no/such/path"), [])

    def test_combined_sources_are_deduplicated(self) -> None:
        self.repo.write("src/server.js", 'app.get("/pets", h);')
        self.repo.write("openapi.json", json.dumps({"paths": {"/pets": {"get": {}}}}))
        found = detect_web_entrypoints(str(self.repo.root))
        self.assertEqual(found.count("GET /pets"), 1)


class CoverageTokenTest(unittest.TestCase):
    def test_route_entry_becomes_matchable_tokens(self) -> None:
        tokens = covered_from_paths(["GET /doc/{p}/share"])
        self.assertIn("doc", tokens)
        self.assertIn("share", tokens)

    def test_tokens_are_deduplicated(self) -> None:
        tokens = covered_from_paths(["/a/doc", "/b/doc"])
        self.assertEqual(tokens.count("doc"), 1)

    def test_blank_input_is_safe(self) -> None:
        self.assertEqual(covered_from_paths([]), [])
        self.assertEqual(covered_from_paths(["", None]), [])


class CompoundingTest(unittest.TestCase):
    """The point of the whole exercise: on a WEB target, round N+1 must be steered at what
    round N did not reach — which was impossible while the entrypoint list was empty."""

    def setUp(self) -> None:
        self.repo = _Repo()
        self._tmp = tempfile.TemporaryDirectory()
        self.eng = Path(self._tmp.name)

    def tearDown(self) -> None:
        self.repo.cleanup()
        self._tmp.cleanup()

    def test_uncovered_hint_is_non_empty_for_a_web_target(self) -> None:
        self.repo.write("src/server.js", """
            app.get("/doc/:id", h);
            app.post("/share", h);
            app.get("/admin/export", h);
        """)
        entrypoints = entrypoints_for(TargetClass.WEB_API, str(self.repo.root))
        self.assertEqual(len(entrypoints), 3)

        store = CorpusStore(self.eng)
        # Before this fix the entrypoint list was [] and the hint was always "".
        hint = store.uncovered_hint("web", entrypoints)
        self.assertTrue(hint)
        self.assertIn("still-uncovered", hint)

    def test_coverage_accumulates_and_the_hint_narrows(self) -> None:
        self.repo.write("src/server.js", """
            app.get("/doc/:id", h);
            app.post("/share", h);
            app.get("/admin/export", h);
        """)
        entrypoints = entrypoints_for(TargetClass.WEB_API, str(self.repo.root))
        store = CorpusStore(self.eng)

        # Round 1 touches the share route.
        store.record("web", covered_symbols=covered_from_paths(["POST /share"]))
        hint = store.uncovered_hint("web", entrypoints)
        self.assertNotIn("/share", hint)
        self.assertIn("doc", hint)

        # Round 2 touches the rest -> nothing left to steer at.
        store.record("web", covered_symbols=covered_from_paths(
            ["GET /doc/{p}", "GET /admin/export"]))
        self.assertEqual(store.uncovered_hint("web", entrypoints), "")

    def test_coverage_survives_a_restart(self) -> None:
        self.repo.write("src/server.js", 'app.get("/doc/:id", h);\napp.post("/share", h);')
        entrypoints = entrypoints_for(TargetClass.WEB_API, str(self.repo.root))
        CorpusStore(self.eng).record("web", covered_symbols=covered_from_paths(["POST /share"]))
        reloaded = CorpusStore(self.eng)
        self.assertNotIn("/share", reloaded.uncovered_hint("web", entrypoints))


if __name__ == "__main__":
    unittest.main()
