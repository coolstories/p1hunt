"""Unit tests for p1hunt/runners/mobile.py — pure parser + tool-absent graceful paths only.

HERMETIC: never invokes apkanalyzer, never touches the network, never boots an emulator. The pure
:func:`parse_mobile` is exercised with realistic AndroidManifest.xml / Info.plist sample strings;
the :class:`MobileRunner` is exercised only in the static-read and tool-absent branches.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from p1hunt.runners import mobile
from p1hunt.runners.base import ReproSpec
from p1hunt.runners.mobile import MobileRunner, parse_mobile

# --- Sample manifests (realistic shapes, generic — no per-app literals tie the test to a program) -

VULNERABLE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
  <application android:debuggable="true"
               android:allowBackup="true"
               android:usesCleartextTraffic="true"
               android:label="Demo">
    <activity android:name=".PublicActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
      </intent-filter>
    </activity>
    <service android:name=".SyncService"/>
    <receiver android:name=".BootReceiver">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
  </application>
</manifest>
"""

HARDENED_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo">
  <application android:debuggable="false"
               android:allowBackup="false"
               android:usesCleartextTraffic="false"
               android:label="Demo">
    <activity android:name=".PublicActivity" android:exported="true"
              android:permission="com.example.demo.permission.PRIVATE">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
      </intent-filter>
    </activity>
    <service android:name=".SyncService" android:exported="false"/>
  </application>
</manifest>
"""

IOS_PLIST_ATS_DISABLED = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
  </dict>
</dict>
</plist>
"""

STRINGS_WITH_SECRET = """<resources>
  <string name="endpoint">https://api.example.com</string>
  <string name="aws">AKIAIOSFODNN7EXAMPLE</string>
</resources>
"""


def _spec(condition: str = "", expect: str = "fail") -> ReproSpec:
    return ReproSpec(
        harness_path="app/",
        kind="policy",
        expect=expect,
        test_name=condition,
        extra={"condition": condition},
    )


class ParseExportedTests(unittest.TestCase):
    def test_exported_component_no_guard_reproduced(self):
        res = parse_mobile(VULNERABLE_MANIFEST, _spec("exported"))
        self.assertTrue(res["reproduced"])
        self.assertIn("exported", res["detail"].lower())
        # implicitly-exported receiver + explicitly-exported activity both flagged
        self.assertGreaterEqual(res["coverage"]["exported_holes"], 2)
        self.assertIn(".PublicActivity", res["coverage"]["covered_symbols"])

    def test_hardened_exported_with_permission_not_reproduced(self):
        res = parse_mobile(HARDENED_MANIFEST, _spec("exported"))
        self.assertFalse(res["reproduced"])
        self.assertEqual(res["coverage"]["exported_holes"], 0)
        self.assertIn("hardened", res["detail"].lower())


class ParseFlagTests(unittest.TestCase):
    def test_debuggable_true_reproduced(self):
        res = parse_mobile(VULNERABLE_MANIFEST, _spec("debuggable"))
        self.assertTrue(res["reproduced"])
        self.assertIn("debuggable", res["detail"].lower())

    def test_debuggable_false_not_reproduced(self):
        res = parse_mobile(HARDENED_MANIFEST, _spec("debuggable"))
        self.assertFalse(res["reproduced"])

    def test_cleartext_android_reproduced(self):
        res = parse_mobile(VULNERABLE_MANIFEST, _spec("cleartext"))
        self.assertTrue(res["reproduced"])

    def test_cleartext_hardened_not_reproduced(self):
        res = parse_mobile(HARDENED_MANIFEST, _spec("cleartext"))
        self.assertFalse(res["reproduced"])

    def test_backup_allowed_reproduced(self):
        res = parse_mobile(VULNERABLE_MANIFEST, _spec("backup"))
        self.assertTrue(res["reproduced"])

    def test_backup_disallowed_not_reproduced(self):
        res = parse_mobile(HARDENED_MANIFEST, _spec("backup"))
        self.assertFalse(res["reproduced"])


class ParseIosAndSecretTests(unittest.TestCase):
    def test_ios_ats_arbitrary_loads_reproduced(self):
        res = parse_mobile(IOS_PLIST_ATS_DISABLED, _spec("cleartext"))
        self.assertTrue(res["reproduced"])
        self.assertIn("NSAllowsArbitraryLoads", res["coverage"]["covered_symbols"])

    def test_embedded_secret_reproduced(self):
        res = parse_mobile(STRINGS_WITH_SECRET, _spec("secret"))
        self.assertTrue(res["reproduced"])
        self.assertIn("secret", res["detail"].lower())

    def test_no_secret_not_reproduced(self):
        res = parse_mobile("<resources></resources>", _spec("secret"))
        self.assertFalse(res["reproduced"])


class ParseFramingTests(unittest.TestCase):
    def test_expect_pass_exploit_framing(self):
        res = parse_mobile(VULNERABLE_MANIFEST, _spec("exported", expect="pass"))
        self.assertTrue(res["reproduced"])
        self.assertIn("exploit assertion held", res["detail"])

    def test_expect_fail_invariant_framing(self):
        res = parse_mobile(VULNERABLE_MANIFEST, _spec("exported", expect="fail"))
        self.assertTrue(res["reproduced"])
        self.assertIn("broken invariant", res["detail"])

    def test_no_target_any_condition_reproduces(self):
        # Empty condition -> any provable insecure condition demonstrates the bug.
        res = parse_mobile(VULNERABLE_MANIFEST, _spec(""))
        self.assertTrue(res["reproduced"])

    def test_no_target_hardened_not_reproduced(self):
        res = parse_mobile(HARDENED_MANIFEST, _spec(""))
        self.assertFalse(res["reproduced"])


class SupportsTests(unittest.TestCase):
    def test_supports_mobile_app_only(self):
        r = MobileRunner()
        self.assertTrue(r.supports("MOBILE_APP"))
        self.assertTrue(r.supports("mobile_app"))
        self.assertFalse(r.supports("WEB_API"))
        self.assertFalse(r.supports(""))

    def test_name_is_mobile(self):
        self.assertEqual(MobileRunner().name, "mobile")


class RunStaticReadTests(unittest.TestCase):
    """Exercise run() WITHOUT apkanalyzer — static read of a materialized manifest in the workdir."""

    def _workdir_with(self, filename: str, content: str) -> str:
        d = tempfile.mkdtemp()
        (Path(d) / filename).write_text(content, encoding="utf-8")
        return d

    def test_run_static_read_vulnerable_reproduced(self):
        wd = self._workdir_with("AndroidManifest.xml", VULNERABLE_MANIFEST)
        spec = ReproSpec(harness_path="AndroidManifest.xml", kind="policy", test_name="exported")
        res = MobileRunner().run(wd, spec, timeout=5.0)
        self.assertTrue(res.ran)
        self.assertTrue(res.reproduced)
        self.assertEqual(res.runner, "mobile")
        self.assertTrue(res.artifact_paths)
        self.assertIn("covered_symbols", res.coverage)

    def test_run_static_read_hardened_not_reproduced(self):
        wd = self._workdir_with("AndroidManifest.xml", HARDENED_MANIFEST)
        spec = ReproSpec(harness_path="AndroidManifest.xml", kind="policy", test_name="exported")
        res = MobileRunner().run(wd, spec, timeout=5.0)
        self.assertTrue(res.ran)        # the inspection DID run
        self.assertFalse(res.reproduced)

    def test_run_workdir_scan_when_harness_is_dir(self):
        wd = self._workdir_with("AndroidManifest.xml", VULNERABLE_MANIFEST)
        spec = ReproSpec(harness_path="", kind="policy", test_name="debuggable")
        res = MobileRunner().run(wd, spec, timeout=5.0)
        self.assertTrue(res.ran)
        self.assertTrue(res.reproduced)


class RunGracefulTests(unittest.TestCase):
    """Tool-absent / missing-file paths must return ran=False, never raise, never hang."""

    def test_run_no_manifest_no_tool_did_not_run(self):
        wd = tempfile.mkdtemp()  # empty workdir, no apkanalyzer, no manifest
        spec = ReproSpec(harness_path="", kind="policy", test_name="exported")
        res = MobileRunner().run(wd, spec, timeout=5.0)
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)
        self.assertIn("candidate", res.detail.lower())

    def test_run_nonexistent_workdir_did_not_run(self):
        spec = ReproSpec(harness_path="x/y.apk", kind="policy", test_name="exported")
        res = MobileRunner().run("/nonexistent/path/p1hunt-test", spec, timeout=5.0)
        self.assertFalse(res.ran)
        self.assertFalse(res.reproduced)

    def test_run_with_empty_manifest_file_did_not_run(self):
        wd = tempfile.mkdtemp()
        (Path(wd) / "AndroidManifest.xml").write_text("   \n", encoding="utf-8")
        spec = ReproSpec(harness_path="AndroidManifest.xml", kind="policy", test_name="exported")
        res = MobileRunner().run(wd, spec, timeout=5.0)
        self.assertFalse(res.ran)


if __name__ == "__main__":
    unittest.main()
