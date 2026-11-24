import datetime as dt
import os
import tempfile
import unittest

import authorization as A
from scope import Scope

TODAY = dt.date(2026, 11, 24)


class LabScopeTests(unittest.TestCase):
    def test_lab_scopes(self):
        self.assertTrue(A.is_lab_scope(Scope(["localhost", "127.0.0.1", "10.0.0.0/8", "juice.test"])))

    def test_live_scope(self):
        self.assertFalse(A.is_lab_scope(Scope(["localhost", "example.ae"])))
        self.assertFalse(A.is_lab_scope(Scope(["re:^api\\.local$"])))

    def test_lab_needs_no_auth(self):
        self.assertEqual(A.enforce(Scope(["localhost"]), {}), "lab")


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.scope_path = os.path.join(self.dir, "scope.json")
        open(os.path.join(self.dir, "policy.pdf"), "w").close()
        self.auth = {"program": "P", "policy_url": "https://p.example/policy",
                     "verified_on": "2026-11-20", "policy_copy": "policy.pdf"}

    def test_complete_record_passes(self):
        self.assertEqual(A.check({"authorization": self.auth}, self.scope_path, TODAY), [])

    def test_missing_block(self):
        self.assertTrue(A.check({}, self.scope_path, TODAY))

    def test_stale_verification(self):
        self.auth["verified_on"] = "2026-09-01"
        self.assertTrue(any("days old" in p for p in A.check({"authorization": self.auth}, self.scope_path, TODAY)))

    def test_missing_policy_copy(self):
        self.auth["policy_copy"] = "nope.pdf"
        self.assertTrue(any("not found" in p for p in A.check({"authorization": self.auth}, self.scope_path, TODAY)))

    def test_enforce_refuses_live_without_auth(self):
        with self.assertRaises(SystemExit):
            A.enforce(Scope(["example.ae"]), {}, self.scope_path, TODAY)


if __name__ == "__main__":
    unittest.main()
