import datetime as dt
import importlib.util
import json
import os
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("uae_scope", os.path.join(ROOT, "scripts", "uae_scope.py"))
U = importlib.util.module_from_spec(spec)
spec.loader.exec_module(U)

import sys  # noqa: E402
sys.path.insert(0, os.path.join(ROOT, "engine"))
import authorization  # noqa: E402
from scope import Scope  # noqa: E402

TODAY = dt.date(2026, 11, 24)


class UaeScopeTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "policies"))
        open(os.path.join(self.dir, "policies", "p.pdf"), "w").close()
        self.entry = {"id": "demo", "name": "Demo", "policy_url": "https://demo.example/policy",
                      "status": "active", "verified_on": "2026-11-20", "policy_copy": "policies/p.pdf",
                      "in_scope": ["demo.example.ae"], "seeds": ["https://demo.example.ae"],
                      "rate_limit_rps": 2}
        self.reg = os.path.join(self.dir, "register.json")
        self._write()

    def _write(self):
        with open(self.reg, "w") as fh:
            json.dump({"max_verification_age_days": 30, "programs": [self.entry]}, fh)

    def test_builds_scope_that_passes_engine_authorization(self):
        out = os.path.join(self.dir, "scopes", "demo.json")
        self.assertEqual(U.main(["build", "demo", "--out", out], self.reg, TODAY), 0)
        raw = json.load(open(out))
        self.assertEqual(raw["rate_limit_rps"], 2)
        self.assertEqual(authorization.check(raw, out, TODAY), [])
        self.assertEqual(authorization.enforce(Scope(raw["in_scope"]), raw, out, TODAY), "authorized")

    def test_refuses_unverified_entry(self):
        self.entry["status"] = "to-verify"
        self._write()
        self.assertEqual(U.main(["build", "demo", "--out", os.path.join(self.dir, "x.json")], self.reg, TODAY), 1)

    def test_refuses_stale_entry(self):
        self.entry["verified_on"] = "2026-08-01"
        self._write()
        self.assertTrue(U.problems(self.entry, self.dir, 30, TODAY))

    def test_shipped_register_is_valid_and_nothing_is_preapproved(self):
        reg = U.load()
        ids = [e["id"] for e in reg["programs"]]
        self.assertEqual(len(ids), len(set(ids)))
        for e in reg["programs"]:
            self.assertNotEqual(e["status"], "active", f"{e['id']} must be verified by the operator first")


if __name__ == "__main__":
    unittest.main()
