import http.server
import subprocess
import threading
import unittest
import urllib.request

import egress_proxy as E
from scope import Scope


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(["example.ae", "127.0.0.1"], ["admin.example.ae"])
        self.policy = E.EgressPolicy(self.scope, rate=0)

    def test_in_scope_is_target(self):
        self.assertEqual(self.policy.classify("api.example.ae")[0], "target")

    def test_out_of_scope_rule_denies(self):
        self.assertEqual(self.policy.classify("admin.example.ae")[0], "deny")

    def test_unknown_host_denied_by_default(self):
        ok, reason = self.policy.check("google.com")
        self.assertFalse(ok)
        self.assertIn("default deny", reason)
        self.assertEqual(self.policy.blocked[-1][1], "google.com")

    def test_infra_allowlist(self):
        self.assertEqual(self.policy.classify("api.anthropic.com")[0], "infra")
        self.assertEqual(self.policy.classify("evilapi.anthropic.com.attacker.io")[0], "deny")

    def test_out_of_scope_beats_infra(self):
        p = E.EgressPolicy(Scope(["example.ae"], ["crt.sh"]), rate=0)
        self.assertEqual(p.classify("crt.sh")[0], "deny")


class TokenBucketTests(unittest.TestCase):
    def test_limits_rate(self):
        now = [0.0]
        slept = []

        def sleep(d):
            slept.append(d)
            now[0] += d
        b = E.TokenBucket(2, clock=lambda: now[0], sleep=sleep)
        for _ in range(6):
            b.acquire()
        # 2 burst tokens free, then 4 more at 2/s => ~2s of waiting
        self.assertAlmostEqual(sum(slept), 2.0, places=3)

    def test_zero_rate_unlimited(self):
        self.assertEqual(E.TokenBucket(0).acquire(), 0.0)


class _Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ProxyRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Hello)
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()
        cls.logs = []
        cls.proxy = E.EgressProxy(Scope(["127.0.0.1"]), rate=50, log=cls.logs.append).start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.origin.shutdown()

    def _open(self, url):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": self.proxy.url}))
        return opener.open(url, timeout=10)

    def test_in_scope_request_passes(self):
        port = self.origin.server_address[1]
        self.assertEqual(self._open(f"http://127.0.0.1:{port}/").read(), b"hello")

    def test_out_of_scope_request_blocked(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self._open("http://out-of-scope.invalid/")
        self.assertEqual(cm.exception.code, 403)
        self.assertTrue(any("BLOCKED" in m for m in self.logs))

    @unittest.skipUnless(__import__("shutil").which("curl"), "curl not installed")
    def test_connect_blocked(self):
        r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_connect}", "-x", self.proxy.url,
                            "https://out-of-scope.invalid/"], capture_output=True, text=True, timeout=20)
        self.assertEqual(r.stdout.strip(), "403")


class EnvTests(unittest.TestCase):
    def test_export_sets_and_clears(self):
        env = {"NO_PROXY": "*", "no_proxy": "*"}
        E.export_proxy_env("http://127.0.0.1:1", env)
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:1")
        self.assertNotIn("NO_PROXY", env)
        self.assertNotIn("no_proxy", env)


if __name__ == "__main__":
    unittest.main()
