#!/usr/bin/env python3
"""
egress_proxy.py — scope-enforcing, rate-limited egress proxy.

Why: scope used to be enforced only on what the engine *handed* an agent, plus an
after-the-fact audit. An agent (or a tool such as katana/gau) could still send a
request to an out-of-scope host. In jurisdictions with strict computer-misuse law
(e.g. UAE Federal Decree-Law 34/2021, which has no security-research exemption) one
stray request is the legal risk. This proxy makes scope a *network* fact:

  * CONNECT (HTTPS) and absolute-URI HTTP requests are allowed only when the
    destination host is in scope (scope.py rules: default-deny, deny wins), or is
    on the small infrastructure allowlist (the Anthropic API for the agents, and
    passive archive sources for gau / crt.sh).
  * Every connection/request to an in-scope target passes a global token-bucket
    rate limiter (default 5/s). Infrastructure hosts are not rate limited.
  * Every blocked attempt is logged, and counted, so the operator sees it.

Two ways to use it:
  1. In-process (default): engine.py starts it on 127.0.0.1 and exports
     HTTP(S)_PROXY to every child process (curl, katana, gau, claude). This is a
     SOFT boundary: a process can ignore proxy env vars.
  2. Hard mode (recommended for live targets): run this file as its own container
     that is the only route out of an `internal` Docker network (see docker/).
     Then nothing in the engine container can reach the internet except via here.

  python3 engine/egress_proxy.py --scope my-engagement.json --bind 0.0.0.0 --port 8888 --rate 5
"""
import argparse
import json
import os
import select
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scope import Scope, _match  # noqa: E402

# Hosts the engine itself needs that are NOT targets. Kept deliberately small.
DEFAULT_INFRA_ALLOW = [
    "api.anthropic.com",          # headless `claude -p` agents
    "web.archive.org",            # gau (passive, historical)
    "index.commoncrawl.org",      # gau
    "otx.alienvault.com",         # gau
    "urlscan.io",                 # gau
    "crt.sh",                     # certificate transparency (osint.py)
]


class TokenBucket:
    """Thread-safe token bucket. rate tokens/second, burst = max(1, rate)."""

    def __init__(self, rate, clock=time.monotonic, sleep=time.sleep):
        self.rate = float(rate)
        self.capacity = max(1.0, self.rate)
        self.tokens = self.capacity
        self._clock, self._sleep = clock, sleep
        self.last = clock()
        self.lock = threading.Lock()

    def acquire(self):
        if self.rate <= 0:
            return 0.0
        waited = 0.0
        while True:
            with self.lock:
                now = self._clock()
                self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return waited
                need = (1 - self.tokens) / self.rate
            self._sleep(need)
            waited += need


class EgressPolicy:
    """Decide allow / deny for a destination host. Pure logic, no sockets (testable)."""

    def __init__(self, scope, infra_allow=None, rate=5.0):
        self.scope = scope
        self.infra_allow = [h.lower() for h in (DEFAULT_INFRA_ALLOW if infra_allow is None else infra_allow)]
        self.bucket = TokenBucket(rate)
        self.blocked = []                 # [(ts, host, reason)]
        self.allowed_target = 0
        self.lock = threading.Lock()

    def classify(self, host):
        """-> ('target'|'infra'|'deny', reason)."""
        host = (host or "").lower().rstrip(".")
        if not host:
            return "deny", "no host"
        if self.scope.in_scope_host(host):
            return "target", "in scope"
        # infra hosts are exact-or-subdomain matches, but never override an explicit
        # out-of-scope rule (deny wins everywhere).
        if any(_match(p, host) for p in self.scope.out_of_scope):
            return "deny", f"{host} matches an out-of-scope rule"
        if any(host == h or host.endswith("." + h) for h in self.infra_allow):
            return "infra", "infrastructure allowlist"
        return "deny", self.scope.reject_reason(host) or "not allowed"

    def check(self, host):
        kind, reason = self.classify(host)
        if kind == "deny":
            with self.lock:
                self.blocked.append((time.time(), host, reason))
            return False, reason
        if kind == "target":
            self.bucket.acquire()
            with self.lock:
                self.allowed_target += 1
        return True, reason


def _make_handler(policy, log):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 60

        def log_message(self, fmt, *args):   # quiet default access log
            pass

        def _deny(self, host, reason):
            log(f"egress: BLOCKED {self.command} {host} — {reason}")
            body = f"blocked by scope egress proxy: {host}: {reason}\n".encode()
            self.send_response(403, "Forbidden by scope")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_CONNECT(self):
            host, _, port = self.path.rpartition(":")
            host = host.strip("[]")
            ok, reason = policy.check(host)
            if not ok:
                return self._deny(host, reason)
            try:
                upstream = socket.create_connection((host, int(port or 443)), timeout=30)
            except OSError as e:
                self.send_error(502, f"upstream connect failed: {e}")
                return
            self.send_response(200, "Connection established")
            self.end_headers()
            self._pipe(self.connection, upstream)

        def _pipe(self, a, b):
            socks = [a, b]
            try:
                while True:
                    r, _, x = select.select(socks, [], socks, 60)
                    if x or not r:
                        break
                    for s in r:
                        data = s.recv(65536)
                        if not data:
                            return
                        (b if s is a else a).sendall(data)
            except OSError:
                pass
            finally:
                b.close()
                self.close_connection = True

        def _forward(self):
            parts = urlsplit(self.path)
            host = parts.hostname or ""
            ok, reason = policy.check(host)
            if not ok:
                return self._deny(host, reason)
            port = parts.port or 80
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            try:
                up = socket.create_connection((host, port), timeout=30)
            except OSError as e:
                self.send_error(502, f"upstream connect failed: {e}")
                return
            hdrs = [f"{self.command} {path} HTTP/1.1"]
            for k, v in self.headers.items():
                if k.lower() in ("proxy-connection", "proxy-authorization", "connection", "keep-alive"):
                    continue
                hdrs.append(f"{k}: {v}")
            hdrs.append("Connection: close")
            up.sendall(("\r\n".join(hdrs) + "\r\n\r\n").encode("latin-1") + body)
            try:
                while True:
                    chunk = up.recv(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            except OSError:
                pass
            finally:
                up.close()
                self.close_connection = True

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _forward

    return Handler


class EgressProxy:
    def __init__(self, scope, bind="127.0.0.1", port=0, rate=5.0, infra_allow=None, log=print):
        self.policy = EgressPolicy(scope, infra_allow, rate)
        self.server = ThreadingHTTPServer((bind, port), _make_handler(self.policy, log))
        self.server.daemon_threads = True
        self.thread = None

    @property
    def url(self):
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


PROXY_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy")


def export_proxy_env(url, environ=None):
    """Point every child process at the proxy and drop bypass lists."""
    env = os.environ if environ is None else environ
    for k in PROXY_ENV_KEYS:
        env[k] = url
    for k in ("NO_PROXY", "no_proxy"):
        env.pop(k, None)
    return env


def direct_egress_open(probe=("1.1.1.1", 443), timeout=3):
    """True if this process can open a direct (non-proxied) TCP connection to the
    internet. Hard mode requires this to be False."""
    try:
        with socket.create_connection(probe, timeout=timeout):
            return True
    except OSError:
        return False


def _main(argv=None):
    ap = argparse.ArgumentParser(description="scope-enforcing egress proxy")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--rate", type=float, default=5.0, help="max new requests/connections per second to targets")
    a = ap.parse_args(argv)
    scope = Scope.load(a.scope)
    raw = json.load(open(a.scope, encoding="utf-8"))
    infra = DEFAULT_INFRA_ALLOW + list(raw.get("infra_allow", []))
    p = EgressProxy(scope, a.bind, a.port, a.rate, infra, log=lambda m: print(m, flush=True))
    print(f"egress proxy for scope={scope.name} on {p.url} rate={a.rate}/s infra={infra}", flush=True)
    try:
        p.server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    _main()
