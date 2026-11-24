#!/usr/bin/env python3
"""
authorization.py — refuse to touch a live target without a recorded authorization.

A scope file for a real target must carry an `authorization` block that ties the
run to a published program (or signed engagement) the operator has checked recently:

  "authorization": {
    "program":     "UAE National Vulnerability Disclosure Policy",
    "policy_url":  "https://...",
    "verified_on": "2026-11-24",          # date you last read the live policy (YYYY-MM-DD)
    "policy_copy": "evidence/policy-2026-11-24.pdf"   # saved copy, relative to the scope file
  }

Lab scopes (only localhost / loopback / private ranges / .test / .local / .localhost)
need no authorization block, so DVWA / Juice Shop / eval runs keep working.

`programs/uae/register.json` + `scripts/uae_scope.py` generate compliant scope files.
"""
import datetime as _dt
import ipaddress
import os

MAX_AGE_DAYS = 30
REQUIRED = ("program", "policy_url", "verified_on", "policy_copy")
_LAB_SUFFIXES = (".localhost", ".local", ".test", ".internal", ".lan")


def _is_lab_rule(rule):
    r = rule.strip().lower()
    if r.startswith("re:"):
        return False                      # can't prove a regex is lab-only
    if r.startswith("*."):
        r = r[2:]
    if r in ("localhost",) or r.endswith(_LAB_SUFFIXES):
        return True
    try:
        net = ipaddress.ip_network(r, strict=False)
        return net.is_private or net.is_loopback
    except ValueError:
        return False


def is_lab_scope(scope):
    return bool(scope.in_scope) and all(_is_lab_rule(r) for r in scope.in_scope)


def check(raw, scope_path=None, today=None, max_age_days=MAX_AGE_DAYS):
    """Return a list of problems (empty list == authorized)."""
    today = today or _dt.date.today()
    auth = raw.get("authorization")
    if not isinstance(auth, dict):
        return ["scope file has no `authorization` block (program, policy_url, verified_on, policy_copy)"]
    problems = [f"authorization.{k} is missing" for k in REQUIRED if not str(auth.get(k, "")).strip()]
    if problems:
        return problems
    if not str(auth["policy_url"]).startswith("https://"):
        problems.append("authorization.policy_url must be an https:// URL")
    try:
        verified = _dt.date.fromisoformat(str(auth["verified_on"]))
        age = (today - verified).days
        if age < 0:
            problems.append("authorization.verified_on is in the future")
        elif age > max_age_days:
            problems.append(f"authorization.verified_on is {age} days old (max {max_age_days}) — "
                            "re-read the live program policy and update it")
    except ValueError:
        problems.append("authorization.verified_on must be YYYY-MM-DD")
    copy = str(auth["policy_copy"])
    base = os.path.dirname(os.path.abspath(scope_path)) if scope_path else os.getcwd()
    if not os.path.isfile(copy if os.path.isabs(copy) else os.path.join(base, copy)):
        problems.append(f"authorization.policy_copy {copy!r} not found (save a copy of the policy you relied on)")
    return problems


def enforce(scope, raw, scope_path=None, today=None):
    """Raise SystemExit with a clear message if a live scope lacks authorization."""
    if is_lab_scope(scope):
        return "lab"
    problems = check(raw, scope_path, today)
    if problems:
        msg = ("REFUSING TO RUN: this scope targets live hosts but its authorization record is incomplete.\n  - "
               + "\n  - ".join(problems)
               + "\nOnly test assets a published program or signed engagement explicitly puts in scope.")
        raise SystemExit(msg)
    return "authorized"
