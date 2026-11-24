#!/usr/bin/env python3
"""
uae_scope.py — turn a verified entry of programs/uae/register.json into an engine scope file.

  python3 scripts/uae_scope.py list
  python3 scripts/uae_scope.py build <program-id> [--out programs/uae/scopes/<id>.json]

`build` refuses unless the entry is status=active, verified within the register's
max age (30 days), has in-scope assets and seeds, and its saved policy copy exists.
The output carries the `authorization` block that engine/authorization.py checks.
"""
import argparse
import datetime as dt
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTER = os.path.join(ROOT, "programs", "uae", "register.json")


def load(path=REGISTER):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def problems(entry, base_dir, max_age, today=None):
    today = today or dt.date.today()
    out = []
    if entry.get("status") != "active":
        out.append(f"status is {entry.get('status')!r}, not 'active'")
    try:
        age = (today - dt.date.fromisoformat(entry.get("verified_on") or "")).days
        if age < 0 or age > max_age:
            out.append(f"verified_on is {age} days old (max {max_age})")
    except ValueError:
        out.append("verified_on is missing or not YYYY-MM-DD")
    if not entry.get("in_scope"):
        out.append("in_scope is empty")
    if not entry.get("seeds"):
        out.append("seeds is empty")
    if not str(entry.get("policy_url", "")).startswith("https://"):
        out.append("policy_url must be https://")
    copy = entry.get("policy_copy") or ""
    if not copy or not os.path.isfile(os.path.join(base_dir, copy)):
        out.append("policy_copy is missing (save the policy under programs/uae/policies/)")
    return out


def build(entry, base_dir, out_path):
    policy_abs = os.path.join(base_dir, entry["policy_copy"])
    return {
        "name": entry["id"],
        "in_scope": entry["in_scope"],
        "out_of_scope": entry.get("out_of_scope", []),
        "seeds": entry["seeds"],
        "rate_limit_rps": entry.get("rate_limit_rps"),
        "required_headers": entry.get("required_headers", {}),
        "rules": entry.get("rules", []),
        "authorization": {
            "program": entry["name"],
            "policy_url": entry["policy_url"],
            "verified_on": entry["verified_on"],
            "policy_copy": os.path.relpath(policy_abs, os.path.dirname(os.path.abspath(out_path))),
            "intrusive_allowed": bool(entry.get("intrusive_allowed")),
        },
    }


def main(argv=None, register_path=REGISTER, today=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    b = sub.add_parser("build")
    b.add_argument("id")
    b.add_argument("--out")
    a = ap.parse_args(argv)
    reg = load(register_path)
    base = os.path.dirname(os.path.abspath(register_path))
    max_age = int(reg.get("max_verification_age_days", 30))
    entries = {e["id"]: e for e in reg.get("programs", [])}
    if a.cmd == "list":
        for e in entries.values():
            p = problems(e, base, max_age, today)
            print(f"{e['id']:28} {'USABLE' if not p else 'not usable: ' + '; '.join(p)}")
        return 0
    if a.id not in entries:
        print(f"unknown program id {a.id!r}; known: {', '.join(entries)}", file=sys.stderr)
        return 2
    e = entries[a.id]
    p = problems(e, base, max_age, today)
    if p:
        print(f"REFUSING to build a scope for {a.id}:\n  - " + "\n  - ".join(p), file=sys.stderr)
        return 1
    out = a.out or os.path.join(base, "scopes", f"{a.id}.json")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(build(e, base, out), fh, indent=2)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
