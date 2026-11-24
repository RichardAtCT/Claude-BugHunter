# UAE authorised-program register

This fork is set up for bug hunting in or for the UAE. Read this before any test.

## The legal line

- **Federal Decree-Law No. 34 of 2021** (Combatting Rumours and Cybercrimes, in force
  2 January 2022) has specific offences for unauthorised access to information systems,
  with heavier penalties for banking, health, media and scientific institutions and for
  government data. **There is no security-research exemption.** Authorisation is the
  only defence.
- **Personal data:** Federal Decree-Law 45/2021 (PDPL), plus the DIFC and ADGM regimes
  for entities in those free zones.
- So: written authorisation (a published program policy, a platform invitation, or a
  signed engagement) must exist **before the first request**, and you keep a dated copy.
- Get a one-off review from a UAE-qualified lawyer before your first submission.

This is a summary to keep you careful, not legal advice.

## Rules this fork enforces in code

| Rule | Where |
|---|---|
| Live targets need an `authorization` block (program, policy URL, verified within 30 days, saved policy copy) | `engine/authorization.py` |
| All traffic goes through a default-deny scope proxy; out-of-scope hosts get 403 | `engine/egress_proxy.py` |
| Global rate limit, default 5/s, lowered to the program's `rate_limit_rps` | `engine/egress_proxy.py`, `engine/engine.py` |
| `--hunt` on live targets needs a locked network (or explicit `--soft-egress`) | `engine/engine.py`, `docker/` |
| Agents get no `python3` unless the network is locked; curl proxy-bypass flags are denied | `engine/agent.py` |
| `--allow-intrusive` needs `"intrusive_allowed": true` from the program | `engine/engine.py` |
| Breach/infostealer lookups, people OSINT and live secret validation are disabled | `skills/offensive-osint`, `skills/osint-methodology` |
| `/autopilot --yolo` is removed | `commands/autopilot.md` |

## Rules you follow

- Only assets listed in the live program scope. Government (`.gov.ae`), banks, health and
  critical infrastructure only through the national VDP or their own published program.
- No DoS or load testing, no social engineering or phishing, no physical testing, no use
  of leaked or found credentials.
- Stop at the first proof of impact. If you reach personal data, stop, keep only what
  proves the issue, and report.
- Follow each program's rate limits, required headers and test-account rules.
- Test from an identifiable source; no anonymising infrastructure unless the program allows it.
- Never publish a finding without the program's permission.

## Workflow

1. **Verify** a program: read its live policy, save a copy (PDF or HTML) to
   `policies/<id>-<YYYY-MM-DD>.pdf`, and fill in `in_scope`, `out_of_scope`, `seeds`,
   `rate_limit_rps`, `required_headers`, `rules` in `register.json`. Set `status` to
   `active` and `verified_on` to today.
2. **Build** a scope file: `python3 scripts/uae_scope.py build <id>`. It refuses
   inactive, stale or empty entries and writes `scopes/<id>.json`.
3. **Map** (no agents): `python3 engine/engine.py --scope programs/uae/scopes/<id>.json`
4. **Hunt** only in the locked container: see `docker/README.md`.
5. **Report** through the program's platform. Keep the engagement folder as your record.
6. **Re-verify** every 30 days, or whenever the program changes its policy.

`python3 scripts/uae_scope.py list` shows every entry and whether it is usable.

Generated scope files and saved policies are git-ignored, because a fork of a public
repo is public.

## Adding a platform program (HackerOne, Bugcrowd, Intigriti, YesWeHack)

Copy any entry, set `platform` and `policy_url` to the program page, and paste the
in-scope assets exactly as the program lists them. Platform programs often require a
header such as `X-Bug-Bounty: <your-username>`: put it in `required_headers`.

## Sources

- UAE National Vulnerability Disclosure Policy: https://u.ae/en/about-the-uae/strategies-initiatives-and-awards/policies/cyber-activities/National-Vulnerability-Disclosure-Policy
- National Bug Bounty Programme (2021): https://www.khaleejtimes.com/business/local/uae-cybersecurity-council-launches-national-bug-bounty-programme
- Clyde & Co on Decree-Law 34/2021: https://www.clydeco.com/en/insights/2022/03/uae-updates-cybercrime-law
- u.ae on the cybercrime law: https://u.ae/en/information-and-services/justice-safety-and-the-law/cyber-safety-and-digital-security/law-on-combatting-rumours-and-cybercrimes
