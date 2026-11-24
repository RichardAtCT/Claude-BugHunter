# Hard-egress mode

Running the engine on your own machine starts an **in-process** scope proxy and points
every child process at it with `HTTP(S)_PROXY`. That stops accidents, but a process can
ignore proxy variables, so it is a *soft* boundary. For that reason `--hunt` against a
live target refuses to start when the process can reach the internet directly, unless
you pass `--soft-egress`.

This folder gives the **hard** boundary:

- `engine` runs on a Docker network with `internal: true`, so it has no route out.
- `egress` (`engine/egress_proxy.py`) is the only bridge. It forwards a connection only
  when the host is in the scope file (default-deny, out-of-scope rules win), or is on a
  short infrastructure list (Anthropic API, web.archive.org, crt.sh and similar passive
  sources). Target traffic is rate limited (default 5 new connections per second).
- Every blocked attempt is logged by the `egress` container.

## Run

```bash
export ANTHROPIC_API_KEY=...            # or log in inside the container
export SCOPE_DIR=$PWD/programs/uae/scopes  # scope JSON + saved policy copies live here
export SCOPE_NAME=my-program.json
export RATE=2                            # follow the program's rate limit
docker compose -f docker/compose.yml run --rm engine --scope /scope/$SCOPE_NAME --base /out
docker compose -f docker/compose.yml run --rm engine --scope /scope/$SCOPE_NAME --base /out --hunt
docker compose -f docker/compose.yml logs egress   # see what was blocked
```

The whole `SCOPE_DIR` is mounted read-only at `/scope`, and `authorization.policy_copy`
is resolved relative to the scope file, so keep the saved policy next to it.

## Check the lock before a live run

```bash
docker compose -f docker/compose.yml run --rm --entrypoint curl engine -sS -m 5 --noproxy '*' https://example.com
# must FAIL (no route). If it succeeds, do not hunt.
```
