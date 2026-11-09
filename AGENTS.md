# nettrace: context for AI assistants

Read this first. It covers what the tool is for, the rules it must keep, where the code lives,
and where to look next. Detail lives in `docs/`:

| File | Read it when |
|---|---|
| `docs/architecture.md` | changing the engine, adding a driver, or debugging a trace |
| `docs/gaps-and-roadmap.md` | picking up the next piece of work, or judging whether a result can be trusted |
| `docs/decisions.md` | wondering why something is built the way it is (and before reversing it) |
| `README.md` | user-facing install, configuration and command reference |

## Intent

The owner runs a mixed network:
- Cisco routers (mostly IOS-XE);
- Palo Alto firewalls on-prem and VM-Series on EC2, managed by **Panorama**;
- Prisma Access (mobile users, remote networks, service connections);
- AWS across several accounts and regions (Transit Gateways, VPCs, security groups, NACLs, GWLB).

`nettrace` takes a source IP, a destination IP and optionally a port and protocol. It walks the path
hop by hop and asks each component live how it would handle that flow: routing, ACLs, NAT, firewall
policy, security groups and NACLs. It then prints a per-hop PASS/BLOCK table in the terminal. The goal is
to answer "why can't A reach B on port X, and where exactly does it stop?" without logging into five
consoles.

CLI style copies the AWS CLI: `nettrace <service> <command> --flags`, with `--output table|json|text`
and `--query` (JMESPath) accepted anywhere on the line.

## Hard rules (do not break)

1. **Read-only, always.** Nothing nettrace sends may change state. This is enforced in code by
   `src/nettrace/readonly.py`, and every new request path must go through it:
   - Cisco: an ALLOWLIST of full-word `show` commands (`readonly.check_cisco_command`; IOS abbreviates, so never a
     deny list or prefix rule); arguments are only IPv4 addresses and `safe_token` names. Same guard for the console.
   - PAN-OS/Panorama XML API: `type=op` with `<show>` or `<test>` roots only, or `type=config` with
     `action=get|show`. Never `set`, `edit`, `delete`, `commit`, `request` or `<request>`. Only the
     parameters `type, cmd, action, xpath, target, vsys` are allowed, and `target` must be a plain
     serial. Never run `test ...-policy-match` or `fib-lookup` on Panorama itself; always send them
     with `target=<firewall serial>`.
   - Strata Cloud Manager: HTTP GET only. The OAuth token POST is the one exception.
   - PAN-OS `<test>` may only contain `security-policy-match`, `nat-policy-match`, or `routing` /
     `advanced-routing` with `fib-lookup`. PAN-OS and SCM requests never follow redirects
     (`allow_redirects=False`; a 3xx is a `DeviceError`), so API keys and tokens go to the configured host only.
   - The web console accepts an exact command list only (no raw XML; Cisco = the allowlist above, nothing else).
     Device I/O runs under a per-device lock (a second command to a busy device gets 429); the global `console_lock`
     guards only the session table and rate limit, so one slow device never blocks the others. `App.history` is
     under `history_lock`. POST bodies must arrive within `BODY_DEADLINE` (10 s) or the answer is 408.
   - Every request sent or refused is appended to the audit log (`src/nettrace/audit.py`,
     `~/.local/state/nettrace/audit.log`, override `NETTRACE_AUDIT_LOG`; tests must set it; a symlinked log or
     directory is never followed, the file is 0600; demo-lab runs add `"demo": true`). Requests only,
     never responses or credentials. This includes the SCM token POST and Netmiko's login prep (`terminal length/width`, `enable`). New request paths must call `audit.log` / `audit.refused`.
   - AWS: a botocore `before-call` hook allows only an exact allowlist of (service, operation) pairs
     (the EC2 reads in `iam/nettrace-readonly-policy.json`) and `sts:AssumeRole` (900 s, that policy as the
     inline session `Policy`, which fails closed: packaged in `nettrace/data/`, AssumeRole is refused if it cannot be
     loaded or is over 2048 chars unless `NETTRACE_ALLOW_NO_SESSION_POLICY=1`; session name `nettrace-<user>-<host>`, re-assumed once on `ExpiredToken`;
     cross-account roles need `external_id_env` when `aws.base_account_id` is set, else a warning).
     Do **not** add Reachability Analyzer or Network Access Analyzer calls. Those
     create resources and cost money per run (see `docs/decisions.md`).
2. **Live data first.** The owner wants answers from the devices as they are now, not a simulation of
   configs. PAN-OS hops ask the firewall itself (`test ...-policy-match`, `fib-lookup`). Only fall back to
   evaluating configuration where no live API exists (Prisma Access policy; AWS, whose control plane
   *is* configuration).
3. **Never guess.** If a rule or ACL entry depends on something nettrace can't evaluate (App-ID, user
   groups, object-groups, FQDN objects, URL categories), report it as uncertain (`UNKNOWN`/`WARN`, or an
   `uncertain` list). Never assume it matched or didn't match. A query the device failed to answer
   (`panos.Unavailable`) is not "not configured". A deny or an allow below an uncertain Prisma rule is UNKNOWN (a rule with a `schedule` is uncertain). A Cisco ingress inferred from the route back is WARN. Cisco ECMP
   and policy routing are WARN (alternatives listed), never a silent pick. Several ENIs with one IP raise
   `AmbiguousEni`. A trace has an overall deadline (`errors.Deadline`, default 120 s, `trace_timeout` /
   `--timeout`); every new request path must call `deadline.check()` before it sends (it also raises `Cancelled`
   when the user cancels from the web UI or Ctrl-C; that ends INCOMPLETE "cancelled by user" with the hops so far). A trace with any UNKNOWN hop never ends
   REACHABLE or EXITED: the engine downgrades it to INCOMPLETE (exit 4). Any driver exception becomes an UNKNOWN hop
   (hops so far are kept). Parser failures raise `DeviceError`; they never mean "no rows".
4. **Credentials come from environment variables only.** The inventory names the variables
   (`*_env` keys) and never holds secrets. Never print credential values, including in
   `configure check` and evidence output.
5. **Escape device-bound values.** PAN-OS op XML is built with ElementTree (`build_op`). Cisco tokens
   (ACL, VRF and interface names) go through `safe_token`. Don't build commands with f-strings from
   untrusted input.
6. **Simulation goes only through the transport seams.** These are `CiscoClient.connection_override`,
   `XmlApi.session_override`, `ScmClient.transport_override` and `AwsEnv.backend_override`. The demo
   lab (`nettrace.demo.lab.install()`) and tests plug in there, *below* the read-only guards. Driver,
   engine and guard code must never branch on "demo". `AwsEnv` with a backend still applies
   the same allowlist (`check_aws_operation`).
7. **The web server stays local and authenticated.** It binds to 127.0.0.1, checks the per-run session
   secret (the `X-Nettrace-Token` header for scripts/tests, or the `nettrace_session` cookie, which must be sent with the
   custom header `X-Nettrace-Client: 1`), the Host and Origin headers, and JSON-only bodies up to 64 KiB. The cookie
   (`HttpOnly; SameSite=Strict; Path=/`, session-only, no Domain/Max-Age) is issued by `GET /?c=<code>`, where the code is a
   separate one-time login code (60 s, single use, memory only). No route mints codes; restart for a new one. `POST /api/trace/cancel`
   `{id}` is one of those authenticated routes: it only sets a cooperative cancel flag (`CancelToken`) that the
   engine checks beside the deadline; it never kills a thread, and it is audit-logged (`status=cancelled`). Don't add a
   `--host` option, CORS, or unauthenticated API routes. Console commands must keep going through
   `CiscoClient.show` / `PanosClient.request`, so the guards apply. `serve` opens the browser by default (`--no-open` only prints the URL; `--open` is a no-op alias)
   at `http://127.0.0.1:PORT/?c=<code>` via `launch_browser`, which drops
   `NETTRACE_*`/`AWS_*` and credential-like names (`*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_KEY`, `*CRED*`) from the browser's environment.
   The code is in argv (visible to `ps`), which is acceptable only because it is single-use and expires in 60 s. Never pass the session
   secret in argv, env, a URL or a log; never log query strings. Console limits:
   one session per device, 1 s between commands, 60 s idle disconnect, 256 KiB output; Cisco SSH refuses
   logins for 5 min after an auth failure.
8. **TLS and SSH stay verified.** `verify_tls: false` under `defaults:` or `panorama:` needs env
   `NETTRACE_ALLOW_INSECURE_TLS=1` (per-device false is allowed with a warning); a string `verify_tls` must be an
   existing CA bundle. A missing/changed SSH host key is a `DeviceError` telling the user to verify with `ssh`;
   never suggest `ssh_strict: false` (in `defaults:` it needs `NETTRACE_ALLOW_INSECURE_SSH=1`; per device it warns by name). AWS clients use `boto_config()` (5 s connect, 20 s read, standard x3);
   PAN-OS/SCM reads retry once on a timeout only.
9. **Artifacts are private.** Maps go through `cli.write_private` (0600) and drop hop evidence unless
   `--with-evidence` (then the HTML shows a "do not share" banner). Evidence is capped (Cisco/PAN-OS 4000
   chars, AWS 1500, any `Evidence` 256 KiB).
10. **Device output is untrusted in the path map too.** Everything from a trace goes through
   `html.escape` in `viz/svg.py` and `esc()` in the viewer JS. The embedded trace JSON is
   `<`/`>`/`&`/U+2028-escaped (`_json_for_script`). The page's CSP is `default-src 'none'`; JSON and error responses carry it too. Keep the
   viewer free of external URLs so it works offline and can't leak trace data.

## Status (as of 2026-11-08)

- v0.4.0. It works end to end in simulation: a custom EC2 simulator for AWS (`demo/sim_aws.py`), canned Cisco, PAN-OS, Panorama and SCM
  answers. The demo lab's 12 presets all give their expected outcome (`tests/test_demo_presets.py`).
- Path maps: `trace run --map x.html|x.svg` / `--open` and `nettrace viz render` draw a NetBrain-style
  map from the trace JSON (`src/nettrace/viz/`). The HTML is a single offline file.
- Demo lab plus web UI:
  - `nettrace demo serve` and `nettrace serve` (real inventory) start a localhost UI with a topology
    canvas, multi-packet flow animation (play/pause/step/replay/speed; stepping while paused keeps the stream frozen), event list, inspector and read-only device console.
  - `--demo` on any command runs it against the simulated Acme Corp lab (`src/nettrace/demo/`).
  **It has never run against real devices, Panorama, Prisma Access or AWS accounts.**
- PAN-OS hops go **through Panorama** when the device has a `serial` and a `panorama:` section exists.
  Requests carry `target=<serial>`. Panorama also supplies HA state (passive members are redirected to
  the active peer) and device-group context. `via: direct` still talks straight to a firewall.
- It is not yet known whether Prisma Access is managed by **Panorama** (device groups such as
  `Mobile_User_Device_Group`) or by **Strata Cloud Manager**. The code assumes SCM. This is roadmap
  item R2.
- Test suite: `.venv/bin/pytest -q` (~446 tests: guards, hardening, audit/console scope, never-guess and robustness cases,
  ACL and netutil units, and all 12 demo presets). It uses the demo lab's simulators as the harness.

## Code map

```
src/nettrace/
  cli.py            click commands; AWS-style global-option hoisting; exit codes
  engine.py         Tracer: locate source -> loop {driver step -> resolve next position}
  steps.py          Position types (DeviceAt, AwsAt, PrismaAt), Egress, StepResult
  models.py         Flow, Hop, Evidence, Status, Outcome, TraceResult (+ to_dict for JSON)
  inventory.py      YAML loader/validator, IP->device lookups, links, discovery cache
  readonly.py       all read-only guards (see Hard rules)
  output.py         rich table / json / text renderers, JMESPath --query
  demo/
    lab.py          Acme Corp lab: one model for devices, AWS resources, inventory, topology layout, presets
    sim_cisco.py    IOS-XE show-command simulator (CEF/route/ARP/interfaces/ACLs/running-config)
    sim_panos.py    PAN-OS + Panorama XML API simulator (FIB, security/NAT match, devices, DG hierarchy)
    sim_scm.py      Strata Cloud Manager GET simulator
    sim_aws.py      EC2 Describe/Search simulator with per-account visibility and filters
  web/
    server.py       stdlib HTTP server: /api/bootstrap, /api/trace, /api/trace/cancel, /api/traces[/id], /api/console
    topology.py     hop -> topology node mapping (Locator, overlay) and auto topology from an inventory
    static/app.html the single-page UI (no external assets)
  viz/
    model.py        trace JSON -> PathMap (nodes, edges with SG/NACL badges, containers, layout)
    svg.py          static self-contained SVG (icons, boxes, badges, header)
    html.py         single-file offline viewer: SVG + hop list + evidence pane, pan/zoom, deep links
  netutil.py        protocol/port tables, prefix and wildcard matching
  credentials.py    env-var lookup
  drivers/
    cisco_iosxe.py  Netmiko client + per-hop evaluation (CEF, route, ACLs, ARP)
    cisco_acl.py    first-match ACL evaluator on ntc-templates output
    ntc.py          ntc-templates wrapper
    panos.py        XmlApi transport; PanosClient (direct or Panorama target=); PanoramaClient (devices,
                    HA, device groups, dg-hierarchy); make_client(); per-hop evaluation (zones, FIB,
                    NAT, security; GWLB inline mode)
    prisma.py       SCM client + config-based rule evaluator
    aws.py          AwsEnv (sessions, cached calls, lookups) + AwsWalker (SG/NACL/RT/TGW/GWLB/NAT/...)
inventory.example.yaml   annotated inventory; real one is inventory.yaml (git-ignored)
iam/nettrace-readonly-policy.json   minimal IAM policy for the per-account role
```

## Working on it

```bash
cd tracer
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/nettrace --help
.venv/bin/nettrace -i inventory.example.yaml inventory list      # works offline
.venv/bin/nettrace demo scenarios                                # every preset's expected outcome
.venv/bin/nettrace demo serve                                    # UI on 127.0.0.1:8765
.venv/bin/pytest -q                                              # tests (set NETTRACE_AUDIT_LOG; conftest does)
.venv/bin/ruff check src --select F,E9,B --ignore B008           # lint used during build
```

- Python 3.10+ (developed on 3.15). Runtime dependencies are in `pyproject.toml`. `moto` (only a mocking option, no test imports it) and `ruff` were
  installed into `.venv` for development only.
- Quickest regression check: every preset in `nettrace.demo.lab.PRESETS` has an `expect` outcome.
  Run them all with `nettrace --demo trace run ... -o json` and compare. When changing a driver, also
  change the matching simulator if the device's real output format is what changed.
- To verify behaviour without real devices, you can also mock at the client boundary: `CiscoClient.show`,
  `requests.Session.post` for PAN-OS and Panorama (switch on URL and the `target` form field),
  `ScmClient.get_all`, and `moto.mock_aws()` (if installed) for AWS. Known moto
  gaps: it has no cross-account TGW, `SearchTransitGatewayRoutes` returns empty
  `TransitGatewayAttachments`, and the ENI filter `association.public-ip` is not implemented.
- Keep changes scoped: there is no CI, and the owner reviews diffs.
- Exit codes for `trace run`: 0 reachable or exited the known network (REACHABLE/EXITED, only with no UNKNOWN hops), 3 blocked,
  4 incomplete (the engine downgrades REACHABLE/EXITED with any UNKNOWN hop to INCOMPLETE; Ctrl-C/cancel also gives 4), 1 error, 2 usage error.
  `--output text` is kept: the README documents it (`--output text | grep ^HOP`).
