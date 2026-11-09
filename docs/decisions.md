# Decision log

Short records of choices made while building nettrace. Each one says why it was made, so a later
change can be judged against the original reason. Newest first.

## D13. Never-guess gaps closed, bounded waits, SSH/TLS edges (2026-11-08)
- **An unanswered question is not "no".** `PanosClient.config_get` returns `Unavailable(reason)` when the
  device errors or times out, and `None` only when the device answered "not configured". `_lookup`
  raises `DeviceError` (hop UNKNOWN, trace INCOMPLETE) when nothing was found and any query went
  unanswered. A hit after a failed query still wins.
- **Prisma:** a deny reached below rules nettrace could not evaluate is UNKNOWN, not BLOCK (an earlier
  rule might have allowed it). An app that is not listed in a rule is uncertain when the rule lists an
  application group or filter, or when those objects can't be read. Known assumption kept:
  `application-default` with `--application` is taken to mean the app's standard port.
- **Cisco:** ECMP (several CEF next hops) is WARN and lists every path; only the first is followed.
  Policy routing on the ingress interface (`Policy routing is enabled, using route-map X` in
  `show ip interface`, which the ntc template drops) is WARN, and a no-route/discard result there is
  UNKNOWN, since PBR may rescue it. Route-maps are not evaluated.
- **Time budget:** one `Deadline` per trace (default 120 s; inventory `trace_timeout`, CLI `--timeout`).
  Every request path checks it before sending; expiry raises `DeadlineExceeded`, which the engine turns
  into an UNKNOWN hop plus INCOMPLETE, keeping the hops so far. A request already in flight is bounded
  by its own timeout, not interrupted. botocore uses connect 5 s, read 20 s, standard retries x3.
  PAN-OS POSTs and SCM GETs retry once, on a timeout only (everything is read-only, so a retry has no
  side effects; the token POST is never retried).
- **Overlapping IP space:** `find_eni` takes an optional `vpc_id` filter. Several distinct ENIs for one
  IP raise `AmbiguousEni` listing them (the same ENI seen from two accounts counts once); nettrace does
  not pick one.
- **SSH:** a paramiko `SSHException` from the host-key check becomes a `DeviceError` (not in known_hosts:
  ssh once to verify; changed key: possible spoofing). `ssh_strict: false` is still not advised.
- **TLS:** `verify_tls: false` under `defaults:` or `panorama:` is refused unless
  `NETTRACE_ALLOW_INSECURE_TLS=1`; per-device `false` still works (with the warning). A string must be
  an existing CA bundle path at inventory load.
- **Cisco commands are an allowlist, not a deny list (re-audit R1):** IOS accepts abbreviations (`show run`),
  so `readonly.check_cisco_command` matches only full-word commands (a short fixed set plus IP / `safe_token`
  arguments) and the web console uses the same guard. The demo simulator expands abbreviations like IOS.
- **The AWS session policy fails closed (R6):** it ships as package data (`nettrace/data/`, equal to `iam/`;
  a test checks it) and AssumeRole is refused if it cannot be loaded or exceeds 2048 characters, unless
  `NETTRACE_ALLOW_NO_SESSION_POLICY=1`.

## D12. Demo lab simulates transports; web UI is a local stdlib server (2026-11-08, v0.4.0)
The owner asked for a demo architecture to show the tool off, with a live localhost UI in the
style of Packet Tracer, CML or NetBrain.
- **Simulate below the guards, not above them.** Four seams were added: the Cisco connection, the
  XML API session, the SCM page fetch and the AWS backend. Everything above them (drivers, engine,
  read-only guards, Panorama HA follow, NAT lookup chain) is the production code. The demo exercises
  it rather than a parallel fake, and a console "write" in the demo is refused by the real guard.
- **Simulators compute from one model, not canned replies.** Routing, ACLs, PAN-OS rule and NAT
  matching and AWS filters are all evaluated from `demo/lab.py`, so arbitrary flows work and
  the presets don't drift from the model.
- **The AWS simulator replaces moto for the demo.** moto can't do cross-account TGW, leaves
  `TransitGatewayAttachments` empty in route searches, and lacks some ENI filters (see G17
  notes). The lab needs three accounts on one TGW. A small Describe/Search responder with
  per-account visibility is about 150 lines and deterministic. moto is still fine for unit-style tests.
- **stdlib `http.server`, no web framework or front-end build.** This adds no dependencies and keeps
  the attack surface auditable. The page is a single HTML file with inline JS and SVG and works
  offline.
  - The server binds to localhost only and requires a per-run token on every API call.
  - It checks the Host header against DNS rebinding and the Origin header against cross-site requests.
  - Bodies must be JSON (which rules out form-post CSRF), and are size-limited.
- **Hand-placed topology for the demo, generated grid for real inventories.** A readable NetBrain or
  CML style canvas needs positions. Real inventories get a wrapped grid until saved layouts exist
  (roadmap R10).

## D11. Path maps are rendered from trace JSON, as offline files (2026-11-08, v0.3.0)
The user asked for a NetBrain-style visualizer. Choices:
- **Input is the saved trace JSON.** The renderer reads `TraceResult.to_dict()`, not live objects.
  A trace saved today renders identically later, traces can be shared and rendered on another
  machine, and the map can't trigger new device queries.
- **Static files, not a server.** The output is one `.html` (or `.svg`) with no CDN, web fonts or
  external scripts, plus a restrictive CSP. This works on air-gapped jump hosts, can be attached to
  tickets, and can't leak trace data (device configs, IPs) to third parties. A local server is
  roadmap R9.6, and it needs auth even on localhost.
- **No graph library.** The path is a sequence, so a deterministic single-row layout is enough and
  keeps the output stable between runs. A general graph layout (dagre, ELK, Graphviz) only becomes
  worth it with ECMP branches or topology context (R9.5, R9.7).
- **Checks are badges on links, not nodes.** SGs and NACLs filter traffic on a link rather than
  forwarding it. Drawing them as nodes doubled the node count and hid the forwarding path, which is
  what NetBrain users read first.
- **Hop locations were added to the data model** (`Hop.location`), instead of parsing strings like
  `account network (1111)` out of hop details. Grouping by site, account and VPC needs structured
  data. The field is additive and optional, so older trace JSON still renders, just without boxes.

## D10. Panorama as a proxy, firewall as the authority (2026-11-06, v0.2.0)
Firewalls are queried *through* Panorama (`target=<serial>`), not modelled from Panorama's
configuration. Reasons:
- **Live and authoritative.** The firewall still answers the policy, NAT and FIB tests itself. Its
  dynamic routes, pushed policy and local overrides are all included, as in D2.
- **Fewer moving parts.** One API key and one reachable endpoint replace a management path and key
  for every firewall.
- **One trustworthy source of HA state.** Panorama's `show devices all` reports it, so a passive member
  can be swapped for the active peer. The trace then reflects the box that actually forwards.

Policy tests are never sent to Panorama without `target`. Panorama's own "Test Policy Match" has a
documented failure mode (PAN KB: "Server error" when a source zone is given), and it can't see
firewall-local state anyway.

Panorama's device-group config is used only as a lookup fallback, to display NAT translations and
rule actions when the firewall's own config doesn't show the rule. It never decides a verdict.

`via: direct` stays supported for firewalls that aren't on Panorama or for troubleshooting Panorama
itself. `via` defaults to `panorama` whenever a serial and a `panorama:` section are both present.

## D9. Panorama exists but wasn't available during the build (2026-11-06)
The owner has a Panorama. "No live one to check against" meant none was reachable while building,
not that none exists. v0.1.0 was built direct-to-firewall on the mistaken reading that there was no
Panorama. v0.2.0 added Panorama support (see D10). The Panorama code was tested only against a
simulated Panorama whose XML shapes come from PAN docs and pan-os-python. Items V12–V16 in
`docs/gaps-and-roadmap.md` list what to confirm on the real one.

## D8. Exit codes encode the verdict
`trace run` exits 0 for REACHABLE/EXITED, 3 for BLOCKED, 4 for INCOMPLETE, 1 for errors and 2 for
usage errors. This lets scripts and CI gates use nettrace without parsing output. EXITED counts as
success because "left our network toward the internet / unmanaged hop" isn't a failure of anything
nettrace checks. Neither counts as success when the path crossed an UNKNOWN hop: the engine then
reports INCOMPLETE (exit 4), because a component nettrace skipped is not a verified pass.

## D7. Global options can go anywhere (AWS CLI parity)
The owner asked for AWS-CLI-like syntax. In the AWS CLI, `--output` and `--query` can follow the
subcommand. Click only accepts group options before the subcommand, so `cli.hoist_global_options`
moves `--output/-o`, `--query`, `--inventory/-i`, `--no-color` and `--debug` to the front.
`--query` uses JMESPath on the JSON form, as the AWS CLI does.

## D6. Uncertain is a first-class result
Firewall and ACL verdicts that depend on things nettrace can't see (App-ID, user groups,
object-groups, FQDN/dynamic objects, URL categories, HIP) are reported as UNKNOWN or WARN with the
reason. A confident wrong answer in a troubleshooting tool is worse than "can't tell". Don't "simplify"
this into assume-match or assume-no-match.

## D5. Topology comes from a YAML inventory plus discovery, not from L2/LLDP
The owner chose a YAML inventory. Next-hop -> device mapping uses static `addresses` and a discovery
cache filled by `inventory discover` (interface IPs read via show commands). Domain boundaries (IPsec
or DX to a TGW, Prisma service connections) are explicit `links`, because those can't be inferred
reliably from one side.

## D4. Credentials only from environment variables
The owner chose env vars. The inventory names the variable for each device (`*_env`) so different
devices can use different keys. For AWS, standard credential resolution provides the base identity,
which then assumes a per-account read-only role.

## D3. Read-only enforced in code, not only by credentials
Credentials can be over-privileged by mistake. `readonly.py` adds an independent guard per
transport. For AWS it is a botocore `before-call` hook, so even a coding mistake that calls a
mutating API is stopped before the request is signed. Reachability Analyzer and Network Access
Analyzer are excluded on purpose: they create `NetworkInsightsPath` / `Analysis` resources and are
billed per analysis, so they fail the read-only requirement.

## D2. Live queries per hop, with the device as the authority where possible
The owner wants current state ("pull from every part of the path"), not a model of saved configs.
- PAN-OS hops ask the firewall: `test routing fib-lookup`, `test nat-policy-match`,
  `test security-policy-match`. This captures Panorama-pushed policy, dynamic routes and the
  firewall's own match logic.
- Cisco hops use `show ip cef` (the forwarding table, not just the RIB) plus ACL evaluation.
- AWS is evaluated from Describe/Search calls, because the AWS control plane *is* configuration.
- Prisma Access is evaluated from config because no live policy-test API was found.

## D1. Build on libraries, not on an existing path-analysis platform
Existing tools were evaluated before building:
- **Batfish**: supports Cisco, PAN-OS and AWS configs and has a traceroute question. Rejected as the
  core because it models saved configs instead of querying live devices, doesn't cover Prisma Access,
  lists PAN-OS Advanced Routing as unsupported, and needs a heavyweight service (Docker, 8–32 GB RAM).
  It is still a candidate for a future offline "what-if" mode.
- **SuzieQ**: live polling of IOS-XE and PAN-OS with a `path show`, but no AWS, its path view ignores
  firewall policy, and it needs a constantly running poller.
- **AWS Reachability Analyzer**: AWS-only, same-region source and destination, and not read-only (see D3).
- **AHEAD-Ansible/ansible-nautobot-network-path-troubleshooting**: a similar hop-walker design, but it
  has no license file and is tied to Nautobot. Used only as a design reference; no code was copied.
- **Palo Alto's `pan-os-ansible` / `ansible_panos_policy_orchestration`**: used as references for the
  `test ...-policy-match` and fib-lookup XML formats (including the PAN-OS 8.1 `msg/line` response
  shape).
- **`pan-scm-sdk`**: used as a reference for SCM endpoints, paging and field names. Not taken as a
  dependency, to keep the GET-only surface small and auditable.

What was used: Netmiko (SSH), ntc-templates/TextFSM (Cisco parsing), boto3, requests + defusedxml,
click, rich and jmespath.
