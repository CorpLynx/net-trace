# Architecture

## Trace loop

```
nettrace trace run -s SRC -d DST -p PORT
        |
        v
Tracer.locate_source(flow)              engine.py
   inventory.networks[] prefix   -> DeviceAt(gateway device, vrf)
   prisma_access pools/prefixes  -> PrismaAt(entry="source")
   devices[].addresses / cache   -> DeviceAt(device)
   AWS ENI search (all accounts) -> AwsAt(kind="source_eni")
   else: error, suggest --start-at
        |
        v
loop (max_hops, loop detection on position+src+dst):
   StepResult = driver.step(position, flow)
      .hops      -> appended to the trace
      .flow      -> may be rewritten (NAT)
      .outcome   -> stop (REACHABLE / BLOCKED / EXITED / INCOMPLETE)
      .next      -> explicit next position (AWS->device, Prisma->link, GWLB resume)
      .egress    -> device forwarded out an interface; engine resolves where that goes
        |
        v
Tracer._resolve_egress(egress)
   1. inventory link on (device, interface) or (device, next_hop) -> link's far end
   2. device has an aws: block -> AwsAt(kind="appliance_egress", ip=egress interface IP)
   3. no next hop (connected)  -> REACHABLE
   4. next hop IP owned by an inventory device (static or discovery cache) -> DeviceAt
   5. otherwise -> EXITED ("not in inventory")
```

Positions are defined in `steps.py`:

| Position | Meaning | Handled by |
|---|---|---|
| `DeviceAt(device, arrival_ip, arrival_interface, vrf, gwlb_endpoint, resume)` | traffic arrives at an inventory device | `cisco_iosxe.step` or `panos.step` |
| `AwsAt(kind, account, region, resource_id, ip)` with kind `source_eni`, `appliance_egress`, `subnet`, `tgw_attachment` or `vgw` | traffic is at a point inside AWS | `AwsWalker.walk` |
| `PrismaAt(entry, name)` with entry `source` or `service_connection` | traffic enters Prisma Access | `prisma.step` |

Drivers never decide which *device* comes next. They return an `Egress` or an explicit `next` position.
Topology knowledge stays in the inventory and the engine.

## Data model (`models.py`)

- `Flow`: src, dst, protocol, dst_port, src_port, application, user. NAT returns a new Flow via
  `with_changes`.
- `Hop`: domain, node, component, status, summary, ingress/egress, policy, nat, details[], evidence[].
- `Status`: PASS, BLOCK, WARN (forwards but something is off, e.g. return path), UNKNOWN (couldn't
  evaluate), INFO (lookup step).
- `Outcome`: REACHABLE, BLOCKED, EXITED (left known networks, e.g. internet or an unmanaged next hop),
  INCOMPLETE. A REACHABLE or EXITED path that passed through any UNKNOWN hop is downgraded to
  INCOMPLETE by the engine (never guess).
- Cancelling: `errors.CancelToken` (a `threading.Event` wrapper, no web concepts) is passed to `Tracer(cancel=...)`
  and carried by the trace's `Deadline`, so `Deadline.check()` raises `Cancelled` at exactly the points the time
  budget is checked: before the first request, before every hop, and before every device/API request. No thread is
  killed and no request is interrupted; one already sent finishes (bounded by its own timeout) and sessions are
  closed normally. The engine ends the trace INCOMPLETE ("cancelled by user", `TraceResult.cancelled`) and keeps the
  hops so far, without adding an UNKNOWN hop. `KeyboardInterrupt` in the engine loop is handled the same way, so
  CLI Ctrl-C exits 4 with partial hops. The web server owns the run-id -> token map (`App.runs`).
- `Evidence`: (source, request, response). Every request a driver sends is recorded and shown with
  `--verbose`. Keep this up for new drivers; it's how a user audits a verdict.
- `TraceResult.to_dict()` is the JSON contract used by `--output json` and `--query`, and it is
  the only input to the path map. Top-level keys are PascalCase (`Flow`, `Outcome`, `Reason`, `Hops`,
  `Warnings`, `FinalFlow`) and hop fields are snake_case. Changing them breaks users' `--query`
  expressions and saved traces.
- `Hop.location` (since v0.3.0) says where a hop is, for map grouping. All keys are optional:
  - `site`: on-prem site name (device `site:`, default `On-prem`) or `Prisma Access`;
  - `cloud`, `account`, `account_name`, `region`, `vpc`: AWS placement;
  - `vrf`, `zone_from`, `zone_to`: shown under the device icon;
  - `serial`, `device_group`: PAN-OS via Panorama.

  Who sets what:
  - The engine sets the base: `site`, or the AWS account/region for devices with an `aws:` block.
  - Drivers add their own extras on top.
  - `AwsWalker` tracks the current region and VPC while it walks. TGW hops get no VPC.

## Drivers

### Cisco IOS-XE (`drivers/cisco_iosxe.py`, `cisco_acl.py`)

Transport is Netmiko `cisco_xe`, one SSH session per device per run. Output is cached per command.
Per hop:
1. Find the ingress interface. Use `arrival_interface`; if missing, match `arrival_ip` against
   `show ip interface brief`; if still missing, take the CEF route back to the source.
2. Run `show ip interface <in>` to get the VRF and the inbound ACL.
3. Evaluate the inbound ACL from `show ip access-lists <name>`.
4. Run `show ip cef [vrf V] <dst>` and parse it with a custom parser (ntc's template only covers the
   full table). The result is nexthop, attached, receive or drop. `show ip route [vrf V] <dst>`
   supplies the protocol label.
5. Evaluate the outbound ACL on the egress interface.
6. If the destination is attached, run `show ip arp <dst>`.

The ACL evaluator does first-match over ntc-templates records. It handles standard and extended ACLs,
host/any/wildcard addresses, eq/neq/lt/gt/range ports, and named ports. `established`/ack/rst entries
never match a new flow. Object-groups, unparsed lines and odd TCP flags are added to `uncertain`. A
referenced but undefined ACL means "permit all" (IOS behaviour).

### PAN-OS (`drivers/panos.py`)

Transport is `XmlApi`, which sends an HTTPS POST to `/api/` with an `X-PAN-KEY` header. Each request
passes `check_panos_request`, the response is parsed with defusedxml, and results are cached per
parameter set. The URL list allows failover to a second host (used for the Panorama HA peer).

`make_client(device, panorama)` decides how each firewall is reached:

| Device | Transport | Key |
|---|---|---|
| `serial` and a `panorama:` section (`via` defaults to `panorama`) | Panorama's `XmlApi`, every request adds `target=<serial>` | `panorama.api_key_env` |
| `host` (`via: direct`) | the firewall's own `XmlApi` | device `api_key_env` |

For a via-Panorama device, `PanoramaClient.resolve_target` runs `show devices all`, once per run.
- If the serial isn't managed, or the target isn't connected, it raises `DeviceError`, and the hop
  becomes UNKNOWN / INCOMPLETE.
- If the device is HA `passive` (or any non-`active*` state) and `follow_ha_active` is on, it switches
  to the peer serial, as long as the peer is connected and active.
- Every decision becomes a line in `PanosClient.notes`, which `step()` puts first in the hop details.

`PanoramaClient` also supplies:
- `devices()`: serial, hostname, mgmt IP, model, version, connected, `ha/state`, `ha/peer/serial`, plus
  device group from `show devicegroups`.
- `dg_parents()`: from `show dg-hierarchy`, nested `<dg name=...>` elements.
- `dg_chain_xpaths(serial, suffixes)`: xpaths for the firewall's device group, then its ancestors, then
  `/config/shared`.

Rule and object lookups (`PanosClient._lookup`, used for NAT translation, missing rule actions and
address objects) try three sources in order:
1. Firewall local config (`action=get`).
2. Panorama-pushed config on the firewall, `/config/panorama/...` (`action=show`, i.e. running config,
   then `get`).
3. Panorama device-group chain and shared (`action=get` on Panorama, no target). This step is best
   effort: Panorama errors are swallowed and the lookup returns None.

Evidence is stored on the `XmlApi`. Through Panorama, all firewalls share one evidence list. Each hop
slices it from its start index, and the request label ends in `[via Panorama, target=<serial>]`.

Routed mode, per hop:
1. Run `show interface all` to get interface -> zone, `vr:`/`lr:` router and IP.
2. Find the ingress interface: `arrival_interface` or `arrival_ip`, else FIB lookup back to the source.
3. Run `test routing fib-lookup` or `test advanced-routing fib-lookup` (from `routing_engine` in the
   inventory). The response fields are `interface`, `nh` (`ip`/other) and `ip`.
4. Run `test nat-policy-match` with pre-NAT zones. When a rule matches, read the rule config
   (`config get`, local vsys rulebase, then Panorama pre/post) to find the translated source and
   destination. Address objects resolve to their first IP.
5. If there is destination NAT, do a second FIB lookup on the translated destination. That interface's
   zone becomes `to_zone`.
6. Run `test security-policy-match` (from/to/source/destination/protocol/port, plus application and
   source-user if given). Three response shapes exist across versions; all are handled in
   `parse_policy_match`. If the action is missing, it is read from the rule config.
7. No match: an intrazone flow gets WARN (intrazone-default allow); an interzone flow gets BLOCK
   (interzone-default deny).

Inline mode (VM-Series behind GWLB): the device is entered with `DeviceAt(gwlb_endpoint=...)`. The zone
comes from `aws.gwlb_zone_map[endpoint]` or `aws.gwlb_zone`, and the policy is tested zone->same zone.
Afterwards the walk resumes in AWS at the endpoint's subnet (`resume`).

### Prisma Access (`drivers/prisma.py`)

Transport is the Strata Cloud Manager API: OAuth2 client credentials from
`auth.apps.paloaltonetworks.com`, then GET `/config/security/v1/security-rules` (`folder`,
`position=pre|post`, limit/offset paging) and `/config/objects/v1/{addresses,address-groups,services,service-groups}`.
Endpoints were checked against the community `pan-scm-sdk`.

Per hop:
- Pick the folder from the source or destination: `Mobile Users` or `Remote Networks` (configurable).
- Pick zones: `from` is the users zone when traffic comes from a Prisma client, otherwise the internal
  zone. `to` comes from inventory routing: a Prisma client gets the users zone, a service-connection
  route gets the internal zone, anything else gets the internet zone.
- Run a first-match evaluation over the pre rules, then the post rules. Each rule check is
  True/False/None (uncertain). An uncertain rule is recorded and evaluation continues; the final
  verdict lists uncertain rules above the match.
- Then follow the matching service connection's `link` in the inventory (to a device or a TGW
  attachment), or finish (delivered or internet).

### AWS (`drivers/aws.py`)

`AwsEnv` sets this up per run:
- Base boto3 session with the read-only guard installed.
- `sts:AssumeRole` per inventory account (`role_arn`, optional external ID from env), or a named
  `profile`, or base credentials.
- Every call is cached by (account, region, op, params) and recorded as evidence. Paginated
  automatically.
- `find_eni(ip)` probes every inventory (account, region) in parallel, by private IP then public IP.

`AwsWalker` handles the following:

| From | Logic |
|---|---|
| source ENI | egress SGs (with peer-ENI SG references), then the subnet's route table |
| subnet route table | explicit association, else the main table. Longest prefix match over CIDRs and prefix lists; blackhole means BLOCK |
| `local` | find the destination ENI in that VPC (same account, then other accounts in the region for shared VPCs), NACLs across subnets, ingress SGs, deliver |
| TGW | VPC attachment for (vpc, tgw); attachment subnet in the source AZ; NACLs; TGW owner account; attachment association route table, `SearchTransitGatewayRoutes` longest-prefix-match (falls back to supernet-of-match). Next attachment type: vpc (enter VPC in same AZ), peering (switch TGW/region/owner), vpn/dx/connect (follow inventory `link` or EXIT) |
| NAT gateway | SNAT to its private IP, continue from the NAT subnet's route table |
| GWLB endpoint | hand off to the inventory device listing that endpoint (inline mode), resume at the endpoint subnet. Unknown endpoint: UNKNOWN plus a warning, continue without policy |
| ENI or instance route target (appliance) | NACLs, source/dest check (enabled means BLOCK), ingress SG, map to an inventory device by `aws.instance_id` or IP, then the PAN-OS hop. Afterwards re-enter AWS at the firewall's egress interface IP (`appliance_egress`) |
| IGW / non-GWLB VPC endpoint | EXITED |
| VPC peering | active check, then deliver in the peer VPC |
| VGW | edge (gateway) route table for ingress routing, else deliver in the attached VPC |

NACL boundary rules follow the AWS TGW NACL documentation. Leaving a subnet checks the source subnet's
outbound rules against dst. Entering a subnet checks its inbound rules against src. When the TGW
attachment subnet is the same as the source subnet, the inbound check is also applied. When a forward
check passes, a return-path check (ephemeral port 49152 or `--source-port`) produces WARN, never BLOCK.

## Simulation seams and the demo lab (`demo/`)

Each transport has one class-level override. `nettrace.demo.lab.install()` sets all four and returns
the demo `Inventory`. The CLI calls it when `--demo` is given or a `demo` subcommand runs.

| Seam | Default | Demo |
|---|---|---|
| `CiscoClient.connection_override(device)` | Netmiko SSH | `sim_cisco.SimConnection.send_command` |
| `XmlApi.session_override(api)` | `requests.Session` | `sim_panos.SimSession.post` (firewalls by mgmt host or Panorama `target=`) |
| `ScmClient.transport_override(endpoint, params)` | HTTPS + OAuth | `sim_scm.get` |
| `AwsEnv.backend_override(env)` | boto3 sessions + botocore guard | `sim_aws.Backend.call` (the op allow-list is still enforced in `AwsEnv.call`) |

`install()` also does the following:
- sets placeholder credential environment variables for the process;
- points `NETTRACE_CACHE_DIR` at a temp directory;
- fills `inv.discovered` with the lab's interface IPs, which is what `inventory discover` would have
  learned.

## Web UI (`web/`)

`nettrace serve` / `nettrace demo serve` call `web.server.serve`. The server is
`ThreadingHTTPServer` on 127.0.0.1, wrapped by an `App`.

| Route | What |
|---|---|
| `GET /` | `static/app.html`, with a strict CSP. Holds no data; everything comes from the API. `GET /?c=<code>` spends the one-time login code, sets the `nettrace_session` cookie and 303s to `/`; API calls then need the cookie plus `X-Nettrace-Client: 1` (or the `X-Nettrace-Token` header) |
| `GET /api/bootstrap` | mode, title, topology, presets, devices (with quick commands), icon SVG fragments, history |
| `POST /api/trace` | validates the flow, runs `Tracer` (at most 2 at once), returns `{trace, overlay, map_svg}` and stores it in history (last 50) |
| `POST /api/trace/cancel` | `{id}`: the run id the page sent with `POST /api/trace` (`[A-Za-z0-9_-]{8,64}`, generated by the server if omitted). Sets the run's `CancelToken`; the trace ends INCOMPLETE ("cancelled by user", entry `cancelled: true`, trace JSON `Cancelled: true`) with the hops found so far. Same token / Host / Origin / JSON rules as every route. Idempotent (200 `already: true` on repeats), 404 for an unknown or finished id, 400 for a malformed id, 429 above 30 calls / 10 s. Audit-logged once per run (`mode=trace`, `kind=trace`, `status=cancelled`, run id only, never the access token) |
| `GET /api/traces`, `/api/traces/<id>` | history list / entry |
| `POST /api/console` | `{device, command}`. Cisco goes through `CiscoClient.show`; PAN-OS CLI is converted to op XML by `panos_cli_to_xml`, then sent with `PanosClient.request`. Guard refusals return `status: "refused"` |

`web.topology.overlay(topology, trace)` places hops on the canvas:
- `hop_nodes` maps each hop to a node, using `Locator.hop`. Match order:
  1. device name;
  2. Prisma Access;
  3. source by IP (longest match over node `cidrs`, excluding 0/0);
  4. an AWS ENI in the hop's ingress, egress or node fields, then the node id (`ids`);
  5. the hop's VPC (`vpcs`), then its AWS account (`accounts`).

  Link hops map to nothing.
- `path` is the node sequence with consecutive repeats removed. It can revisit a node: the TGW and the
  inspection VPC router appear twice on inspected paths.
- `step_index` gives each hop's position in `path`, which is where the packet sits.
- `status` is the worst status per node.
- `dest` is the destination node and whether it was reached.

The UI animates a stream of packets along `path` positions (several staggered packets per reached edge,
coloured by hop status, piling up and fading at a block), draws completed segments green (red at a block),
and draws a dashed gray segment to an unreached destination. Controls: play/pause, step back/forward,
first/last, replay and speed. Pause freezes the stream, and stepping while paused keeps it frozen.
With `prefers-reduced-motion` there is no auto-play or tweening, only the step controls.

The topology comes from one of two places:
- **Demo:** `lab.TOPOLOGY`, with hand-placed positions.
- **Real inventory:** `auto_topology(inv)` builds a Prisma column, one box per site (gateway LANs and
  devices) and one per AWS account (VM-Series included), wraps them into rows, and adds an Internet
  node.

## Path map (`viz/`)

`build_map(trace_dict)` turns a trace into a `PathMap`. The rules:
- **Nodes:** forwarding components become nodes: source, routers, firewalls, Prisma, VPC and TGW route
  tables, IGW/NAT/GWLB endpoints, ENIs, errors.
- **Badges:** checks (`aws security-group`, `aws nacl`) are not nodes. They become badges on the edge
  into the next node, in hop order. An edge takes the worst status of its badges.
- **Links:** `engine link` hops become the label of the next edge.
- **Destination:** the map always ends at one.
  - A delivering ENI becomes the destination.
  - Otherwise a synthetic node is added: "not reached" (BLOCKED, faded dashed line after the blocking
    badge), "unknown" (INCOMPLETE), or "Internet / outside known network" (EXITED).
- **Containers:** grouped outer to inner from `location`: `site:<name>` or `aws:<acct>:<region>`, then
  `vpc:<acct>:<vpc>`. A VM-Series hop inherits the VPC when the hops on both sides agree
  (`_inherit_vpc`). A box is drawn per maximal run of consecutive nodes, so a path that leaves a
  container and comes back gets two boxes with the same label.
- **Layout:** a single row. Spacing grows with the badge count on an edge and with container changes.

`render_svg` draws it with hand-built inline icons and no external assets. Every element that maps
to a hop has `data-hop="<index>"`. `render_html` embeds the header-less SVG (the side panel shows
outcome and reason), the full SVG for download, and the trace JSON. All of the viewer's interaction
is built on `data-hop`.

## Inventory (`inventory.py`)

The loader validates as it goes and raises `InventoryError` with a path like
`devices[3].addresses`.

PAN-OS rules:
- A device needs `host` (direct) or `serial` plus a top-level `panorama`.
- `via` is resolved at load time.
- Serials must be alphanumeric and unique.
- Cisco devices always need `host`.

Lookups:
- `device_by_serial(serial)`.
- `device_by_address(ip)`: static `addresses`, then the discovery cache
  (`~/.cache/nettrace/addresses.json`, written by `inventory discover`). The cache is validated on load
  (canonical IP, device in the inventory, short safe interface name; bad entries are dropped with a warning) and
  written by `merge_discovered` under a file lock via a 0600 temp file and `os.replace`. Layout:
  `{"addresses": {ip: {device, interface}}, "ambiguous": {ip: [claims]}}` (the old flat layout still loads).
  An IP claimed by two devices is kept for neither: `device_by_address` returns None and the engine ends the
  trace INCOMPLETE with an UNKNOWN hop naming the colliding devices (`ambiguous_owners`).
- `network_for(ip)`: longest match over `networks`.
- `prisma_location(ip)`: mobile-user pools or remote-network prefixes.
- `device_for_aws(instance_id | ip | gwlb_endpoint)`.
- `link_from_device(device, interface, next_hop)`, `link_from_aws(attachment|vgw)` and
  `link_from_prisma(service_connection)`. Links are bidirectional.

## Adding a driver (checklist)

1. Make a client class that goes through a `readonly.py` check for every request and appends
   `Evidence` for each.
2. Add `step(client, position, flow) -> StepResult`. Return either an `outcome`, an `egress`, or a
   `next`, and use `Status.UNKNOWN` instead of guessing.
3. Add the platform to `inventory.PLATFORMS` and `DEFAULT_ENV`, then dispatch in `engine.Clients.device`
   (the single factory: CLI single-component commands and `inventory discover` also use it) and
   `Tracer._step`.
4. Add `discover_addresses(client)` if the platform has interfaces, so `inventory discover` covers it.
5. Add CLI single-component commands under a new service group, mirroring existing ones.
6. Document it in README (evaluation section, least-privilege credentials) and in this file.
