# Gaps and roadmap

Priorities reflect the owner's environment: Panorama-managed Palo Altos, Prisma Access, IOS-XE,
multi-account AWS. Section 1 lists what must be checked on real systems before results can be trusted.
Section 2 lists functional gaps. Section 3 is the proposed order of work.

## 1. Unverified assumptions (check against live systems first)

Nothing has run against real equipment yet. All behaviour was checked with mocks. Each item names the
code that would change if the assumption is wrong.

| # | Assumption | Where | How to verify |
|---|---|---|---|
| V1 | A read-only PAN-OS admin role can run `test security-policy-match`, `test nat-policy-match` and `test routing fib-lookup` over the XML API | `drivers/panos.py` | `nettrace panos test-security-policy ...` with the read-only key |
| V2 | `test advanced-routing fib-lookup` works over the API on the owner's PAN-OS versions. PAN's own Ansible collection skips it, citing missing API support | `PanosClient.fib_lookup` | run on an Advanced Routing firewall. Fallback: parse `<show><advanced-routing><route>` and do LPM locally |
| V3 | fib-lookup XML has `interface`, `nh`, `ip`, `src` directly under `result` | `PanosClient.fib_lookup` | `--verbose` evidence |
| V4 | `show interface all` returns `result/ifnet/entry` with `name`, `zone`, `fwd` (`vr:X`/`lr:X`), `ip` | `PanosClient.interfaces` | `--verbose` evidence |
| V5 | NAT rule XPaths (local vsys rulebase, `/config/panorama/vsys/...` pre/post) find Panorama-pushed rules on the firewall | `PanosClient.rule_config` | run `panos test-nat-policy` on a Panorama-managed firewall |
| V6 | Prisma Access is managed by Strata Cloud Manager, and folders are named `Mobile Users` / `Remote Networks` | `drivers/prisma.py`, inventory `prisma_access.*.folder` | ask the owner. If Panorama-managed, see R2 |
| V7 | SCM returns rules in evaluation order and `position=pre/post` is complete (no inherited parent-folder rules missing) | `ScmClient.security_rules` | compare with the SCM UI rule order |
| V8 | IOS-XE `show ip cef <ip>` output matches the parser (nexthop/attached/receive lines) on the owner's versions | `parse_cef` | `nettrace cisco show-route` |
| V9 | `SearchTransitGatewayRoutes` with `route-search.longest-prefix-match` is accepted (fallback is `supernet-of-match`) | `AwsEnv.search_tgw_routes` | `nettrace aws search-tgw-routes` |
| V10 | AssumeRole into every account works from the operator's base credentials | `AwsEnv.session` | `nettrace configure check --test-connections` |
| V11 | Cross-account TGW (VPC owner ≠ TGW owner) works as coded. moto couldn't simulate it | `_to_tgw`, `_enter_vpc_from_tgw` | trace between two accounts that share a TGW |
| V12 | Panorama proxies `test security-policy-match`, `test nat-policy-match` and `fib-lookup` with `target=<serial>` for a read-only Panorama admin. PAN documents `target` for op/config queries in general | `PanosClient.request` | `nettrace panos test-security-policy --device <serial-based device>` |
| V13 | `show devices all` reports HA as `ha/state` (`active`/`passive`/`active-primary`/...) and `ha/peer/serial`. Taken from pan-os-python and go-panos parsers | `PanoramaClient.devices`, `resolve_target` | `nettrace panorama list-devices` on an HA pair |
| V14 | `show devicegroups` → `devicegroups/entry[@name]/devices/entry[@name=serial]` and `show dg-hierarchy` → nested `<dg name>` (pan-os-python) | `PanoramaClient.devices`, `dg_parents` | `nettrace panorama show-device --device X` |
| V15 | Panorama-pushed rules are visible on the firewall under `/config/panorama/vsys/...` with `action=show`. If not, the Panorama DG-chain fallback still finds them | `PanosClient._lookup` | `panos test-nat-policy` on a NAT rule defined in a parent device group, with `--verbose` |
| V16 | Firewall interface IPs from `show interface all` through Panorama are enough for `inventory discover` to map next hops | `discover_addresses` | `nettrace inventory discover` then `inventory resolve --ip <fw interface>` |

## 2. Functional gaps

### Palo Alto / Panorama
- **G1. Panorama, partly done (v0.2.0).**
  - Done: firewalls are queried through Panorama, `panorama list-devices` and `generate-inventory`
    work, and device-group context is in the output.
  - Remaining: generated entries don't fill in `virtual_router`, `routing_engine`, `vsys` or `aws:`
    blocks; set them by hand.
  - Remaining: firewalls that Panorama manages but the inventory lacks still aren't followed as next
    hops until they're added.
  - Remaining: template stack isn't shown.
- **G2. HA, partly done (v0.2.0).**
  - Done: a passive member is redirected to the active peer.
  - Remaining: active/active pairs use whichever member is listed, so session-owner and
    floating-IP behaviour isn't modelled.
  - Remaining: firewalls reached directly (`via: direct`) get no HA handling.
- **G3.** No PBR (`test pbf-policy-match`) and no decryption-policy evaluation.
- **G4.** Address objects resolve to the first IP only (affects NAT translated-address display).
  Address groups and FQDN objects in NAT aren't expanded.
- **G5.** Multi-vsys: one `vsys` per device in the inventory. The vsys isn't derived from the ingress
  interface.
- **G6.** App-ID: without `--application`, a PASS means layer 3/4 only. There is no listing of the
  applications the matched rule allows.

### Prisma Access
- **G7.** Policy is evaluated from config, not live. No API equivalent of `test security-policy-match`
  was found for Prisma Access.
- **G8.** Routing is taken from the inventory (service-connection prefixes). Real Prisma Access routing
  (BGP learned from service connections or remote networks) is not read.
- **G9.** User and group rules are uncertain unless `--user` exactly matches a listed user. Group
  membership (Cloud Identity Engine) isn't resolved.
- **G10.** Prisma Access source NAT on egress and explicit-proxy flows aren't modelled.

### Cisco
- **G11.** Not evaluated: zone-based firewall, PBR / route-maps, NAT, VRF-leaking edge cases,
  object-group contents (`show object-group` could resolve these), and IPv6.
- **G12.** ECMP follows the first CEF path only (with a warning). Not modelled: CEF hash, NX-OS/ASA
  (out of scope, "mostly XE").

### AWS
- **G13.** Not handled: Cloud WAN, AWS Network Firewall endpoints (treated as a generic VPC endpoint,
  so the walk EXITs), Direct Connect gateway internals, TGW Connect peers, Local/Carrier gateways,
  Route 53 Resolver, PrivateLink services, ELB/NLB targets.
- **G14.** ECMP across TGW attachments follows the first attachment. Appliance-mode symmetry isn't
  checked.
- **G15.** Return path is checked only for NACL ports. A full reverse trace (dst -> src) is not run, so
  asymmetric routing through a stateful firewall isn't detected.
- **G16.** ENI search is O(accounts × regions × 2) calls. It could be slow with many accounts, and
  there is no persistent cache.

### General
- **G17.** A pytest suite exists (`tests/`, 446 tests: demo presets, read-only guards, hardening,
  audit/console scope, never-guess and robustness cases, ACL and netutil units, packet-flow and
  artifact checks), but there is no CI, and nothing verifies against real devices. The suite
  uses the demo simulators, so it proves self-consistency, not device behaviour. Still missing:
  committed fixtures of real device output (R3) and a fake-Panorama failover suite.
- **G17a.** Discovery cache (R18): validated on load, merged atomically under a file lock, duplicate IPs marked
  ambiguous (UNKNOWN hop for a next hop; a *source* IP that is ambiguous is still not reported by name, it falls
  through to the AWS lookup). The lock is POSIX `flock` (no-op elsewhere), advisory and same-uid. Web console: a busy
  device returns 429 instead of queueing; a stalled body returns 408 after 10 s; closing the server does not wait
  for a stalled device.
- **G18.** One path per trace. Nothing traverses the ECMP fan-out, so no all-paths view.
- **G19.** A trace has an overall deadline (`trace_timeout` / `--timeout`, default 120 s), AWS clients
  use short timeouts with standard retries, and PAN-OS/SCM reads retry once on a timeout. Cisco SSH
  commands are not retried, so a slow device fails the hop (`INCOMPLETE`).
- **G20.** IPv4-centric throughout.

## 3. Proposed next iterations

Ordered by value to the owner versus effort. Each one should keep the hard rules in `AGENTS.md`.

### R1. Panorama integration: core DONE in v0.2.0; follow-ups open
Done:
- `panorama:` inventory section (host, `peer_host`, key env, TLS, `follow_ha_active`). PAN-OS devices
  can be given by `serial`.
- Every firewall request goes to Panorama with `target=<serial>`. Policy tests never run on Panorama
  itself.
- The read-only guard validates `target` and rejects unknown parameters.
- HA: a passive member is redirected to the active peer, with notes in the hop details.
- Device-group chain lookup for NAT and rule details.
- CLI: `panorama list-devices`, `panorama show-device` and `panorama generate-inventory`.
  `configure check` covers Panorama.

Follow-ups (in value order):
1. **Next hop to a firewall that isn't in the inventory.** When a next hop isn't in the inventory,
   look it up among Panorama-managed firewalls' interface IPs (cached, read through `target=`) and
   follow it automatically, with a note asking to add it.
2. **More fields in generated entries.** Have `generate-inventory` fill in `routing_engine`
   (detect via `<show><advanced-routing>`), `virtual_router` and `vsys`. Mark VM-Series candidates for
   an `aws:` block (model `PA-VM`).
3. **Template stack in hop details,** from `<show><templates>`.
4. **Active/active HA,** if the owner runs it. Report both members and the session owner.

### R1b. Persist Panorama device list between runs (low effort)
`show devices all` runs once per invocation. Cache it under `NETTRACE_CACHE_DIR` with a short TTL so
single-component commands stay fast.

### R2. Panorama-managed Prisma Access (do only if V6 says Panorama manages it). Fixes V6
- Read rules from Panorama device groups (`Mobile_User_Device_Group`, `Remote_Network_Device_Group`,
  plus parent groups) with `type=config&action=get` on `/config/devices/entry/device-group/entry[@name=...]/pre-rulebase|post-rulebase`
  and `shared`. Feed them into the existing `prisma.evaluate_rules` by normalising the field names.
- Put SCM and Panorama sources behind one small interface (`rules(folder_or_dg)`, `objects(kind)`).
  Reuse `PanoramaClient` (`config_get`, `dg_parents`, `dg_chain_xpaths`) from `drivers/panos.py`.
  The transport, read-only checks and DG-hierarchy walk already exist.

### R3. Mock-based regression suite: partly done (see G17); real-device fixtures open
- `tests/` with pytest:
  - moto scenarios (same-account TGW, IGW, NAT, appliance ENI, GWLB, NACL and SG blocks);
  - canned Cisco/PAN-OS/SCM fixtures;
  - a fake Panorama (`show devices all` with an HA pair, `show devicegroups`, `show dg-hierarchy`,
    target routing, NAT rule in a parent DG, primary-down failover to `peer_host`);
  - read-only guard tests that try writes and expect `ReadOnlyViolation`.
- Capture real `--verbose` evidence from the first live runs and turn it into fixtures, which also
  locks in V3, V4 and V8.

### R4. Reverse-path trace (high value for stateful firewalls, medium effort). Fixes G15
- `trace run --both-directions`: after a forward REACHABLE, trace (final dst -> src) with the
  post-NAT flow. Flag it if the reverse path crosses a different stateful firewall than the forward
  path (asymmetric routing).

### R5. Cisco object-groups and PBR (medium value, low to medium effort). Fixes part of G11
- Resolve `object-group` ACL entries via `show object-group name X`.
- Detect `ip policy route-map` on the ingress interface. Report it as UNKNOWN at first, then evaluate
  simple `match ip address` / `set ip next-hop` cases.

### R6. AWS Network Firewall and Cloud WAN (environment-dependent). Fixes part of G13
- Network Firewall: detect `vpce-` owned by `network-firewall`, then read the firewall policy and
  stateless/stateful rule groups (Describe-only) and evaluate 5-tuple rules. Suricata rules would be
  UNKNOWN.
- Cloud WAN: `networkmanager:GetNetworkRoutes` for core network segments.

### R7. Performance and usability (low effort)
- Persistent ENI and IP -> account cache with a TTL, alongside the discovery cache.
- `--account` / `--region` hints on `trace run` to skip the global ENI search.
- `nettrace inventory generate` from Panorama (R1) plus AWS (TGW attachments -> links).
- A markdown or HTML report output for tickets (`--output md`).

### R9. Path map: next iterations (v0.3.0 shipped the first version)
Shipped:
- single-row map with site/Prisma/AWS/VPC boxes and SG/NACL badges;
- static SVG output;
- offline HTML viewer: pan/zoom, hop list, evidence, deep links, several traces per file.

Next, in value order:
1. **Wrap long paths.** Paths over about 8 nodes get small when fitted to the window. Break them into
   rows (serpentine) at container boundaries.
2. **Return path.** With R4, draw the reverse path as a second lane under the forward one, and
   highlight a firewall that appears in only one direction (asymmetry).
3. **Compare runs.** Render two traces of the same flow (before and after a change, or now vs.
   yesterday) and highlight hops whose status, policy or next hop changed.
4. **Interfaces on the line.** Label ingress and egress interfaces at each end of an edge, like
   NetBrain's interface labels. The data is already in `Hop.ingress` / `Hop.egress`.
5. **ECMP branches.** When G18 is solved, draw the alternate paths as faded branches.
6. **Live mode: shipped in v0.4.0** as `nettrace serve` / `nettrace demo serve` (see R10 for
   follow-ups).
7. **Topology context.** Show neighbouring inventory devices (from `links` and discovery) greyed out
   around the path.

### R10. Web UI and demo lab: next iterations (v0.4.0 shipped the first version)
Shipped:
- simulated Acme Corp lab: IOS-XE, PAN-OS HA pair plus VM-Series via Panorama, Prisma Access (SCM),
  3 AWS accounts on a TGW with an inspection VPC;
- `--demo` on every command;
- localhost UI: topology canvas, multi-packet flow animation with play/pause/step/replay/speed controls, event list, inspector (hop / device / path
  map / JSON), read-only console, presets, history, deep links;
- `nettrace serve` for real inventories, with an auto-generated topology.

Next, in value order:
1. **Saved layouts for real inventories.** Drag nodes in the UI, then save positions to a
   `topology.yaml` next to the inventory, the way CML saves a lab. Today a real inventory gets a
   generated grid.
2. **Hops appear while the trace runs.** Stream progress over SSE. Live traces against real devices
   can take tens of seconds; today the UI shows a spinner until the whole trace finishes.
3. **AWS internals on the live canvas.** In live mode, AWS hops map to the account node only. Add
   VPC, TGW and ENI nodes on the fly as traces discover them (from hop `location`), and remember them
   in the saved layout.
4. **Compare two traces** (with R9.3): before/after a change, shown side by side on the canvas.
5. **Lab editing.** Let the demo lab (or a "what-if" copy of real config) be edited in the UI, for
   example toggling a rule or adding an SG entry, then re-trace. That also starts a path toward
   Batfish-style pre-change validation without touching devices.
6. **Demo presets as a regression test: done** (`tests/test_demo_presets.py`).
7. **Accessibility and keyboard reach.** Add ARIA labels on canvas nodes, a high-contrast theme, and
   tab focus through the event list.

Proposal (not done): share viewer code between `viz/html.py` and `web/static/app.html`. Both carry their
own copy of `esc()`, the packet-stream animation (`pf*` vs `buildFlow`/`updateFlow`) and hop-detail layout.
A safe way is one `viz/viewer.js` read with `importlib.resources` and inlined into both pages at render
or serve time, so there are still no external URLs and the CSP stays `default-src 'none'`. Both pages use an
inline script, so the CSP must stay as is. It touches about 150 lines of tightly coupled JS in two
different state models (`pf` vs `S`), so do it as its own change with browser checks.

Demo lab limits (deliberate, to keep the simulators small):
- one region, no VRFs on the router, no object-groups;
- PAN-OS `application-default` uses a small App-ID → port table;
- Prisma Access rules come only from the pre-rulebase;
- AWS has no NAT gateways, GWLB, peering or prefix lists.

The real drivers support more than the lab exercises.

### R8. Prisma Access routing (depends on API availability)
- Investigate whether the SCM or Prisma Access APIs expose service-connection or remote-network BGP
  routes. If they do, replace the inventory `service_connections[].routes` with live routes.
