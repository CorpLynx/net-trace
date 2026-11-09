# Dynamic topology discovery: design

Status: proposal (nothing built). Author context: read-only review of `AGENTS.md`, `docs/architecture.md`,
`docs/decisions.md`, `docs/gaps-and-roadmap.md`, `engine.py`, `inventory.py`, `readonly.py`,
`drivers/{cisco_iosxe,panos,aws,prisma}.py`, `web/topology.py`, and the demo simulators. No source or
tests were edited. Device command shapes marked **[verify]** come from vendor docs/memory and must be
checked on a live device before they are trusted (the project has never run against real equipment; add
them to the V-list in `gaps-and-roadmap.md` when building).

## 0. Problem and scope

Today the engine needs hand-written `links:` for every domain boundary: PAN-OS tunnel to a TGW VPN
attachment, Cisco tunnel to a Prisma service connection, ISP exits (`engine._resolve_egress` step 1, and
`AwsWalker._leave_via`, `prisma.step`). Same-domain next hops already resolve through
`device_by_address` (static `addresses` + the `inventory discover` cache). The goal is to learn those links,
and the device list, from the systems themselves, without weakening any Hard rule.

Where the value is, in order:
1. Tunnel and attachment links (device <-> AWS VPN/DX/TGW attachment, device <-> Prisma). These cannot be
   resolved from one side (D5) and are the links people forget to update.
2. Device list from Panorama (serials, HA, model) and AWS (VM-Series `aws:` block). Mostly exists
   (`panorama generate-inventory`); this makes it automatic and opt-in.
3. L2/L3 adjacency (CDP/LLDP/BGP/OSPF). Mostly useful for the map, `diff` and validation. The trace
   already follows next hop -> owning device.
4. Learned `networks` (prefix -> gateway) for `locate_source`. Last, optional.

This **amends D5** ("topology comes from YAML plus discovery, not from L2/LLDP"). D5's reason (a link
cannot be inferred reliably from one side) stays the governing constraint: a link is only *learned* when
two independent observations agree. Record the amendment as D14 before building.

## 1. Data sources per platform (read-only, exact requests)

"Guard today" says whether the current guard already passes it. A key finding: **the Cisco and PAN-OS
guards are generic.** `check_cisco_command` accepts any `show <safe chars>`; `check_panos_request` accepts
any `<show>` tree. So nothing below is blocked today, which is exactly why section 1.5 proposes a
*narrower*, discovery-only allowlist instead of widening anything.

### 1.1 Cisco IOS-XE (SSH, `CiscoClient.show`, never the web console)

| Purpose | Command | Parse | Cost | Guard today |
|---|---|---|---|---|
| Self identity | `show version` | hostname from the `<host> uptime is` line, model, version | low | passes |
| Interfaces + IPs | `show ip interface brief` | ntc (exists, `discover_addresses`) | low | passes |
| VRFs | `show vrf` | ntc | low | passes |
| L2 neighbors | `show cdp neighbors detail` | ntc `cisco_ios_show_cdp_neighbors_detail`: host, mgmt IP, platform, local/remote port, capabilities | med | passes |
| L2 neighbors | `show lldp neighbors detail` | ntc `cisco_ios_show_lldp_neighbors_detail` | med | passes |
| ARP (L2 corroboration, small scopes only) | `show ip arp`, `show ip arp vrf <v>` | ntc (exists) | med-high on big LANs: row cap | passes |
| Connected prefixes (learned `networks`, P5) | `show ip route connected`, `show ip route vrf <v> connected` | custom or ntc | med | passes |
| Tunnel interfaces | enumerate `Tunnel*` from `show ip interface brief`, then `show interfaces Tunnel<n>` | custom parser: source, destination, mode (gre/ipsec), `Tunnel protection via IPSec (profile ...)`, line/protocol state | low per tunnel | passes (`safe_token`) |
| IPsec session state | `show crypto session` (add `show crypto ikev2 sa` / `show crypto isakmp sa` for legacy) | custom: Interface, peer IP/port, status (`UP-ACTIVE`) | low | passes (console denies `crypto`, crawl does not use the console) |
| BGP neighbors | `show ip bgp summary`, `show ip bgp vpnv4 vrf <v> summary` [verify VRF forms] | ntc `cisco_ios_show_ip_bgp_summary`: neighbor, AS, state | low | passes |
| OSPF/EIGRP neighbors | `show ip ospf neighbor`, `show ip eigrp neighbors` | ntc | low | passes |
| Neighbor-to-interface | `show ip cef [vrf v] <neighbor-ip>` | existing `CiscoClient.cef` | low | passes |

Not used: `show running-config`, `show tech-support`, `show ip bgp` (full table), `show ip route` (full
table), `show crypto isakmp key` or anything printing keys. `show interfaces` (all) is avoided: it is large
and the ntc template does not cover tunnel source/destination.

Leave manual: DMVPN/NHRP, FlexVPN/Virtual-Access (`show crypto session` reports `Virtual-Access`, no
stable interface identity), SD-WAN/Catalyst Center managed estates.

### 1.2 PAN-OS firewalls (XML API, via Panorama `target=<serial>` or direct)

All are `type=op` with a `<show>` root, so they pass `check_panos_request` today. Tag shapes are
**[verify]** on the owner's PAN-OS versions.

| Purpose | Request | Fields used |
|---|---|---|
| Interfaces, tunnel interface names | `<show><interface>all</interface></show>` (exists: `PanosClient.interfaces`) | `tunnel.N` entries, zone, vr, ip |
| LLDP neighbors | `<show><lldp><neighbors>all</neighbors></lldp></show>` [verify tag] | local interface, chassis id, port id, system name, mgmt addr |
| Tunnel <-> peer map (best single source) | `<show><vpn><flow></flow></vpn></show>` | tunnel id/name, `inner-if` (tunnel.N), `outer-if`, `localip`, `peerip`, state |
| IKE SAs | `<show><vpn><ike-sa></ike-sa></vpn></show>` | gateway name, peer, state (corroboration) |
| IPsec SAs | `<show><vpn><ipsec-sa></ipsec-sa></vpn></show>` | tunnel name, remote, state |
| Configured gateways (tunnel down case) | `<show><vpn><gateway></gateway></vpn></show>` [verify] or `type=config action=get xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway` and `.../network/tunnel/ipsec` | peer address, local interface; xpath already allowed by `_PANOS_XPATH` |
| BGP peers | `<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>`; advanced routing: `<show><advanced-routing><bgp><peer></peer></bgp></advanced-routing></show>` [verify both] | peer IP, remote AS, state |
| HA | `<show><high-availability><state></state></high-availability></show>` (the lab already simulates it) | local/peer state; Panorama already gives `ha/peer/serial` |
| System info | `<show><system><info></info></system></show>` (exists) | hostname, model, serial, mgmt IP |

Panorama itself (no `target`):

| Purpose | Request | Notes |
|---|---|---|
| Managed device list | `<show><devices><all></all></devices></show>` (exists: `PanoramaClient.devices`) | serial, hostname, mgmt IP, model (`PA-VM` marks VM-Series), connected, HA |
| Device groups / hierarchy | `<show><devicegroups></devicegroups></show>`, `<show><dg-hierarchy></dg-hierarchy></show>` (exist) | context only |
| Templates (optional) | `<show><templates></templates></show>` [verify] | context only (G1 remainder) |

No `<test>` request is used by discovery. Nothing here is sent to Panorama itself except the list above.

### 1.3 AWS (botocore, `AwsEnv.call`, per inventory account x region)

Already allowlisted and sufficient for much of it:
- `ec2:DescribeTransitGateways`, `DescribeTransitGatewayAttachments` (rows with `ResourceType` =
  `vpn` | `direct-connect-gateway` | `peering` | `connect`, and `ResourceId`), `DescribeTransitGatewayVpcAttachments`,
  `DescribeTransitGatewayPeeringAttachments`, `DescribeVpnGateways`, `DescribeNetworkInterfaces`, `DescribeVpcs`.
- VM-Series `aws:` block: match the Panorama mgmt IP or interface IPs against `DescribeNetworkInterfaces`
  (private IP filter) -> `Attachment.InstanceId`, VPC, account, region. No `DescribeInstances` needed.

Needs **new allowlist entries** (section 1.5): `ec2:DescribeVpnConnections` (VPN id, state, customer gateway
id, TGW or VGW id, per-tunnel `OutsideIpAddress`, `TunnelInsideCidr`, `VgwTelemetry`), `ec2:DescribeCustomerGateways`
(`IpAddress`, `BgpAsn`), and for Direct Connect (phase P5) `directconnect:DescribeConnections`,
`DescribeVirtualInterfaces`, `DescribeDirectConnectGateways`, `DescribeDirectConnectGatewayAssociations`,
`DescribeDirectConnectGatewayAttachments`. DX gateways are not regional: query once per account in its first
inventory region.

**Secret exposure (blocking item for DescribeVpnConnections).** The response carries
`CustomerGatewayConfiguration` (device config XML with the IKE pre-shared keys) and, in `Options.TunnelOptions`,
pre-shared key material **[verify field]**. `AwsEnv._record` caches the whole response, puts the first 1500
chars in `Evidence`, and `--verbose`/the web UI display evidence. So a response scrubber must run inside
`AwsEnv._boto_call_once`/the backend path, before the cache, evidence and audit, deleting those fields
(`_SENSITIVE = {("ec2","DescribeVpnConnections"): ["CustomerGatewayConfiguration", "Options.TunnelOptions[].PreSharedKey"]}`).
IAM cannot restrict fields, so the role still *can* read PSKs; the owner must accept that (decision 3).
The alternative is to keep AWS VPN links manual.

### 1.4 Prisma Access (SCM, GET only)

Candidate endpoints, **unverified in this review** (I could not confirm them from search; the repo's code
uses `/config/security/v1/...` and `/config/objects/v1/...`; `pan-scm-sdk` is the reference to check):

| Purpose | GET | Fields used |
|---|---|---|
| Service connections | `/config/deployment/v1/service-connections` (folder `Service Connections`) | name, region, `ipsec_tunnel`, `subnets`, BGP flag/peer |
| Remote networks | `/config/deployment/v1/remote-networks` (folder `Remote Networks`) | name, region, `ipsec_tunnel`, `subnets`, BGP |
| IKE gateways | `/config/network/v1/ike-gateways` | customer-side `peer_address` (the on-prem device's IP) |
| IPsec tunnels | `/config/network/v1/ipsec-tunnels` | tunnel -> IKE gateway reference |

What this gives: which on-prem IP terminates each service connection/remote network, plus static
`subnets`. What it does not give: BGP-learned routes or live tunnel state (R8). The Insights API is a POST
query API, which violates the GET-only rule; do not use it without an explicit owner exception (decision 12).
If Prisma turns out to be Panorama-managed (V6/R2), the equivalents are `type=config action=get` under
`/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services/...` **[verify]** through the
existing `PanoramaClient.config_get`.

### 1.5 Exact allowlist additions for the owner to approve

None of these are applied. Each is listed so it can be approved or rejected individually.

**A. AWS (`readonly._AWS_ALLOWED`, `iam/nettrace-readonly-policy.json`)**
- A1 `ec2:DescribeVpnConnections` (needs the scrubber from 1.3; blocks P2's AWS side if rejected)
- A2 `ec2:DescribeCustomerGateways`
- A3 `directconnect:DescribeConnections` (P5)
- A4 `directconnect:DescribeVirtualInterfaces` (P5)
- A5 `directconnect:DescribeDirectConnectGateways` (P5)
- A6 `directconnect:DescribeDirectConnectGatewayAssociations` (P5)
- A7 `directconnect:DescribeDirectConnectGatewayAttachments` (P5)

Constraints: the policy is also the STS inline session policy and must stay under 2048 packed characters
(`_SESSION_POLICY_MAX`). It is 604 now; A1-A7 add roughly 300, so it fits. The per-account IAM role must also
get the same actions (outside this repo). Not requested: Reachability/Network Access Analyzer (stays
forbidden), `DescribeInstances`, `GetTransitGatewayRouteTable*`, Cloud WAN.

**B. Cisco: a new, narrower discovery allowlist (no widening)**
A new `check_cisco_discovery_command` in `readonly.py`, enforced in addition to `check_cisco_command` when the
call comes from the crawler (`CiscoClient.show(cmd, purpose="discovery")`). Patterns (anchored, tokens via
`safe_token`):
- B1 `show version`
- B2 `show vrf`
- B3 `show ip interface brief`
- B4 `show cdp neighbors detail`
- B5 `show lldp neighbors detail`
- B6 `show interfaces Tunnel<digits>`
- B7 `show crypto session`
- B8 `show crypto ikev2 sa`
- B9 `show crypto isakmp sa`
- B10 `show ip bgp summary`
- B11 `show ip bgp vpnv4 vrf <token> summary` [verify]
- B12 `show ip ospf neighbor`
- B13 `show ip eigrp neighbors`
- B14 `show ip arp` and `show ip arp vrf <token>`
- B15 `show ip route connected` and `show ip route vrf <token> connected`
- B16 `show ip cef [vrf <token>] <ip>` (already used by traces)

The web console denylist (`crypto`, ...) is unchanged; the crawler never uses the console.

**C. PAN-OS: a new discovery allowlist, same idea**
A `check_panos_discovery_request` (exact `<show>` trees) applied for crawler calls:
- C1 `<show><system><info></info></system></show>`
- C2 `<show><interface>all</interface></show>`
- C3 `<show><lldp><neighbors>all</neighbors></lldp></show>` [verify]
- C4 `<show><vpn><flow></flow></vpn></show>`
- C5 `<show><vpn><ike-sa></ike-sa></vpn></show>`
- C6 `<show><vpn><ipsec-sa></ipsec-sa></vpn></show>`
- C7 `<show><vpn><gateway></gateway></vpn></show>` [verify]
- C8 `<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>` [verify]
- C9 `<show><advanced-routing><bgp><peer></peer></bgp></advanced-routing></show>` [verify]
- C10 `<show><high-availability><state></state></high-availability></show>`
- C11 `<show><devices><all></all></devices></show>`, `<show><devicegroups></devicegroups></show>`,
  `<show><dg-hierarchy></dg-hierarchy></show>` (Panorama; already used)
- C12 `type=config action=get` with xpath exactly `/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway`
  or `.../network/tunnel/ipsec` (optional, down tunnels)

**D. Strata Cloud Manager (new: today only the HTTP method is checked, there is no endpoint list)**
A GET endpoint allowlist, including the existing endpoints so behaviour is unchanged:
- D1 existing `/config/security/v1/security-rules`, `/config/objects/v1/{addresses,address-groups,services,service-groups}`
- D2 `/config/deployment/v1/service-connections` [verify]
- D3 `/config/deployment/v1/remote-networks` [verify]
- D4 `/config/network/v1/ike-gateways` [verify]
- D5 `/config/network/v1/ipsec-tunnels` [verify]

## 2. Data model

### 2.1 Link with provenance

Extend `inventory.Link` additively. Existing constructors and YAML keep working (defaults make a link
`declared`). `LinkEnd` is reused unchanged, so `engine._from_link_end` and `AwsWalker._leave_via` need no change.

```python
@dataclass(frozen=True)
class Provenance:
    source: str          # "cisco:show crypto session" | "panos:show vpn flow" | "aws:ec2.DescribeVpnConnections"
                         # | "scm:GET /config/deployment/v1/service-connections" | "inventory.yaml"
    device: str          # inventory device name, "aws:<acct>/<region>", "panorama", "scm"
    observed_at: float   # local epoch seconds (the device clock is never trusted)
    run_id: str          # crawl id; matches the audit log (mode=crawl)
    digest: str          # sha256 of the normalised fragment; raw output is not stored

@dataclass
class Link:                      # existing fields: name, a, b
    origin: str = "declared"     # declared | learned | inferred
    kind: str = "unknown"        # l2 | l3 | ipsec | gre | bgp | aws-vpn | aws-dx | prisma | ha
    oper: str = "unknown"        # up | down | unknown  (liveness, separate from existence)
    id: str = ""                 # stable: sha256 of kind + sorted canonical endpoints
    provenance: tuple[Provenance, ...] = ()
    first_seen: float = 0.0
    last_confirmed: float = 0.0
    absent_since: float | None = None
    conflicts: tuple[str, ...] = ()
```

Confidence rules (the "never guess" mapping):
- **declared**: from `inventory.yaml`. Always authoritative.
- **learned**: at least two observations from different `(device, source)` pairs agree on both ends (a join
  rule in 2.2 succeeded), each from a query that was answered (`Unavailable` never counts, D13), all within
  TTL. Used for forwarding.
- **inferred**: one-sided, or a heuristic (same /30, name match, NAT'd peer). Never used to forward. A trace
  that reaches one gets an UNKNOWN link hop ("probable link X (inferred) not used; declare it or run
  `topology crawl`"), so the trace becomes INCOMPLETE, never REACHABLE/EXITED.

A device can only assert links where it is itself an endpoint. It cannot assert a link between two other
nodes, and one device's claim about its neighbour is a claim, not a confirmation.

### 2.2 Join rules (what makes two observations "agree")

| Link | Observation 1 | Observation 2 | Result |
|---|---|---|---|
| PAN-OS tunnel <-> AWS VPN | `show vpn flow`: `inner-if` tunnel.N, `peerip` P, `localip` L | `DescribeVpnConnections`: P is a tunnel `OutsideIpAddress` of vpn-X and the CGW (`DescribeCustomerGateways`) `IpAddress` equals L | learned. End b = `aws_tgw_attachment` (attachment with `ResourceType=vpn`, `ResourceId=vpn-X`) or `aws_vgw` (VPN's `VpnGatewayId`). Peer matches but CGW IP does not (NAT-T): inferred |
| Cisco tunnel <-> AWS VPN | `show interfaces TunnelN` destination = P and `show crypto session` Interface TunnelN, Peer P | same as above; optionally `show ip bgp summary` neighbor inside `TunnelInsideCidr` | learned |
| Device tunnel <-> device tunnel | A tunnel dest = IP owned by B (unique `device_by_address`) | B has a tunnel/flow with peer = A's source/local IP | learned; one side only: inferred |
| Device <-> Prisma service connection | SCM IKE gateway `peer_address` is an IP uniquely owned by device D (and D's tunnel peer equals the Prisma endpoint if SCM exposes it) | D's tunnel/crypto session shows an up session to that peer | learned if both; SCM alone: inferred |
| Device <-> device (L2) | A's CDP/LLDP says N port p | N's own CDP/LLDP says A port q, **or** A.if and N.p have addresses in the same /30-/31 | learned; one-sided CDP: inferred (CDP is sent by the neighbour, so spoofable) |
| BGP/OSPF adjacency | A's neighbor IP resolves (unique) to device N, `show ip cef <ip>` gives the interface | N lists A's address as a neighbor | learned |
| HA pair | Panorama `ha/peer/serial` | peer's own HA state | learned |
| Device <-> DX (P5) | VIF `customerAddress` owned by router R on interface I, BGP session to `amazonAddress` Established | DX gateway association -> TGW/VGW id matches attachment | learned |
| VM-Series <-> AWS | Panorama mgmt IP / interface IPs | ENI private IP + `Attachment.InstanceId` | learned (fills `Device.aws`) |

Join hygiene:
- Ignore as join keys: `169.254.0.0/16` (VPN inside addresses repeat on every connection), RFC1918 inside
  tunnel addresses, loopbacks, multicast, `0.0.0.0`.
- Address ownership must be **multi-valued**. `inventory discover` stores `mapping[ip] = {...}`, so the last
  device wins silently, and `Inventory.device_by_address` returns the first static hit. With overlapping
  VRFs or reused addresses that is a silent guess. Prerequisite (P0): store `ip -> [(device, interface, vrf)]`
  and make duplicates an ambiguity (UNKNOWN) in `device_by_address`, `_resolve_egress` step 4 and the joiner.
- Cisco interface names are normalised (`Gi0/0/1` = `GigabitEthernet0/0/1`) before any comparison.
  `link_from_device` currently compares lower-cased raw strings.

### 2.3 Merge with hand-written links

1. Key: each end's canonical identity (`(device, interface)`, `tgw_attachment`/`vgw` id, `service_connection`).
2. **Declared wins.** If a declared link names an end, learned links on that end never replace it. The trace
   uses the declared link.
3. Agreement: the learned observations are attached to the declared link as corroboration
   (`origin` stays `declared`, `provenance` grows, shown as "declared, confirmed 12 min ago").
4. Conflict (learned says a different far end for a declared end): both are kept, `conflicts` is set, the
   trace uses declared and adds a WARN detail on the link hop ("learned topology disagrees: ..."), and
   `topology diff` lists it. Not silent.
5. Declared link not observed: reported by `diff` as "declared, not observed" **only** when both ends'
   observations were answered successfully within TTL. A device that did not answer means "unverified",
   never "absent".
6. Two learned links claim the same end with different far ends (e.g. `tunnel.1` matches two VPNs): neither
   is used; the engine returns UNKNOWN listing candidates, like `AmbiguousEni`.
7. Learned link not re-observed in a successful, complete observation of both ends: set `absent_since`;
   remove after a grace period (2 successful crawls or `ttl_max`). A failed query never deletes anything.

### 2.4 Staleness, TTL and refresh-on-miss

Live data first (Hard rule 2): the device's FIB/route answer is always live; the link store only maps "this
egress" to "that far end". So:

| State | Age (defaults, configurable) | Engine behaviour |
|---|---|---|
| fresh | < `ttl_fresh` 1 h | use, show age |
| stale | `ttl_fresh` .. `ttl_max` 24 h | use only after a bounded **refresh-on-stale** of that one link; if it fails, treat as inferred (UNKNOWN) |
| expired | > `ttl_max` | inferred; never forwards |

**Refresh-on-miss** in `Tracer._resolve_egress`, as a new step 1b, only when step 1 finds no declared/learned
link and the egress interface looks like a tunnel/virtual interface (`Tunnel*`, `tunnel.*`, `Virtual-Access*`)
or the far end is outside the inventory. It runs a targeted observation of only that device's interface
(Cisco `show interfaces TunnelN` + `show crypto session`; PAN-OS `show vpn flow`) and re-joins against the
cached cloud-side data; if that data is stale, one filtered AWS/SCM call. Budget: <= 3 refreshes per trace,
each through the existing `Clients` (same per-run cache, same `Deadline`, same audit path), and default
**off** until decision 6 says otherwise (`--refresh-topology` or `topology.refresh_on_miss: true`).

Store: `~/.cache/nettrace/topology.json` (alongside `addresses.json`; `NETTRACE_CACHE_DIR`), directory 0700,
file 0600, atomic write (temp file + `os.replace`, `O_NOFOLLOW`), `flock` because the web server runs two
traces at once. It is **untrusted input on load**: schema-validate, cap size (5 MiB), device names must exist,
IPs parse. The current `addresses.json` load is not validated; apply the same hardening there.

### 2.5 Ambiguity always yields UNKNOWN

UNKNOWN link hop (trace -> INCOMPLETE, exit 4) in each of these:
- several learned links match the egress `(device, interface, next_hop)`;
- the egress interface has more than one observed neighbour and `next_hop` matches none;
- an address has more than one owner (overlapping VRFs/IP space);
- the only matching link is inferred, expired, or failed refresh;
- learned and declared disagree *and* the declared link's device was not reachable to settle it
  (declared still wins, but the hop is WARN with the conflict text);
- the CGW IP is NAT'd (peer matches, local does not);
- parse failure of any discovery output (`DeviceError`, never "no rows", Hard rule 3).

## 3. Crawl algorithm

```
nettrace topology crawl [scope flags]
  0. load inventory + CrawlPolicy (inventory `topology.crawl:` section; defaults below). Open audit.mode("crawl").
     audit.log("crawl", "-", "begin run=<id> limits=<...>", "ok").
  1. control planes (no per-device SSH), parallel, capped:
       Panorama: devices/HA/groups  -> managed-device facts
       AWS: for each inventory (account, region): TGWs, attachments, VPN connections, CGWs, VGWs, ENIs for
            VM-Series; DX once per account (P5)
       SCM: service connections, remote networks, IKE gateways, IPsec tunnels
  2. device BFS. Frontier = inventory devices (all, or --device) + Panorama-managed firewalls (opt-in
     `topology.auto_devices: panorama`). Each device: one session, fixed command set (section 1),
     parse, emit Observations. Expansion beyond inventory only through eligible candidates (below).
  3. join Observations -> candidate links (section 2.2), merge with declared (2.3), write store atomically.
  4. audit.log("crawl", "-", "end run=<id> devices=N ok=.. failed=.. links=.. new=.. changed=..", "ok").
```

Limits (all in the policy, all enforced in code, defaults conservative):

| Limit | Default |
|---|---|
| overall crawl deadline (reuse `Deadline`) | 600 s |
| max devices per run | 200 |
| max depth from a seed (candidate hops) | 1 (0 = inventory only) |
| concurrent device sessions | 4 (one session per device) |
| min gap between commands to one device | 1 s (matches console rule) |
| per-device wall clock / commands | 60 s / 40 |
| per-command read timeout / output cap | 30 s / 256 KiB (over the cap = `DeviceError`, not partial rows) |
| rows kept per command (neighbors, ARP, routes) | 2000; more = `DeviceError` "table too large, narrow scope" |
| AWS concurrency | 8 (account x region); `boto_config()` timeouts and retries unchanged |
| per-device cooldown between crawls | 15 min unless `--force` (persisted in the store) |
| per-profile auth-failure stop | 2 failures stops that credential profile for the run |

**Seeds and eligibility (credential rules).**
- Seeds: inventory devices, the Panorama, the AWS accounts and the SCM tenant from the inventory. Nothing
  else is contacted by default.
- A CDP/LLDP/BGP neighbour is recorded as a **candidate** (sanitised name, platform string, address). It is
  logged into only if **all** hold: `topology.crawl.auto_login: true` (default false), its address is inside
  `allow_prefixes`, its platform matches a credential profile (`cisco_iosxe` capabilities
  Router/Switch, platform string regex), its SSH host key is **already in known_hosts** (no first contact,
  `ssh_strict` stays true), depth <= `max_depth`, and the device count is under the cap. Otherwise: recorded,
  shown as a ghost node, never contacted. The crawl never writes `inventory.yaml`; `topology show --as-inventory`
  prints a YAML snippet for the owner to paste.
- **No credential reuse across vendors.** Credentials are looked up per platform through the existing
  `*_env` names and `DEFAULT_ENV`. Cisco creds only go to `cisco_iosxe` devices, the PAN-OS/Panorama key only
  to Panorama and its managed serials (via `target=`), SCM creds only to SCM, AWS roles only to AWS. No
  fallback list, no "try every credential on an unknown host".
- Spray/lockout guard: stop a credential profile after 2 authentication failures in a run. The existing
  `CiscoClient._auth_failed` cooldown is in-memory, per process; a crawl run per cron/CLI invocation would
  forget it. Persist it in the store (30 min lockout) and apply it to traces too.
- Panorama-managed firewalls: name = sanitised hostname, key = serial. Skip disconnected ones (record as
  unverified), follow `follow_ha_active` as traces do.

**Loops and duplicates.** Identity = inventory name, else serial, else canonical management IP. A visited
set keyed by identity, plus the depth cap, bounds cycles (A-B-C-A). The link graph may contain cycles; only
the trace's existing `(position, src, dst)` loop check matters at trace time.

**Failure semantics.** Per-device errors are recorded (`Unavailable`-style) and the crawl continues; a
failed device's links keep their old `last_confirmed` and become "unverified" as they age, never deleted.
Parser failure on any command rejects that device's whole observation set for the run.

**Audit.** Every request already goes through `audit.log`/`audit.refused` (and the contextvar adds
`"mode":"crawl"`). Add: `begin`/`end` summary records, and one record per skipped candidate
("skip candidate: outside allow_prefixes", status `refused`). Candidate strings are length-capped and have
control characters stripped before logging.

## 4. CLI and UI surface

```
nettrace topology crawl [--device NAME]... [--scope control-plane|devices|all] [--no-aws] [--no-prisma]
                        [--max-devices N] [--max-depth N] [--timeout S] [--force] [--dry-run]
nettrace topology show  [--kind K] [--confidence learned|inferred|declared] [--stale] [--device D]
                        [--as-inventory] [-o table|json|text]
nettrace topology diff  [--against inventory|previous|FILE]
nettrace topology clear                       # deletes only the topology cache file
```

- `crawl --dry-run` prints the exact request list per device and class, and sends nothing. It is the
  review artifact for the owner's approval of section 1.5.
- `show` columns: id, A, B, kind, confidence, oper, age, sources. `--as-inventory` emits `links:` YAML to
  stdout for promotion to declared.
- `diff` classes: observed-not-declared, declared-not-observed, conflicts, changed since last crawl.
  Exit 0 identical, **5** differences (new code; 1/2 stay errors), documented like D8.
- `trace run` gains `--no-learned` (declared only, today's behaviour) and `--refresh-topology`. The link hop
  summary carries the origin: `fw-dc1 tunnel.1 -> vpn-0abc/tgw-attach-1 [declared]` or
  `[learned 12m: panos show vpn flow + aws DescribeVpnConnections]`. `--verbose` shows the provenance rows
  as evidence. Inferred/expired links give the UNKNOWN hop from 2.5.
- JSON contract: additive only. A new optional hop field `link: {origin, confidence, age_s, sources[]}`;
  no change to the PascalCase top-level keys, so saved traces and `--query` keep working.
- Maps (`viz/`): the engine-link label gets the origin suffix; edge style declared = solid, learned = solid
  with an `L` badge, stale = amber, conflict = red dotted with a warning mark. Inferred links are drawn dashed
  grey and are never part of the path.
- Web UI (`web/topology.py`, `app.html`): `auto_topology` builds links from the merged view, ghost nodes for
  candidates (greyed, no console), a legend, and provenance in the inspector. New route `GET /api/topology`
  only (token, Host/Origin checks unchanged). **No crawl endpoint**: crawling stays an explicit CLI action
  (decision 9). All provenance strings are device-controlled: they go through `html.escape` in `svg.py` and
  `esc()` in the viewer JS; CSP unchanged.

## 5. Test strategy (existing seams, no demo branches)

Principle: add simulator capability below the four seams; add no `if demo` anywhere. Existing 233 tests must
pass unchanged because declared links remain the default path.

1. **Pure unit tests** (fast, no seams): join rules fed with parsed observation dataclasses; merge
   (declared wins, agreement, conflict, absent, ambiguous); TTL with an injected clock; interface-name
   normalisation; ambiguity cases from 2.5; multi-valued address ownership.
2. **Parser tests** with committed fixtures for each command (CDP, LLDP, `show interfaces TunnelN`,
   `show crypto session`, PAN `vpn flow`/`ike-sa`/`lldp`, AWS VPN/CGW). Property: truncated or garbled input
   raises `DeviceError`; it never returns an empty list.
3. **Simulator additions** (all computed from `demo/lab.py`, like D12):
   - `sim_cisco.py`: `show cdp neighbors detail`, `show lldp neighbors detail`, `show interfaces Tunnel200`
     (source/destination/protection), `show crypto session`, `show ip bgp summary`,
     `show ip route connected`, `show vrf`. The lab device model gains `neighbors` and `tunnels`.
   - `sim_panos.py`: `<show><lldp>`, `<show><vpn><flow|ike-sa|ipsec-sa|gateway>`, `tunnel.1` in
     `show interface all`; Panorama `<show><templates>` if used.
   - `sim_aws.py`: `describe_vpn_connections` (with a sentinel fake PSK in `CustomerGatewayConfiguration`),
     `describe_customer_gateways`, plus DX ops later. Gap to flag: the backend seam is
     `backend.call(account, region, op, params)` with no `service`, and DX ops live in a different
     service. Add `service` to the seam (touches Hard rule 6's seam list: owner OK needed) or keep op names
     unique per service.
   - `sim_scm.py`: the four deployment/network endpoints; unknown ones keep returning 404.
4. **Golden integration test, the key regression:** load the lab inventory with `links:` removed, crawl
   through the seams, and assert the learned set equals the lab's declared `dc1-aws-vpn` and `dc1-prisma-sc`
   (the `dc1-internet` `external` link is not learnable and stays declared). Then run all 12 presets with
   zero declared links and assert the same `expect` outcomes as `tests/test_demo_presets.py`.
5. **Hostile-input tests:** a CDP neighbour named with newline/ANSI/`<script>`; 5000 fake neighbours (cap
   hit = `DeviceError`); a neighbour claiming a management IP outside `allow_prefixes` (never contacted);
   duplicate IPs; A-B-C-A loop; a hung device (deadline); two auth failures (assert the fake connection was
   opened at most twice and the profile stopped); name collision across Panorama hostnames.
6. **Guard and audit tests:** a recorder wrapped around each seam asserts every crawl request matches the
   discovery allowlists in 1.5; `show running-config`/`<request>`/an unlisted AWS op from crawler code raise
   `ReadOnlyViolation`; the audit file has `"mode":"crawl"` for every request and the begin/end records.
7. **Secrets test:** the sentinel PSK appears in none of: cache file, `Evidence`, audit log, `--verbose`,
   `-o json`, web API responses.
8. **Staleness/refresh tests:** clear the store, trace `dc-to-prod-web`, assert the link resolves via
   refresh-on-miss with at most the budgeted extra requests; stale -> refresh failure -> UNKNOWN.
9. **Web tests** in the style of `test_hardening.py`: `/api/topology` needs the token, rejects bad Host/Origin;
   hostile names are escaped in the topology JSON, the SVG and the viewer.
10. Real-device fixtures (R3): capture `--verbose` evidence from the first live runs and replace the
    **[verify]** shapes.

## 6. Security review of the new surface

| Threat | Impact | Control |
|---|---|---|
| Hostile or compromised CDP/LLDP neighbour advertises a management IP it controls and the crawler logs in | Cisco credentials sent to an attacker host (the highest risk) | `auto_login` default off; `allow_prefixes`; platform profile match; host key must already be in known_hosts (paramiko checks the key before authentication, so the password is not sent to an unknown host); depth/device caps; no TOFU |
| Spoofed identity (neighbour claims to be `core-rtr1`) | wrong topology, wrong far end for a trace | keys are inventory name/serial/IP, never advertised names; one-sided claim = inferred; learned needs the far end's own session to agree; a device can only assert links it is an endpoint of |
| Control characters / escape sequences / markup in names, descriptions, tags, CGW `DeviceName` | terminal injection, XSS in map/UI, log forging | sanitise at parse time (length cap, strip control chars); render only through `rich` escaping, `html.escape`, `esc()`; audit JSON caps; AWS tags and `DeviceName` are display-only, **never used for logic** |
| Injection into commands | config or data exposure | CDP/LLDP interface names pass `safe_token` before use in `show interfaces <x>` (fail = skip + audit); IPs via `ipaddress`; PAN XML via `build_op`; AWS/SCM values as structured params; discovery allowlist is exact |
| Neighbour flood / huge tables | memory, CPU on device and nettrace | row/output/command/device caps; truncation is an error, not a partial result; no full BGP/route tables |
| Loops | infinite crawl | identity visited set, depth cap, deadline |
| Secrets in responses | PSKs from `DescribeVpnConnections`; any key-bearing show | scrubber before cache/evidence/audit; discovery allowlist excludes key-bearing commands; evidence stored as digest, raw capped as today; secret sentinel test |
| Cache poisoning / tampering | wrong links used in traces | 0600/0700, atomic write, `O_NOFOLLOW`, schema validation on load, size cap; the same hardening for `addresses.json` |
| Credential lockout | account lockout across the estate | persisted auth-failure lockout, 2-failure profile stop, per-device cooldown |
| Silent address collision | wrong device picked (guess) | multi-valued ownership; duplicate = UNKNOWN |
| Web exposure | remote crawl trigger or data leak | read-only `GET /api/topology`; no crawl route; Hard rule 7 unchanged (127.0.0.1, token, Host/Origin, JSON) |
| Artifacts leak topology | IPs, ASNs, account IDs shared | `topology show`/maps through `write_private`; provenance dropped from maps unless `--with-evidence` |
| TLS/SSH downgrade | MITM of the crawler | Hard rule 8 untouched; the crawler cannot set `ssh_strict: false` or `verify_tls: false` |
| Over-trusting a stale link | confident wrong verdict | TTL, refresh-on-stale, expired = inferred = UNKNOWN |
| Scheduled/unattended crawl | broader blast radius, stale creds in cron env | not in scope; if wanted, dedicated read-only creds and an owner decision (10) |

Not weakened: read-only (all requests via `.show`/`.request`/`AwsEnv.call`/`ScmClient.get_all`, plus the
narrower allowlists), live data first (device routing answers stay live; links are a mapping), never guess,
env-only creds, escaping, seams-only simulation, local authenticated web, untrusted device output.

## 7. Phased plan

| Phase | Content | Effort | Notes |
|---|---|---|---|
| **P0 Foundations** | D14 decision record; `Provenance`/`Link` fields (defaults = declared); `TopologyStore` (validated, 0600, atomic, flock); multi-valued address ownership + UNKNOWN on duplicates; validate/harden `addresses.json`; persisted auth lockout; PSK scrubber hook point | S-M | No behaviour change; fixes two latent "silent guess" issues. Do first |
| **P1 Control-plane crawl** | Panorama devices -> opt-in auto devices; AWS TGW/attachment/VPN/CGW/ENI facts (A1, A2 approved); SCM service connections/remote networks/IKE (D2-D5 approved, endpoints verified); `topology show`, `crawl --dry-run` | M | One-sided facts = inferred |
| **P2 Tunnel joins + engine** (**build first**) | Cisco tunnel/crypto parsers, PAN `vpn flow` parser, joins to AWS VPN/TGW and Prisma; `TopologyView` behind `link_from_*`; hop provenance; WARN on conflict; sims; golden "presets with zero declared links" test | L | Replaces the hand links people actually maintain. Start with fw-dc1 <-> TGW VPN, since it is the main link in the lab and probably in production |
| **P3 Adjacency, diff, TTL** | CDP/LLDP/BGP/OSPF/HA joins; `topology diff`; TTL states; refresh-on-miss (off by default) | M | Mostly validation and map value |
| **P4 UI** | `/api/topology`, badges, legend, ghost nodes, inspector provenance; JSON `link` field | M | Reuse R9.7/R10.3 work |
| **P5 Optional** | Direct Connect (A3-A7); learned `networks` for `locate_source` (ambiguous = `--start-at`); auto-login candidates; Panorama-managed Prisma (needs V6) | M-L | Each separately approved; auto-login may stay off forever |

Leave manual (declared in YAML): `external` ISP/Internet links; NAT-T tunnels (CGW behind NAT);
DMVPN/FlexVPN/Virtual-Access; SD-WAN; Cloud WAN and TGW Connect/GRE; Prisma BGP-learned routes and mobile-user
pools (no GET source known); remote-network sites' internal prefixes; switches not in the inventory; any link
the owner wants pinned regardless of what devices say; credential mapping for new devices.

## 8. Decisions the owner must make

1. Amend D5: allow learned topology at all? Only tunnel/attachment joins (P1-P2), or also CDP/LLDP/BGP (P3)?
2. Approve, individually, the allowlist additions: A1-A7 (AWS + IAM), B1-B16 (Cisco discovery allowlist),
   C1-C12 (PAN-OS discovery allowlist), D1-D5 (SCM endpoint allowlist).
3. Accept that `ec2:DescribeVpnConnections` lets the role read VPN pre-shared keys (scrubbed in nettrace,
   not preventable in IAM), or keep AWS VPN links manual.
4. Inferred links: never forward (recommended, UNKNOWN) or forward with WARN.
5. Learned links in traces: default on when corroborated (with `--no-learned`), or opt-in `--use-learned`.
6. Refresh-on-miss: default off (recommended), on with the 3-refresh budget, or never.
7. Auto-login to CDP-discovered neighbours: never (recommended), or only inside `allow_prefixes`.
8. Auto-create devices from Panorama's managed list (same Panorama key, serial-keyed), opt-in or not.
9. Web UI: read-only topology only (recommended) or also a crawl trigger.
10. Who runs crawls and where: operator workstation only, or a scheduled job with dedicated read-only credentials.
11. TTL values (1 h fresh / 24 h max proposed), per-device cooldown (15 min), caps (200 devices, depth 1).
12. Prisma: confirm SCM vs Panorama (V6); and whether any non-GET API (Insights, POST) may be an exception.
13. New exit code 5 for `topology diff` and the additive `link` field in trace JSON.
14. Add `service` to the `AwsEnv.backend_override` seam (needed for DX simulation).
15. Where the store lives: `~/.cache/nettrace/topology.json` (proposed, never committed) or beside the inventory.

## 9. Summary

1. Biggest win is learning tunnel/attachment links (PAN/Cisco <-> AWS VPN/TGW, Prisma); same-domain next hops already resolve.
2. A link is `learned` only when two independent observations agree; one-sided is `inferred` and never forwards a trace.
3. Declared inventory links always win; disagreements are reported (WARN and `topology diff`), never silently overridden.
4. Cisco and PAN-OS guards are generic `show`; I propose narrower discovery-only allowlists instead of widening anything.
5. Real new permissions: `ec2:DescribeVpnConnections`, `ec2:DescribeCustomerGateways` (+ Direct Connect later), and an SCM GET endpoint list.
6. `DescribeVpnConnections` returns VPN pre-shared keys; a scrubber before cache/evidence/audit is mandatory.
7. Two latent issues found: discovered addresses overwrite on duplicate IPs (silent guess), and the Cisco auth lockout is per process.
8. Crawl is CLI-only, bounded (devices, depth, rate, deadline), audited with `mode=crawl`, no credential reuse across vendors, no auto-login by default.
9. Test with the existing seams; the key test is "all 12 demo presets pass with zero declared links".
10. Build order: P0 foundations (S-M), then P2 tunnel joins with P1 inputs (L), then adjacency/diff (M) and UI (M); ISP, NAT-T, DMVPN and Prisma BGP stay manual.
