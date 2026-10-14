# 21pins: public network policy and verification design

Status: proposed product specification; independent design reviewer APPROVED after three bounded review rounds. Owner review pending before implementation planning. Documentation only. None of the commands or adapters proposed here is represented as shipped.

## 1. Product primitive and boundaries

**Who should be able to reach what, through which protected path, and can 21pins prove that the policy is actually enforced?**

Expose gateway, network, vpn, service, policy/access and verification—not a particular router, geography, deployment, tunnel interface or personal infrastructure. WireGuard and Tailscale implement `vpn`; they are not the primary product model. Keep current LLM provider routing, grants, receipts and native SSH lifecycle intact. This is an additive network-policy product surface, not a replacement for those features.

The new registry uses the typed discriminator `network_gateway`, exposed as `gateway` in this public CLI, and a separate local object-ID namespace from existing proxy configuration/targets. Here `gateway` means a network routing/access boundary. The existing localhost LLM HTTP gateway remains the proxy served by the existing commands/API; it does not become a home-router object. Documentation must distinguish **network gateway** from **LLM proxy**. No access/management endpoints are added to that proxy by this design.

Options considered:
- Protocol-first commands: close to native tools, but leaks platform internals and fragments common workflows. Not the public default.
- **Object-first model with capability-based adapters (selected):** matches the owner's proposed stable vocabulary while retaining native evidence and limitations.
- Universal router/VPN configuration engine: much broader authority and semantics. Explicitly deferred; inspection/verification does not require it.

Non-goals: installing trust, scanning arbitrary networks, automatic enrollment/configuration/repair, replacing native VPN clients, inventing a VPN protocol, or guaranteeing all platforms support the same checks. No implementation, deploy, existing CLI rename or infrastructure mutation is authorized by spec review.

## 2. Public objects and relationships

| Object | Meaning and minimum contract |
|---|---|
| gateway | Registered network boundary with friendly name, immutable local ID, adapter/platform binding and evidence-backed capability state; relates to networks, VPN connections and routes. |
| network | Named source context such as trusted, guest or iot, bound to actual adapter-observed selectors. Labels do not themselves grant trust. A role and actual membership are separate facts. |
| vpn | Logical protected connectivity/path, with participating gateways/hosts, endpoint/peer/device references, route ownership and implementation binding. A standalone client or tailnet need not belong to a gateway. |
| service | Named destination: exact local endpoint binding(s), transport/ports, optional application protocol and allowed verification methods. DNS, SSH, web and arbitrary TCP/UDP are profiles, not separate top-level products. |
| policy | Versioned reachability intent binding subject/source, service, allow/deny, required/forbidden path(s), address families/transports, direct/mediated access scope and fail-closed/exposure requirements. |
| access | A resolved question/effective-policy view for a subject/source and service, not another mutable policy store. Policies are the source of declared intent. |
| verification | Time-scoped assessment of resolved policy revision(s) and bound objects, combining normalized observations with provenance, scope, freshness, missing evidence and verdict. Not an execution authorization. |

The user-facing overview may be a tree:

```text
gateway home-router
  networks: trusted, guest, iot
  vpn connections: private-network
  routes: declared protected destinations

vpn private-network
  implementation: adapter-selected

service private-dns
  protocol: DNS; transports: declared UDP/TCP

policy
  trusted -> private-dns: allow via private-network
  guest -> private-dns: deny via private-network
```

Internally relationships form a small graph, not forced containment: one VPN can involve multiple gateways/devices; a service can have several endpoint bindings; some networks/VPNs have no gateway controller available. A network is a source/membership context, not a VPN implementation; networks and VPNs can have many-to-many path relationships. Service endpoints are bound to their local routing realm as well as endpoint identity, so identical addresses in unrelated realms are not conflated. Store references, not duplicated mutable children. Verification is an immutable assessment/run record attached to intent and evidence, not another mutable configuration authority or a new CRUD subsystem. No graph database, plugin marketplace or generic workflow language is needed.

Friendly names are suggested locally, operator-confirmed and distinct from identity. Aliases map to immutable registration IDs plus adapter/resource bindings. Duplicate/ambiguous suggestions are suffixed; renames preserve identity; replacement/rebinding creates a new revision and invalidates old approvals/evidence. Never route an approval by a reused alias alone. Object names are bounded identifiers, never shell fragments.

## 3. Public CLI contract (proposed, not installed)

```text
21pins discover

21pins inspect gateway home-router
21pins inspect vpn private-network
21pins inspect service private-dns
21pins inspect network guest
21pins inspect policy guest-private-dns

21pins verify gateway home-router
21pins verify vpn private-network
21pins verify access private-dns
21pins verify isolation guest private-dns

21pins inspect vpn private-network --details
21pins inspect wireguard private-network
21pins inspect tailscale personal-tailnet
```

`vpn` stays the stable entry point. Protocol inspection aliases resolve the SAME VPN object and delegate to its matching adapter; an implementation mismatch is a clear error, never an implicit rebind or different target. `--details` reveals safe capability/protocol detail; it does not expose credentials, MACs, public/WAN addresses, raw interfaces/marks/table numbers, raw configuration or unfiltered logs. A separately scoped technical diagnostic may use minimized native details locally if genuinely required; it is not the default product output.

`verify access private-dns` resolves the current registered source/actor context and matching policy declaration(s), one applicable revision per requested tuple. If source identity is ambiguous/unavailable, return UNVERIFIED with an explicit source-selection requirement; do not infer trusted/guest from a name, failed connection or SSID alone. Proposed explicit form: `21pins verify access private-dns --from trusted`. Network source declarations and independently supported membership evidence must both be recorded; an explicit argument is not by itself proof of membership.

`verify isolation guest private-dns` requires a declared deny policy for that source/service pair, with explicit protected-path scope. Do not invent a deny policy from an unsuccessful connection. Multiple conflicting or incomparable matching policies make the question unresolved, not silently resolved by last-write-wins.

Verification meanings:
- `verify gateway`: scoped operational/identity/configuration prerequisites for that gateway, not all access policies.
- `verify vpn`: declared VPN status/route/path requirements covered by available capabilities, not every attached network's isolation.
- `verify access`: observed reachability, application behavior if declared, and required path/exposure properties for the resolved source/service policy.
- `verify isolation`: meaningful deny enforcement for the declared source/service/path/family/transport scope, with a valid same-endpoint positive control and causal boundary evidence.

Human output leads with friendly source, service, expected path and result/missing fact. A future structured output uses immutable refs plus the same scope, verdict and evidence basis; a simple success boolean without scope is insufficient. No claims beyond the evaluated policy. Proposed exit contract: 0 VERIFIED, 1 VIOLATED, 2 UNVERIFIED (including partial/unsupported/stale), 3 invalid request/operational error. Existing command exit semantics remain unchanged.

## 4. Discovery: suggestion, not reconnaissance or authority

Default discovery is passive, local and bounded: read only already-authorized, minimized metadata from enrolled native clients/registrations and specifically scoped read-only gateway channels. If a channel/client is not enrolled/authorized, report that limitation; do not initiate login, read credentials, connect to unknown routers, scan LAN ports, inventory every device, request MACs/public IPs or change trust. Native credentials remain in native custody; use their authorized interfaces, never scrape keys/cookies/profile secrets into 21pins.

Suggest objects/names such as home-router, private-network, trusted, guest and private-dns from non-sensitive role/capability facts. A detected client is only a candidate implementation, not proof of connectivity, gateway support, protected-path ownership or service reachability. Discovery does not register automatically, overwrite an existing binding or authorize probes. Reconcile suggestions by local IDs; unresolved duplicates require confirmation.

Every discovery result reports candidate confidence, enrollment status, supported checks and missing facts without raw topology. Unsupported gateways may still be named as manually declared objects, but have no verified capabilities. A guessed network label cannot satisfy a policy. All registration/mutation/probe authority is separate from discovery.

## 5. Adapters and capability contract

Separate platform and VPN dimensions:

| Gateway adapter | Platform-specific responsibility | Product commitment |
|---|---|---|
| Generic Linux | Effective routes/policy rules, interface/network binding, firewall evidence when available, native service state | Initial reusable read-only target; platform/version/permissions still tested. |
| OpenWrt | UCI-to-effective kernel/netifd/firewall translation, logical-network mapping and routing/firewall order | Initial platform-specific candidate; config alone is not universally effective-policy proof. |
| GL.iNet | OpenWrt base plus generated VPN route policy, source selectors, destination sets, killswitch/leak guards and managed forwarding interpretation | Extension of OpenWrt semantics, not a parallel public object model. |
| UniFi | Authorized controller/API interpretation and evidence of effective device policy | Roadmap, not implemented support. |
| OPNsense | Versioned native routing/firewall/controller evidence | Roadmap, not implemented support. |
| MikroTik | Versioned native routing/firewall/controller evidence | Roadmap, not implemented support. |

| VPN adapter | Common model projection | Product commitment |
|---|---|---|
| WireGuard | Session freshness, fixed peer/endpoint binding, allowed-destination/route evidence, protected-path observations | First extraction target from existing native work; no public peer-enrollment mutation in this slice. |
| Tailscale | Device/tailnet identity, supported route/access-policy evidence and path observations | Second adapter target; do not equate online/device status with ACL enforcement or treat its routes/SSH as WireGuard semantics. |
| OpenVPN | Future status/client/route/path evidence | Deferred. |
| Others | Add only after native evidence contracts and representative fixtures exist | Deferred. |

Capabilities: status, peers/devices, routes, reachability, exposure, isolation. Each returns supported/partial/unsupported/unknown plus platform/version/permission requirements and evidence scope. Support is per operation and policy property, not one boolean per vendor. An online client can support status but lack isolation evidence. Unsupported/unknown must propagate to UNVERIFIED when required; a missing capability never becomes success or triggers broad sudo/SSH grants.

Adapters normalize **facts, not verdicts**: active source/destination selectors, route/path binding, enforcement guards, policy precedence/override coverage, observations and errors. The generic verifier evaluates declared policy against those facts. A gateway adapter and VPN adapter can contribute independently to one assessment. Keep provenance and native semantics sufficient to audit normalization; never hide an incompatible capability behind a universal method that always returns true.

Normalized evidence separates `forwarding_permission`, `path_selection` and `enforcement_guard` facts, each with scope/provenance; none substitutes for another. No promise to implement all adapters before the first slice. Prefer existing deterministic native mechanisms and small concrete adapters; defer an extensible plugin SDK until there are multiple working implementations with actual variation.

## 6. Policy, authorization and verification lifecycle

A network policy expresses desired reality, e.g. trusted may reach private-dns via private-network; guest may reach public Internet/DNS but not that protected service/path. It does NOT permit configuration changes, obtain credentials, grant management access or authorize arbitrary probes. Existing 21pins execution grants/identity/scope/data-boundary controls continue to gate what the verifier may inspect/run. Keep network reachability policy and execution admission policy explicitly typed apart; reuse IDs/receipts/persistence patterns without changing existing grant semantics.

### Declared-policy resolution: no precedence language in the first version

Normalize each declared scope to finite sets of immutable source-network references, canonical service endpoint bindings (including routing realm), address families, exact transport/port tuples and access modes (`direct`, `mediated`, or an explicit set of both). There are no wildcard selectors, inferred defaults, priority inheritance or implicit exceptions in the initial public policy store. A source must resolve to a unique applicable membership context; ambiguity is UNVERIFIED.

A policy has one allow/deny decision and its explicit path/exposure/fail-closed requirements. The common allow form requires a named protected path; the deny form must say whether it forbids service access across all paths in scope or only named protected paths. Keep those restrictions within ONE policy, not overlapping allow/deny records. Different paths or decision values do NOT make two otherwise overlapping scopes disjoint.

Two declared policies overlap if their source, canonical endpoint/realm, family, transport/port and access-mode sets have a nonempty common tuple. Compare resolved endpoint bindings, not just service aliases; unresolved bindings prevent successful conflict checking. Registration/revision must reject overlapping scopes, even if decisions currently agree. Imported/legacy/externally edited overlap makes affected verification UNVERIFIED with the conflicting policy refs—never last-write-wins, implicit deny-wins or silent specificity rules. A missing matching declaration is UNVERIFIED, not permission or a synthesized deny.

For a compound service question, expand the explicitly requested scope into these tuples, require exactly one matching declaration for every tuple and aggregate their separate property outcomes. Any contradictory observation makes the scoped aggregate VIOLATED; otherwise an uncovered/uncertain required tuple makes it UNVERIFIED; only complete passing coverage is VERIFIED. A supported subset must not narrow the requested scope silently. Cross-cutting constraints that need exceptions must be rewritten into disjoint scopes before acceptance; composition/priority language is deferred.

These restrictions apply to PUBLIC DECLARED INTENT, not native firewall/routing rule lists. Native overlapping rules remain interpreted by the platform adapter's effective precedence/override semantics; 21pins does not rewrite them into this declaration format or delete them.

Lifecycle:
1. Resolve immutable objects, source identity and service endpoint bindings; require exactly one applicable policy revision per requested tuple and bind ALL resolved revisions to the assessment.
2. Check capabilities and existing least-privilege read/probe authority; present the smallest missing evidence/permission, not a full suite by default.
3. Read minimized effective policy/path/service facts. Validate selectors, destination parity and active runtime interpretation; account for overriding or alternative routes and mediated DNS/proxy paths within declared scope.
4. Reuse still-applicable same-endpoint trusted-positive/boundary evidence if revisions/bindings and time scope match. Explicitly attach earlier evidence to the composite assessment; do not pretend it was captured at the new probe's timestamp.
5. Only when needed and explicitly authorized, run a small bounded challenge with required observer readiness, source/protocol binding and covered start/end times. Each operation including cleanup has a hard deadline no longer than120s; no indefinite collector or silent rearming/retry.
6. Evaluate required properties, record VERIFICATION verdict/evidence locally, close observers/leases and verify cleanup. Failure to clean leaves an unresolved operational error, not a clean success.

A service's actual endpoint(s)/ports/families and VPN/route binding are necessary local facts, not default public output. Keep them inside the adapter/native boundary where possible; use derived matching facts and opaque local refs in reports. Do not ask a user to paste credentials or sensitive addresses to match bindings. If necessary sensitive collection remains, request a narrowly described owner operation rather than weakening checks.

## 7. Evidence and verdict semantics

Verdicts: VERIFIED (all declared required properties pass), VIOLATED (attributable observation contradicts intent), UNVERIFIED (insufficient/partial/stale/unsupported/uncertain evidence). Preserve individual property states; do not turn unknown into false-denial evidence. A passing subset can be reported, but the whole required scope remains UNVERIFIED until complete. Inspection status is not enforcement proof.

Each verification binds all resolved policy revisions and their tuple coverage, source/network identity and evidence basis, immutable gateway/VPN/service registrations, endpoint/transport/family scope, effective-policy observation/version, actual observation windows, capability limitations and cleanup state. It records whether evidence was observed, operator-attested or adapter/runtime-validated; these confidence levels cannot be silently interchanged. If owner-attested active facts are accepted for an operational assessment, display that reliance. Configuration/file presence alone does not prove its effective application.

Evidence reuse is invalidated by changed identity/bindings, endpoint or path, source assignment, policy revision, effective configuration, adapter semantics/version or relevant runtime facts. No timeless VERIFIED badge. Report the assessment timestamp/scope and later stale state separately. A policy change never silently carries old enforcement proof forward.

Allow proof requires real same-endpoint reachability and required protected path evidence; DNS success must include valid response/transport, and required filtering uses a validated explicit policy indicator rather than NXDOMAIN/timeout alone. TCP connection is not SSH authentication or HTTP health. UDP delivery/send success alone is not application reachability; arbitrary UDP needs a service-specific response/witness or remains UNVERIFIED.

Deny/isolation proof requires:
- source context and meaningful positive controls sufficient to rule out a broken guest/client/observer path;
- a same-endpoint allowed-source positive baseline for the protected service/protocol scope, not arbitrary listening services or bastion access;
- observed denied transport/application behavior with source/time binding;
- exact challenge absent beyond the required monitored boundary during complete windows when that observation method is used;
- causal evidence for the **intended policy boundary**, not silence/aggregate peer counters alone.

Two valid causal evidence forms:
1. A validated test-linked matched deny event/counter/trace with the correct source/destination/path and applicable policy. Aggregate/background deltas alone are insufficient.
2. Validated active/effective source-scoped route/access selection excluding the denied source, with applicable fail-closed guard and bound protected destination/path, corroborated by synchronized differential observations. Per-probe rule-counter delta is NOT universally mandatory. It would add which exact operation consumed the probe, not a new required isolation property when structural policy evidence already establishes the intended boundary.

A generic forwarding permission is distinct from route/mark/path selection. Its presence is neither automatically a violation nor a reason to delete managed rules. Conversely, declared source exclusion is insufficient if another applicable route, global mark or mediated path bypasses it. Platform adapters must disclose their coverage rather than assert completeness from one configuration stanza.

Protocol-independent active policy may cover both UDP/TCP; protocol-specific rules require corresponding coverage. Never upgrade an IPv4/private-DNS assessment into IPv6, all-host/admin-plane or all-port isolation. Nonce absence for one special/local-cached name is not proof of all DNS upstream selection: scope the claim or require effective proxy/upstream policy or a suitably validated challenge if indirect DNS use is in scope. Service health, aggregate transfer counts, one timeout and a default label cannot independently prove enforcement.

## 8. Reusable capability versus platform-specific interpretation

| Completed operational lesson | Generic capability | Remains adapter-specific |
|---|---|---|
| Same source/destination/transport/window binding | Object-bound observations and reusable positive-baseline validation | Native source/network identity and endpoint matching mechanisms. |
| Public positive/private negative + downstream challenge absence | Differential reachability/isolation verification | Capture interfaces/filters/privilege/runtime prerequisites. |
| Observer readiness immediately before a client challenge | Bounded owner-triggered synchronization and cleanup lifecycle | Remote/native observer transport and kernel packet format. |
| Active source-limited route plus fail-closed guard proves intentional exclusion | Normalized effective policy/path witness; counters optional when sufficient | Platform rule compilation, priority/selector semantics and override coverage. |
| Generic forwarding is not route authority | Separate permission, path selection and runtime facts | Managed/generated rule ownership and platform interaction. |
| Real filtering rather than unqualified NXDOMAIN | DNS response validation, explicit policy evidence and honest unknowns | Resolver-specific EDE/policy support and query/service APIs. |
| Authenticated VPN traffic is not necessarily a new handshake | Common session/path freshness with precise evidence wording | WireGuard handshake/peer counters; other VPN identity/session models differ. |
| Least privilege and immutable selector bindings | Target-bounded read authority and approval/evidence reuse guards | Exact native SSH/root-command adapters; no general shell fallback. |
| Partial evidence must not become a universal success | Scoped verdicts, provenance, stale/unsupported capability handling | Which platform can provide which missing fact. |

OpenWrt-specific: logical interfaces/zones, netifd policy-rule translation, UCI versus loaded kernel state, routing/firewall precedence and per-version compiled selectors.

GL.iNet-specific: generated VPN policy source-interface and destination-set matching, policy marks/table selection, generated guest leak blackhole/killswitch guards and the platform's managed VPN-forwarding marker/ownership. These fields stay inside its adapter. No hard-coded device, geography, address, interface name, mark value, routing table number or private deployment command appears in the public model.

WireGuard-specific: cryptographic peer/allowed-address binding, handshake semantics and peer counters. Tailscale-specific: authenticated device/tailnet binding and native access/route semantics. Technitium-specific status/filter evidence belongs beneath the DNS service adapter, not the public service name.

Existing domain-specific CLI/helper experiments remain historical/internal extraction inputs, not public command contracts to copy or advertise. No new public infrastructure-specific commands are added by this spec. Migration/removal of preexisting experimental literals needs an explicitly approved implementation compatibility plan; it is not performed in this documentation change.

## 9. Privacy, safety and records

Collect minimum facts before invoking an adapter; filter at source, not after raw outputs reach the model. No raw packet dumps, unrelated traffic/history, provider credentials, peer/private keys, auth cookies, hardware identifiers, public/WAN IPs or unreviewed screenshots in model calls, discovery/default output, telemetry or review artifacts. Detail inspection is not a privacy bypass. Protected topology is kept local only when required for binding/verification.

Reuse hardened local metadata patterns (atomic writes, restrictive permissions, symlink refusal, one writer). No new cloud control plane or database. Persistent verification records contain minimal normalized refs/scope/property outcomes/provenance/observed times and applicable policy binding, not packet bodies/raw logs. Define retention/cleanup in the approved slice plan; do not silently retain raw captures. Synthetic nonces are temporary correlation values, not credentials. Cleanup failure/stale snapshots are visible.

Discovery/inspection/verification never broadens immutable host roles, credentials, sudo policy or grants merely to produce a green result. Policy disagreement yields VIOLATED/UNVERIFIED, not automatic repair. Read-only management authority does not imply probe/configuration/deployment authority. Existing native credentials/trust/recovery paths stay unchanged.

## 10. Initial extraction slice and acceptance gates

This is an architecture spec, not a plan to implement six gateway vendors and three VPN stacks at once. Proposed first planning slice: object identity/policy/verdict contract, passive enrolled-resource suggestions, normalized read-only Linux/WireGuard and OpenWrt/GL.iNet witnesses using isolated fixtures, then one portable DNS access/isolation flow. Tailscale is the second adapter validation target; other listed platforms/protocols remain roadmap until tested.

Before declaring commands/support shipped, require:
- identical user-facing VPN/access/isolation semantics across representative implementations or explicit capability limitations;
- default discovery does not scan/connect/login/register/mutate or emit protected metadata;
- names disambiguate, immutable bindings survive rename and invalidate proof on substitution;
- current source ambiguity, wrong endpoint, stale/partial/effective-policy gaps and unsupported operations return UNVERIFIED;
- genuine leak/forbidden path yields VIOLATED; intentional active source-policy exclusion plus appropriate real observations can yield VERIFIED without artificial mandatory counters;
- missing fail-closed guard, alternate-route/proxy bypass, transport/family mismatch, inactive config and forged client self-attestation cannot produce VERIFIED;
- observer readiness/coverage/deadline/cleanup and DNS parser/protocol negative cases pass isolated tests;
- generic managed forwarding remains untouched and cannot alone imply VPN authorization;
- no changes to existing LLM proxy/grant/native SSH command contracts or production trust;
- public examples and fixtures use generic synthetic resources only, with no deployment-specific nouns, identities or addresses.

Implementation planning begins only after independent design review and owner review. Review approval is not authority to implement, publish, deploy or enable management/probe access.
