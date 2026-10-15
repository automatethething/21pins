# Network verification — first slice

This is an additive local CLI surface. It does not change the LLM proxy, execution-grant schemas/semantics, signed legacy receipts, SSH roles/certificates, existing hosts or native VPN configuration. No OpenWrt/GL.iNet, Tailscale or other vendor/protocol adapter is implemented here.

## What ships locally

- Immutable object IDs + binding revisions, friendly aliases, explicit atomic metadata import.
- Finite disjoint source/endpoint/realm/family/transport/port/access-mode policy scopes; no implicit priority/default/exception language.
- Normalized scoped evidence and VERIFIED / VIOLATED / UNVERIFIED assessment records.
- Passive bounded metadata discovery; generic local Linux/WireGuard readers and direct DNS UDP/TCP probes.
- Real isolated synthetic Linux/WireGuard/DNS integration, including a real intentional deny and an injected real leak.

`vpn` is the stable public abstraction. `inspect wireguard` is a matching expert view of the same object, not another registry.

## Privacy: no endpoint disclosure mechanism in v1

**Every endpoint remains suppressed in output, including intentionally public endpoints.** This slice adds no confirmation command, stored approval flag or inferred public classification. Imports reject unknown disclosure/confirmation fields. Reachability, DNS, discovery and `--details` cannot declassify anything.

A later local confirmation mechanism must bind immutable object ID + binding revision + exact endpoint, invalidate on rebinding/substitution, and never declassify adjacent/customer/home/private/tailnet topology, credentials, keys or tokens. Until that mechanism exists, there is no reachable “operator-confirmed” display state.

Necessary native bindings remain in owner-local `0600` metadata. Default output/receipts use opaque refs, normalized outcomes, provenance and actual observation windows, never keys, raw native output, MACs, packet bodies or unrelated topology.

## Metadata and commands

`PINS21_STATE_PATH` retains its existing meaning. New network metadata is `network-state.json` beside that existing state file; network assessment records live in `network-receipts/`. Metadata-only commands never construct the legacy store, initialize signing keys or load provider objects.

```text
21pins registry import /owner-local/manifest.json
21pins discover
21pins inspect gateway router
21pins inspect network trusted
21pins inspect vpn tunnel --details
21pins inspect wireguard tunnel
21pins inspect service private-dns
21pins inspect policy trusted-dns

21pins verify gateway router --request
21pins verify vpn tunnel --request
21pins verify access private-dns --from trusted --request
21pins verify isolation guest private-dns --baseline <prior-assessment-id> --request
```

The import is a local metadata operation only: no host enrollment, login, credential import, native configuration, permission grant or automatic discovery registration. The input file must be owner-local, regular and `0600`. Schema: `{"objects":[...],"policies":[...]}`. Objects use typed `kind`, bounded `alias`, explicit `binding`; references in imports can use friendly aliases and are resolved atomically to immutable IDs/revisions. Objects may omit unsupported bindings, but verification then remains UNVERIFIED. New objects cannot choose another object's immutable ID. Rebinding increments revision; friendly rename does not change identity.

Declare each DNS endpoint, routing realm, address family, exact `transports` (UDP/TCP) and `access_modes` explicitly; there is no implicit direct-only scope. The manifest's policy tuples reference a source network and service, realm, `ipv4`/`ipv6`, `udp`/`tcp`, exact port and `direct`/`mediated` mode. Only direct DNS is implemented; mediated, mixed-decision or unavailable native-vantage requirements remain UNVERIFIED rather than narrowing scope. No credentials, arbitrary argv or public-disclosure flags are accepted.

All inspect forms (including expert views / `--details`) are metadata-only. Discovery checks only registered metadata and `ip`/`wg` executable presence (maximum64 suggestions); it never runs native clients, reads key configs, scans, contacts a host or registers an object.

### Execution admission

An offline `--request` returns immutable scope and opaque execution-target digests. Issue an existing execution grant through the existing grant workflow with the exact requested target(s), `network.read` / `network.probe` capabilities and `network-metadata` data class. Network commands reuse the existing seven-pin evaluator, including its existing subject, status, time, target, data and approval checks. No new grant semantics or privileged helper is introduced.

Then execute the same question with `--grant ID` instead of `--request`:

```text
21pins verify gateway router --grant <existing-grant-id>
21pins verify vpn tunnel --grant <existing-grant-id>
21pins verify access private-dns --from trusted --grant <existing-grant-id>
21pins verify isolation guest private-dns --baseline <prior-assessment-id> --grant <existing-grant-id>
```

Subject resolution uses the existing local `ck whoami` helper; there is no auto-login or arbitrary `--sub` override. Admission rechecks current metadata and existing-grant revocation/expiry before each native read/probe. Native OS permissions must already permit the exact read/probe; no sudo/SSH/remote-shell fallback, installation, trust change or firewall/routing repair occurs. Missing identity/grant/tool/vantage is UNVERIFIED. Local grant evaluation is additional admission, not an unbypassable OS sandbox.

`--baseline` explicitly selects an owner-local historical positive assessment. Its endpoint, protocol/family/mode, object/policy revisions, native binding and10min lifetime must still match. Reuse retains the original times and is labeled operator-attested local historical evidence, never silently upgraded to fresh runtime evidence. JSON cannot set the in-memory runtime-validation seal. Synthetic records are not accepted as production evidence.

## Exact gateway and VPN meanings

`verify gateway` evaluates exactly:

1. `gateway.binding` — registered local namespace identity.
2. `gateway.interface_binding` — registered interface/address assignment.
3. `gateway.reader` — admitted bounded native reader works.
4. `gateway.policy_scope` — explicitly bound nft chain is readable/normalizable within the supported subset.

It does **not** evaluate attached access policies, service reachability, Internet health, remote management or whole-ruleset override completeness.

`verify vpn` evaluates exactly:

1. `vpn.binding` — bound namespace/interface/address.
2. `vpn.peer_binding` — exact registered WireGuard peer and allowed destination.
3. `vpn.session_freshness` — nonzero authenticated session timestamp within180s, not a forced-new-handshake claim.
4. `vpn.route_ownership` — registered target's scoped route belongs to the bound VPN.

It adds `vpn.path_selection` ONLY when declared required, and `vpn.fail_closed_guard` ONLY when declared required. Those properties cannot be silently removed when unsupported. Unknown effective-policy coverage means UNVERIFIED. No all-peer/all-endpoint, attached-access-policy or universal-health promise follows from a passing VPN assessment.

## Evidence and limitations

Adapters normalize facts, never verdicts. Forwarding permission, actual path selection and enforcement guards remain distinct. Silence, a counter delta, a client label or one plausible native chain cannot prove isolation.

Native nft reads target registered family/table/chain bindings only; no global ruleset dump. Unknown/shared namespace override coverage stays UNVERIFIED. This first slice does not provide a production CLI switch for claiming a closed policy universe. Complete closure in the real isolated integration comes only from its private synthetic fixture coordinator and is explicitly test-only provenance. **Passing that fixture does not certify a customer network.**

DNS validation binds transaction, question, source, transport and complete bounded response; filtering requires a validated binary policy EDE, not NXDOMAIN alone. Protected-path monitors are kernel-filtered L3 sockets (no Ethernet/MAC/promiscuous capture or raw persistence), filter-installed before activation and ready before the challenge. Normal data must match the exact random DNS question as well as the bound address pair/protocol/port. Fragment/split-query uncertainty copies only one payloadless version byte and makes coverage incomplete; it never silently proves absence. CLOEXEC descriptors, final kernel drop accounting and bounded closure prevent inherited/leftover collectors. The native collector accepts one source/endpoint/realm/family/port and at most one probe per transport; richer/repeated scopes stay UNVERIFIED instead of sharing hit attribution. Each positive control has a separate challenge from the protected attempt. Current observer support is IPv4; requested unsupported IPv6/mediated scope stays UNVERIFIED. A special local challenge does not certify arbitrary DNS upstream/proxy selection.

Operations have a100s total bound, short subcommand/socket deadlines and explicit cleanup. No background collector, auto-rearm or permission escalation. Failed controls/coverage or missing evidence remain UNVERIFIED; attributable contradictory observations (including an actual protected-query leak) are VIOLATED. Contradiction outranks simultaneous missing facts. Cleanup failure is an operational error, never clean success.

Outputs are readable JSON (`--json` is accepted explicitly), with friendly source/target/registered-VPN labels, immutable refs, execution-grant ID and identical scope/assurance. Facts retain actual probe and observer windows; historical-baseline reuse preserves its original times and assessment reference. Exit0 VERIFIED;1 VIOLATED;2 UNVERIFIED;3 invalid request / operational failure. Immutable local assessment files are not legacy signed receipts or tamper-proof attestations. Resolved assessments have30day retention; unresolved cleanup records are retained.

## Verification gate

```sh
go test ./...
go test -race ./internal/netpolicy ./cmd/21pins
go vet ./...
# Only on an authorized isolated Linux runner with ip/nft/wg and namespace capabilities:
go test -tags=netpolicy_integration ./internal/netpolicy -run TestLinuxWGDNSE2E -count=1 -v -timeout=100s
```

The real integration uses fresh owned namespaces, synthetic keys/identities, a native WireGuard pair, nft guards, UDP/TCP DNS servers and actual source-bound observers. It exercises metadata import→discovery/inspection→offline request→existing-grant admission→real allow/isolation→receipt, then a real leak, unsupported coverage/tool and broken positive control/service. All fixture namespaces, keys, sockets and temporary records are removed. Missing prerequisites/SKIP are **not** a passing integration gate.
