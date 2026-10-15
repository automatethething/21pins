# Generic Network Policy / Linux–WireGuard–DNS First Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (single writer) or superpowers:subagent-driven-development only when separately authorized. Steps use checkbox syntax. **Owner APPROVED execution with the two clarifications below. One writer; real isolated Linux/WireGuard/DNS integration remains the completion gate.**

**Status:** Independent fresh-context review APPROVED in round2; [review record](../reviews/2026-10-14-network-policy-first-slice-plan-review.md). Owner execution approval GRANTED with bounded disclosure/profile clarifications before Task1.

**Goal:** Establish the generic product contracts, then exercise one registered Linux/WireGuard protected DNS allow/deny path with minimal discover/inspect/verify commands.

**Architecture:** One new `internal/netpolicy` package owns immutable references, disjoint desired-policy scopes, normalized facts and pure verdicts. Concrete Linux/WireGuard and DNS collectors supply facts, not decisions. Separate network metadata/assessment files and early CLI dispatch leave the existing LLM proxy, grants, legacy receipts and native SSH contracts unchanged.

**Tech Stack:** Existing Go1.24+ / standard library, existing seven-pin evaluation/native identity helpers, existing native Linux `ip`/`nft`/`wg` read mechanisms when authorized. No new dependencies, daemon, database, controller, plugin SDK or privilege bootstrap.

**Spec:** `docs/superpowers/specs/2026-10-14-network-policy-verification-design.md` (owner-approved for planning, contextual privacy clarified).

---

## Scope and fixed decisions

Build these eight steps in order, not parallel platform work. First release supports DNS/direct access, explicit IPv4/IPv6 and UDP/TCP tuple coverage ONLY where actually evidenced. Mediated/proxy DNS scope can be declared but returns UNVERIFIED until supported; it must not be silently dropped. Do not implement general SSH/web/arbitrary-UDP probes yet.

Next increment: OpenWrt/GL.iNet adapters using existing dogfood lessons and **sanitized** fixtures, without changing the generic core into UCI/mark-specific types. Subsequent increment: Tailscale device/tailnet/ACL cross-model validation. No UniFi, OPNsense, MikroTik, OpenVPN, plugin SDK or public infrastructure-specific commands in this plan.

### Files / seams (planned; create none until approval)

| Files | Responsibility |
|---|---|
| `internal/netpolicy/types.go`, `registry.go`, `registry_test.go` | Typed objects/revisions, alias resolution, explicit import, hardened separate persistence. |
| `internal/netpolicy/policy.go`, `policy_test.go` | Canonical tuple resolution, non-overlap checks, exact observation request/digest. |
| `internal/netpolicy/evidence.go`, `evidence_test.go` | Capability/fact provenance, privacy projection and freshness/binding validation. |
| `internal/netpolicy/verify.go`, `verify_test.go` | Pure verdict aggregation and separate assessment receipts. |
| `internal/netpolicy/discover.go`, `discover_test.go` | Bounded candidate suggestions, zero scan/login/register/probe. |
| `internal/netpolicy/linuxwg.go`, `linuxwg_test.go` | Concrete fixed-argv Linux/WireGuard reader + supported native-policy normalization. |
| `internal/netpolicy/dns.go`, `dns_test.go` | Bounded DNS response/challenge/observer orchestration; no service administration. |
| `internal/netpolicy/authorize.go`, `authorize_test.go` | Narrow read-only existing-grant projection + existing evaluation/native subject helpers; no new grant semantics. |
| `cmd/21pins/network.go`, `network_test.go`; small edit `main.go` | Minimal new command dispatch/formatting; preserve old paths. |
| `internal/netpolicy/integration_linux_test.go`, `testdata/network/*.json` | Synthetic isolated real Linux fixture and generic normalized evidence fixtures. |
| `docs/network-verification.md`, `README.md` | Proposed-to-shipped distinction, limitations, opt-in setup and examples. |

Keep tests near each seam; no framework or generalized adapter/plugin SDK. Native parsers may be split only if needed for readability, not speculative future vendors.

## Shared contracts to pin in tests

- `Ref{ID, BindingRevision}` is immutable identity; aliases are separate. Binding changes increment revision and invalidate old requests/evidence; replacement gets a new ID even if alias reused. Alias-only rename does not redirect or reauthorize an old request.
- Kinds: `network_gateway`, `network`, `vpn`, `service`; network `policy` and immutable assessment records are separate from existing `internal/policy.Grant` / `Receipt`. VPN implementation labels are adapter data.
- Canonical `Tuple{SourceRef, EndpointRef, RealmRef, Family, Transport, Port, AccessMode}`; finite selectors only. Path requirements/decision do not make otherwise overlapping scopes disjoint. Canonicalize aliases/native bindings before overlap checking; ambiguity is UNVERIFIED.
- `Capability{Operation, Support, Scope, Missing}` uses supported/partial/unsupported/unknown. `Fact{Kind, Scope, Revisions, ObservedAt, ValidUntil, Provenance, Coverage}` keeps forwarding permission, path selection and enforcement guard DISTINCT.
- `Assessment{Verdict, RequiredProperties, PolicyRefs, ObjectRefs, TupleCoverage, EvidenceRefs, ObservationWindows, Assurance, Missing, Cleanup}`. Adapter output cannot set the verdict or self-upgrade imported/operator-attested data to runtime-validated.
- `Evaluate(intent, evidence, now)` has no I/O. Contradictory attributable fact => VIOLATED; otherwise missing/stale/unsupported required property => UNVERIFIED; only full passing coverage => VERIFIED. Invalid CLI syntax is operational error, not a network-policy violation.

### Minimal onboarding and execution authority

Add ONE explicit `21pins registry import FILE` local metadata operation so operators need not hand-edit state. It validates the full finite manifest before atomically applying it; it does not contact/enroll/configure any host, import credentials or authorize reads/probes. Native source/channel bindings are explicit; discovery only proposes candidates. PUBLIC DISCLOSURE IS SUPPRESSED IN THIS SLICE. There is no confirmation command, persisted approval bit, import field or reachable operator-confirmed state. All endpoint display stays suppressed, including intentionally public endpoints, until a separately designed local confirmation mechanism binds immutable object ID + binding revision + exact endpoint, invalidates on substitution/rebind and never declassifies adjacent/customer/home topology. DNS, reachability and discovery cannot confirm it. Reject disclosure/confirmation fields in imports rather than accepting inert or forgeable approvals.

Before actual native reads/probes, require an existing active execution grant bound to the resolved immutable observation request. Use existing `policy.EvaluateAction` unchanged with capabilities `network.read` / `network.probe`, data class `network-metadata`, cost0 and the exact request digest as target. Resolve subject using existing authenticated native `ck whoami` path (`identity.ResolveSubject` with no arbitrary explicit `--sub`); no automatic login or new identity system. A declared reachability policy, binary presence, `--from`, imported observation or invoking discovery is NOT permission.

`authorize.go` implements `ReadGrantProjection(path, grantID) (policy.Grant, error)` as a concrete read-only reader, NOT `store.New` or a subprocess calling normal grant CLI. Open the existing `config.StatePath()` regular file read-only, reject symlinks/unsafe modes and verify pre-open versus opened-file identity; cap input at16MiB, decode into a DTO containing ONLY `Grants []policy.Grant`, select the requested record and return only that grant. Physical JSON bytes necessarily pass through the local decoder; unknown provider/signing fields are skipped, never materialized as provider/signing objects, used, logged, returned or persisted. Do not promise that a shared JSON file can be read without its encoded bytes passing through local memory. Missing/oversize/malformed files fail closed with sanitized codes; no mkdir/init/migration/chmod/write. Tests use sensitive-field sentinels and wrong-shaped ignored values to prove no secret decode/use/export and byte/mode equality before/after. Re-evaluate revocation/expiry/subject/request before each operation. Use normal existing native OS/host command enforcement as well: the local evaluation is additional admission, not an unbypassable sandbox. If identity, grant or native read channel is missing, return UNVERIFIED with the smallest missing prerequisite—no broader SSH/sudo grant or remote shell fallback.

Expose an offline `verify ... --request` form that resolves registered metadata and emits only the opaque target digest, requested capability, object revisions and bounded scope needed to issue an existing grant. No native read/probe occurs. The digest includes source/service/gateway/VPN bindings, all policy revisions, requested properties and operation, not aliases or the later random nonce. Actual execution takes `--grant ID`. Read-only inspection/discovery needs no grant when using registry metadata ONLY; requesting live native data must pass admission.

### Finite first-slice verification profiles (no universal health claim)

`verify gateway` requires EXACTLY `gateway.binding`, `gateway.interface_binding`, `gateway.reader`, `gateway.policy_scope`. These mean: exact registered local network-namespace identity; assigned address/interface matching the registered binding; admitted fixed native reader succeeds; explicitly bound nft family/table/chain is readable and normalizable within the supported subset. No service reachability, attached policy compliance, remote management, general Internet health or global override coverage is asserted. Missing bindings/evidence return UNVERIFIED, not inferred success.

`verify vpn` requires EXACTLY `vpn.binding`, `vpn.peer_binding`, `vpn.session_freshness`, `vpn.route_ownership`. These mean: registered namespace/interface/address observed; exact registered WireGuard peer plus allowed-destination binding; a nonzero authenticated session timestamp within180s (no forced new handshake); declared target's source-bound route owned by the registered VPN. Add ONLY `vpn.path_selection` when the binding explicitly requires selected-path evidence, and `vpn.fail_closed_guard` when it explicitly requires fail-closed evidence. Those requirements cannot be dropped when unsupported. Guard/selection facts require applicable scope and adequate override coverage; unknown shared namespace closure remains UNVERIFIED. Other protocols, all peers, all endpoints, attached access/isolation policies and universal network health are excluded.

Pin exact property-set equality in unit and CLI tests, including optional requirements, unsupported/missing facts, binding substitution and unrelated access-policy leaks. Extra unrequested facts must not silently expand the claim. Receipts enumerate evaluated properties and explicit exclusions.

## Task 1 — Immutable registry and friendly aliases

**Files:** `types.go`, `registry.go`, `registry_test.go`.

- [ ] Write failing `TestRegistryBindings` / `TestRegistryAtomicFailure`: create/resolve/rename, alias collision, alias reuse, rebinding revision, canonical duplicates, hostile names, unknown fields, replacement invalidates prior refs, failed save preserves old bytes.
- [ ] Run `go test ./internal/netpolicy -run 'TestRegistry' -count=1`; expect RED before implementation.
- [ ] Implement a small typed registry, `Create/Resolve/Rename/Rebind/Import`, with JSON schema version1. IDs use `crypto/rand` (existing `policy.NewID` is reusable). Store `network-state.json` in the existing config directory, separate from provider state; `0700` directory/`0600` files, symlink refusal, temp+fsync+atomic replace and process-level lock. Concurrent writer must serialize/reload or fail explicitly, not lose updates. No credential fields or arbitrary native argv in imports.
- [ ] Re-run the focused test; require PASS and unchanged provider-state sentinel. Commit only these files.

## Task 2 — Policy/access resolution and admission request

**Files:** `policy.go`, `policy_test.go`, `authorize.go`, `authorize_test.go`.

- [ ] Write table tests for disjoint rules, overlapping same/opposite decisions, aliases to same endpoint/realm, wrong source, no declaration, tuple holes, scope-family/mode mismatch, conflicting imported data, alias rename vs binding substitution. Add admission cases: revoked/expired/wrong-target/wrong-subject grant, zero-cost without capability, unsafe state, missing native identity; no native call on failure.
- [ ] Run `go test ./internal/netpolicy -run 'TestPolicy|TestAdmission' -count=1`; expect RED.
- [ ] Implement finite tuple expansion/resolution exactly as spec§6, one revision per requested tuple and all revisions bound. Missing/unresolved intent yields UNVERIFIED; malformed imports rejected. Implement fixed request digest and concrete `ReadGrantProjection`/admission as specified above, with injected read/identity runners in tests; reuse existing evaluation/identity functions, do not modify their schemas/semantics. Do not add an approval server, credentials or new SSH authority.
- [ ] PASS focused tests; demonstrate provider/grant/signing/legacy receipt bytes remain unchanged. Commit.

## Task 3 — Normalized capabilities, evidence and contextual privacy

**Files:** `evidence.go`, `evidence_test.go`.

- [ ] Write `TestEvidenceBindingAndPrivacy` covering unknown/partial support, stale evidence, revision/endpoint/source substitution, native vs operator/import provenance, and separate forwarding/path/guard facts. Include an inspection-disclosure matrix: public endpoint display is suppressed in this slice (no confirmation mechanism exists); customer/home WAN, private/internal/tailnet, unknown classification, adjacent topology, credentials/keys/tokens remain protected—even under `--details` or a forged public flag. Discovery, telemetry and bulk output do not inherit the display exception.
- [ ] Run `go test ./internal/netpolicy -run 'TestEvidence' -count=1`; expect RED.
- [ ] Implement small fact/capability structs, exact scope/freshness checks and purpose-aware output projection. Default evidence lifetime10min, shortened by native/session/grant expiry; reuse only while object/policy/runtime binding still matches. Preserve actual earlier observation windows, never rewrite them as a fresh probe. Unknown or overriding native semantics prevents complete coverage.
- [ ] PASS; errors contain only allowlisted codes/refs, not native stderr, addresses or raw config. Commit.

## Task 4 — Pure verdict engine and assessment receipts

**Files:** `verify.go`, `verify_test.go`.

- [ ] Write `TestEvaluate`: complete allow; intentional deny via active effective source-policy+guard+differential observations WITHOUT counter; attributable matched deny alternative; forwarding-only/timeout/absence/aggregate counters insufficient; unsupported/stale/partial/other-family/proxy gaps UNVERIFIED; genuine leak VIOLATED; contradiction outranks simultaneous missing facts; cleanup failure cannot cleanly pass. Operator-attested accepted evidence retains that assurance label, never runtime-validated.
- [ ] Run `go test ./internal/netpolicy -run 'TestEvaluate|TestAssessmentReceipt' -count=1`; expect RED.
- [ ] Implement pure evaluation and tuple aggregation. Write immutable create-once `network-receipts/<randomID>.json`, minimal normalized refs/outcomes/provenance/times, no packet bodies/raw logs. These are local assessment records, NOT existing signed `policy.Receipt` or proof of tamper resistance. Retain resolved receipts30days; do not auto-prune unresolved cleanup records. No legacy receipt mutation, signing-key creation or daemon.
- [ ] PASS; receipt save failure is explicit operational error and cannot report a successful persisted assessment. Commit.

## Task 5 — Passive bounded discovery

**Files:** `discover.go`, `discover_test.go`.

- [ ] Write `TestDiscoverIsPassive` with a recording runner: enumerate bounded registered metadata and detect local executable presence; zero process executions, packets, login, credentials, scans, state writes or automatic registration. Duplicate suggestions have deterministic suffixes and unverified candidate status.
- [ ] Run `go test ./internal/netpolicy -run 'TestDiscover' -count=1`; expect RED.
- [ ] Implement candidate suggestions only. First slice reads registered objects and allowlisted executable-presence metadata (`ip`/`wg`) without invoking clients or reading VPN configs/private keys; missing metadata gives partial suggestions, not a guessed topology. Cap result count at64; do not enumerate all devices/interfaces. Any future live discovery capability still needs its own read authority.
- [ ] PASS; source/target privacy matrix and preexisting registry byte equality hold. Commit.

## Task 6 — Generic Linux + WireGuard read-only facts

**Files:** `linuxwg.go`, `linuxwg_test.go`, `testdata/network/linux-*.json`.

- [ ] Write synthetic parser/runner tests for source binding, protected endpoint route, WireGuard peer/session/path freshness, rule ordering and alternate-route/mark coverage. Include missing tools/rights, unsupported native expressions, empty output and scoped-peer mismatch. Unknown normalization must be UNVERIFIED, not a wildcard supported capability.
- [ ] Run `go test ./internal/netpolicy -run 'TestLinux|TestWireGuard' -count=1`; expect RED.
- [ ] Implement concrete allowlisted fixed-argv local Linux reads after admission. Register exact nftables family/table/chain bindings and query those chains directly; NEVER dump the global ruleset to discover relevance. Supported syntax within those bindings: exact source/interface/destination selectors and simple mark/drop/reject guards; separately normalize approved RPDB priority/source/interface/mark selectors and bound route lookup. A bounded chain read proves only facts within that chain, NOT absence of other hooks/rules/overrides. Any effective-policy claim requiring unknown/whole-ruleset override coverage is UNVERIFIED. The runtime end-to-end fixture uses a freshly created, exclusively controlled isolated namespace with its entire tiny policy graph explicitly bound; its closure is fixture-coordinator provenance, not a transferable claim about shared customer namespaces. Do not build a general hook/ruleset inventory system in this slice. Parse/filter native data locally before returning facts. Query only the registered interface/peer/target; NEVER use `wg show ... dump`, read private-key configs, dump unrelated logs or print raw native output. Use named `wg show <bound-interface> latest-handshakes|transfer|allowed-ips` fields, filtering to the pinned peer before normalization. Record a recent session as such, not a fabricated new handshake.
- [ ] No new remote execution transport: use local native rights only in this slice; preexisting remote narrow channels may be identified but unsupported ones return UNVERIFIED. No automatic sudo, SSH, route/firewall change or trust installation. No UCI/GL.iNet fields in generic structs. Add a shared/unknown-namespace test proving that plausible bound chains plus silence do NOT produce a complete effective-policy witness; separately test fixture-scoped closure cannot upgrade production evidence. PASS tests and commit.

## Task 7 — DNS access/isolation and bounded observation

**Files:** `dns.go`, `dns_test.go` and synthetic DNS fixtures.

- [ ] Write `TestDNS`: valid UDP/TCP responses/control parity, transaction/question/length/status mismatch, explicit policy-EDE when filtering is required, NXDOMAIN/timeout/send-only insufficiency, missing same-endpoint positive baseline, wrong source/nonce/windows, leak, special/local-cached challenge limitations, observer cleanup/crash. Imported client JSON cannot assert that a boundary was validated.
- [ ] Run `go test ./internal/netpolicy -run 'TestDNS' -count=1`; expect RED.
- [ ] Port ONLY reusable DNS wire validation/synchronization algorithms from existing proof scripts; do not invoke/import deployment-specific wrappers, manifests, selectors or installed role commands. Implement local Linux source-bound probes and protected-path observers in the registered context; missing authorized vantage remains UNVERIFIED. Need no public/home WAN discovery or unrelated traffic. Prefer UDP socket/protocol metadata; where capture is required use a kernel-filtered network-layer collector for exact synthetic source/destination/protocol/nonce, never Ethernet/MAC collection or raw packet persistence.
- [ ] Gate challenge emission on actual observer readiness and supported clock/coverage checks; whole operation≤100s including≤15s cleanup (all subcommands bounded). No retry/rearm daemon. Positive source baseline and denied source attempt can be separate authorized invocations within the applicable freshness/binding window; persist normalized earlier evidence only and combine transparently. Source switching is operator-controlled, never automatic. Deny readiness/coverage/source/causality gaps are UNVERIFIED, not permission to repeat full suites.
- [ ] PASS unit checks; guarantee observer/temporary-data cleanup on success/error/cancellation. Commit.

## Task 8 — Minimal CLI and isolated end-to-end gate

**Files:** `cmd/21pins/network.go`, `network_test.go`, small `main.go` dispatch; `integration_linux_test.go`; `docs/network-verification.md`, README.

- [ ] Write CLI contract tests first. Dispatch `registry`, `discover`, `inspect`, `verify` BEFORE `store.New` in `main.go`, preserving every legacy branch. Pure metadata commands must not initialize provider state. Live operations open only the admitted grant projection. Assert legacy SSH/LLM/grant/receipt behavior unchanged and private output projection holds for all new commands.
- [ ] Implement only:

```text
21pins registry import FILE
21pins discover
21pins inspect gateway|network|vpn|service|policy NAME [--details]
21pins inspect wireguard NAME
21pins verify gateway|vpn NAME --grant ID
21pins verify access SERVICE --from NETWORK --grant ID
21pins verify isolation NETWORK SERVICE --grant ID
# Any verify form supports offline --request instead of execution.
```

  ALL `inspect` forms, including `--details` and the WireGuard expert view, are registry/cached-capability inspection ONLY in this slice, with original observation times visible; they perform no native process/network read. Live reads belong exclusively to admitted `verify` operations. `vpn` is canonical; WireGuard is an expert view of the same object, mismatch is an error. Tailscale expert inspection reports unsupported in this slice, not fabricated WireGuard-like data. Resolve `--from`/current context from actual binding; a flag is not membership proof. Without adequate local read/probe authority/vantage return UNVERIFIED. Gateway/VPN checks never imply all attached policies pass. Human + `--json` outputs have identical scope, assurance and missing facts; exit0 VERIFIED,1 VIOLATED,2 UNVERIFIED,3 request/operational error.

- [ ] Run `go test ./cmd/21pins -run TestNetwork -count=1` (initial RED, then PASS); add a real isolated Linux namespace fixture with synthetic keys/resources, DNS responders, trusted/guest sources, protected WireGuard path, simple supported effective policy/guard and source-bound observers. The fixture coordinator binds the entire fresh namespace graph and records controlled/synthetic closure; that provenance is accepted ONLY for the test namespace, never shared production namespaces. Prove metadata import→discover/inspect→request/admitted verify→receipt for both allowed and isolated cases; inject a real leak for VIOLATED and remove witness/tool/permission for UNVERIFIED. No existing host interface, sysctl, firewall, VPN, credentials or production data may change; cleanup every fixture resource.
- [ ] Run `go test -tags=netpolicy_integration ./internal/netpolicy -run TestLinuxWGDNSE2E -count=1` only on an already-authorized isolated Linux runner with required tools/CAP_NET_ADMIN. Missing prerequisites must clearly SKIP and cannot count as the release gate passing. A fixture receipt is labeled synthetic/test; never claim it verified a real customer network.
- [ ] Final gate: `go test ./...`, `go test -race ./internal/netpolicy ./cmd/21pins`, `go vet ./...`, Linux end-to-end PASS with observed cleanup, `git diff --check`. Confirm no existing provider/grant/receipt/SSH contract or owned infrastructure changed. Publish no support claim before the real isolated gate passes. Commit only slice files/docs; preserve unrelated website edits.

## Review / owner handoff

The implementation can be done as eight small commits under one writer, with the generic contracts complete before native collection. Independent plan reviewer checks this plan against the owner-amended spec, especially scope, privacy, admission and effective-policy gaps. Fix blocking findings and rerun review (max three rounds). Owner has now approved execution with the two bounded clarifications above; proceed through all eight tasks under one writer. Do not change existing infrastructure/trust or add later adapters. Only passing real isolated Linux/WireGuard/DNS integration plus regression gates counts as completion.
