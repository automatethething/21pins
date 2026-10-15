# OpenWrt / GL.iNet Read-Only Gateway Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans task-by-task, one writer. Steps use checkbox (`- [ ]`) tracking. This document authorizes **no implementation** until owner approval.

**Goal:** Validate the accepted generic gateway contracts with a small, bounded OpenWrt reader/normalizer; GL.iNet is a capability/version-specific extension of OpenWrt, never a public object model.

**Architecture:** Add one private platform-evidence seam behind the existing admitted local collector. A pure normalizer distinguishes observed runtime, stored intent and unknown coverage, returning scoped facts/capabilities—not verdicts. Keep public objects, finite gateway/VPN profiles, policy/access questions, execution-grant evaluation, native SSH, LLM proxy and legacy receipts unchanged.

**Tech Stack:** Existing Go1.24/stdlib, `internal/netpolicy`, bounded local Linux reads; synthetic fixture tests. No dependency, SDK, daemon, remote transport or new privilege.

**Status:** Independently APPROVED round3 — [review record](../reviews/2026-10-15-openwrt-gateway-plan-review.md). Owner implementation approval GRANTED for all four tasks under one writer. Work in progress; live/private-device access remains separately unauthorized. Baseline `a4885e0` remains accepted.

---

## 1. Product gate and scope

[CLI product smoke](../reviews/2026-10-15-network-cli-product-smoke.md): **no blocking product-model issue**. All requested commands and three verdict presentations were exercised using synthetic state only. The default JSON, generic errors, opaque refs and engineer-facing labels need a later bounded human-presentation pass before mass-market launch, not a schema/object redesign. This plan does not silently implement that UX work.

**Recommended minimum:** one local OpenWrt evidence adapter, fw4/nft supported-subset firewall normalization, and GL.iNet routing-policy extensions where exact runtime semantics are supported. Logical bindings, RPDB selection and stored/runtime separation can still be partial on other firmware. **Legacy fw3/iptables firewall evidence is explicitly unsupported in this small step**; no all-OpenWrt/all-GL.iNet claim. Capability selection depends on actual runtime shape/backend, not a version string or brand.

Alternatives rejected: a separate GL.iNet object/CLI (duplicates the model); a universal fw3/fw4/vendor/plugin framework (too large). A later firmware/backend slice requires its own bounded plan. Tailscale and all other vendors/protocol adapters remain deferred until the owner accepts this gateway cross-model validation.

No current device inspection, credentials, installation, configuration changes, probes, private snapshot import or product implementation is authorized now. Future private dogfood is a separate, explicitly bounded use of existing access; it does not create transport/trust authority or product fixture data.

## 2. Facts and non-equivalences

Always preserve:

```text
forwarding_permission != path_selection != enforcement_guard
stored_configuration != active_runtime
registered_source_label != observed_source_membership
route_lookup_result != observed_packet_path
```

Normalize the following independently, with exact source/service/family/transport/realm/revision and actual observation windows:

| Area | Minimum accepted evidence | Must remain partial/unknown when |
| --- | --- | --- |
| Logical network/source binding | Bound logical network's live status, resolved ingress device and registered native binding agree. | Subnet inclusion/name/config only; no real client-origin witness. Never turn the router's own address into proof of a client source. |
| Effective route-policy selection | Actual applicable RPDB selectors/order/masks plus source-bound kernel lookup for the registered destination and ingress/observed mark agree. | Mark supplied merely to force a desired lookup; ambiguous earlier rules, NAT/rewrite, missing source context or selectors. |
| Destination-set binding | Exact family/table/set identity and live membership of the requested destination; correlated to the active classifier. | Set name appears in config but live set/membership/scope unknown. Never export all elements. |
| Forwarding permission | Relevant active forward-chain rule path supports that finite tuple. | UCI zone forwarding alone, unknown earlier verdict/jump/override, or fw3 backend. Permission is not route choice or leak protection. |
| Path selection | Distinguish prospective effective FIB selection from actual path observation. Existing `path.selection` access proof still requires its existing correlated observation. | Static default/main route, counter delta, prospective lookup or a configured tunnel alone. |
| Enforcement / leak guard | Active source/destination-scoped drop/reject/blackhole or exclusion plus supported precedence/override coverage. | UI/UCI kill-switch bit, silence or an isolated plausible chain. Unknown coverage must not produce a complete guard fact. |
| Active vs stored | Distinct provenance and digests for observed active state and selected stored values. | Stored-enabled/disabled bits are treated as enforcement or overwrite observed state. Drift is explicit, never repaired. |
| Precedence / override coverage | All relevant supported selector paths within the admitted bounded graph accounted for. | Unread hook/table/chain/extension, unsupported expression, flow offload, priority/mask conflict or snapshot change. |

Adapters never emit VERIFIED/VIOLATED. The existing evaluator alone classifies the question. Match existing property meanings exactly; otherwise retain a separately named intermediate native fact/partial capability, not a falsely equivalent generic fact.

**Important ceiling:** This plan does not solve global production netfilter closure. Bound chains, firmware identity, UCI settings and imported assertions cannot prove absence of other overrides. Production guard/isolation requirements stay UNVERIFIED where coverage is unknown. Reuse the private synthetic coordinator's closed-universe proof only in its owned test namespace; no public `closed`/`trusted` flag, imported seal or new attestation authority.

## 3. Small code footprint / binding seam

Create only:

- `internal/netpolicy/openwrt.go` — small typed snapshot, provenance/coverage outcomes, pure normalization.
- `internal/netpolicy/openwrt_read.go` — fixed read forms and local admitted collection.
- `internal/netpolicy/openwrt_test.go` — synthetic fixture builder/table tests and integration assertions.

Modify narrowly:

- `types.go`, `registry.go`, `question.go` — optional `openwrt` binding selectors and their validation/digest inclusion.
- `linuxwg.go` — private gateway-evidence dispatch/native tool allowlist, preserving the default Linux path.
- Existing integration test and `docs/network-verification.md`; no other product surface unless an existing matching property requires the same private helper.

Proposed selector DTO is private/native binding metadata, NOT a new object:

```go
// Omitted pointer keeps existing JSON/digests unchanged.
// Names are bounded native identifiers, not paths or command text.
type OpenWrtBinding struct {
    LogicalNetwork string             `json:"logical_network,omitempty"`
    Profile        string             `json:"profile,omitempty"` // reader hint, never support/closure proof
    Chains         []BoundChain       `json:"chains,omitempty"`  // exact family/table/chain; max8
    DestinationSet *BoundSet           `json:"destination_set,omitempty"`
    StoredSections []string           `json:"stored_sections,omitempty"` // exact named firewall sections; max8
}
type BoundChain struct {
    Family string `json:"family"` // ip | ip6 | inet
    Table string `json:"table"`
    Chain string `json:"chain"`
    Role string `json:"role"` // classifier | forwarding | guard
    Hook string `json:"hook,omitempty"` // empty for regular chain; prerouting | forward | output
    Priority *int32 `json:"priority,omitempty"` // required iff Hook nonempty; zero is meaningful
}
type BoundSet struct {
    Family string `json:"family"`
    Table string `json:"table"`
    Name string `json:"name"`
    ElementFamily string `json:"element_family"` // ipv4 | ipv6
}
```

**Ownership/freeze:** deep-copy the optional pointer, chain/section slices, every priority pointer and destination-set pointer before validation/canonicalization/storage or constructing an admitted question. Return independent deep copies from registry/inspection APIs. Reads use only the frozen admitted question, never caller-owned mutable objects. Canonicalization sorts owned copies, never mutates caller slices. Add a regression that mutates both input and returned DTOs after validation: persisted selector scope, computed digest, native argv and evidence binding must remain unchanged.

**DTO validation:** table/chain/set/logical/section names use `^[A-Za-z_][A-Za-z0-9_]{0,47}$`; profiles are a fixed implementation enum (unknown profile => unsupported, never guessed). Profiles are exactly `fw4-basic` and `gl-policy-fw4` reader hints (empty/other values cannot grant support); observed runtime must corroborate the selected subset. No duplicate family/table/chain identity, even with another role. At most8 chains total and at most1 destination set; selector sets are canonicalized before hashing so order is not authority. Hook/priority are expected binding constraints, corroborated by native chain metadata, not closure assertions. `classifier` accepts prerouting/output or a bound regular chain; forwarding accepts forward/regular; guard accepts only a modeled hook/regular path. Network objects may carry only `LogicalNetwork`; gateway refs tie them to the gateway selectors. Empty lists mean missing capability, never wildcard/all-chain collection.

Families must agree with the question and live set type: `ip`→ipv4, `ip6`→ipv6; `inet` requires an explicit element family. This first profile executes IPv4 only; requested IPv6 remains unsupported without shrinking scope. First supported sets are scalar `ipv4_addr`, exact one-target membership; interval/concatenated/map/dynamic types are unknown. Known nonmembership requires a supported unambiguous native result; missing set, permission/tool error or ambiguous exit is UNKNOWN, not `not_member`. Identity includes family/table/name/type plus the selected membership observation; no export of all elements.

Add optional `OpenWrt *OpenWrtBinding` to existing binding. Gateway owns reader scopes; the selected source network can carry only its logical-network name, tied to its existing gateway ref. Keep source-client namespace/context/address distinct from router namespace/context. Validate kind-appropriate fields, bounds and native identifiers; reject arbitrary argv/paths/unknown disclosure or closure fields. No authoritative support flag.

The new selectors participate in the existing metadata/request digest and revision rules. Existing bindings with the optional field omitted retain old encoded bytes/digests. Rebinding, native source/device changes or observed runtime digest changes invalidate affected evidence; friendly rename remains identity-neutral. No second registry/state store or provider/signing objects.

### Finite classifier / mark contract (no general nft interpreter)

For the selected IPv4 source/destination only, accept a conjunction of: exact source address (`/32` is equivalent), `iifname ==` the corroborated ingress device, and exact destination address OR membership in the bound scalar set. No duplicate/conflicting selector, OR/negation/range or implicit wildcard source. Proven nonmatching rules are irrelevant; unsupported potentially applicable rules make classifier/precedence coverage unknown.

Accepted action is `meta mark set <uint32 constant>` (optional counter/comment only). Rule order is semantic: evaluate applicable rules in order; a later supported full assignment overwrites the earlier mark. Full assignment establishes all32 bits; never assume incoming mark0. RPDB mark/mask comparison is `(mark & mask) == (rule_mark & mask)`, with explicit native priority and source/ingress selectors; earlier possibly applicable unsupported selectors prevent attribution. Only this derived, fully known mark may parameterize the kernel route lookup. Missing assignment, masked read/modify/write, ct-mark restore/copy, verdict/map lookup, dynamic expression, NAT, conntrack-dependent action or offload => UNKNOWN for mark-dependent evidence. These are deliberate first-profile limits, including on GL.iNet firmware.

**Active reachability prerequisite:** every role-relevant regular chain must have a currently installed, bounded modeled call path from a selected compatible active base hook, with native hook/family/type/priority matching the binding and each call condition evaluated for the requested tuple. A registered/installed but uncalled chain supplies no effective mark, forwarding or guard evidence. Missing caller/unknown edge/unreachable chain => partial/unknown. Forwarded client classification requires prerouting (not router-output); forwarding requires forward. Output-hook evidence is only for an independently established router-origin question and cannot stand in for a client source.

Bound regular-chain calls support only a single explicit `jump` to another bound chain with the same finite selectors (or an unconditional call), followed by normal return to the next caller rule. Unconditional regular-chain `return` and end-of-chain return are supported. Max depth4, acyclic graph; goto, unbound call, ambiguous conditional return and unsupported verdict paths => unknown. First applicable drop/reject ends that modeled packet path. Accept ends its chain/hook path only, **not later base hooks**. Hook ordering/priority and all potentially overriding paths must be accounted for; otherwise retain the candidate mark/guard as partial and do not emit complete effective evidence. Synthetic closure never upgrades production coverage.

Correlation binds current source/service refs, logical→ingress mapping, exact set membership, ordered classifier graph, RPDB rows and before/after runtime digest. A configured policy name, matching mark literal or desired route table alone is not correlation. Unit tests must pin each accepted form and one unknown case for each rejected category above.

## 4. Collection boundary

Use current `network.read`, `network-metadata`, exact request targets and actor/grant checks. Revalidate before **each** native operation; enter the verified opened namespace FD as today. No sudo, SSH, HTTP login, ubus-over-network, host enroll, role/force-command changes, credential import or arbitrary helper.

Fixed bounded local forms (validate installed syntax during implementation; unavailable form => unsupported):

- `ubus call network.interface.<bound-name> status`, never `network.interface dump` or global ubus object enumeration. Keep only live logical/device/address/route fields needed for this question.
- `uci -q get` of explicitly named non-secret network/device and firewall src/dest/enabled selectors only. No `uci show/export`, wireless credentials, VPN private-key/profile configs or recursive config reads. Stored values are intent only.
- One-family RPDB **metadata** read within the bound router namespace, capped64 rows/64KiB, locally projected to potentially applicable priority/source/ingress/mark-mask/table/terminal selectors for the exact source/destination. This narrowly necessary precedence read is not permission for route-table/interface/network inventory. If a bounded representation cannot establish relevance/order, return unknown rather than silently truncate/filter away an override.
- Existing fixed source-bound `ip -j route get` form; mark must come from a supported active classifier, not operator assertion. No dump of all tables/routes.
- Exact bound nft chain reads (max8, recursion depth4; unbound jump/goto => unknown), plus exact bound set metadata/one-target membership. Never global `nft list ruleset`, generated `fw4 print` as runtime proof, full set elements or logs.
- At most32 subprocess reads, each≤3s, whole existing operation≤100s including≤15s cleanup. Output overflow/unsupported tools/version/rights => partial/UNVERIFIED. No retries/rearm, packet capture or new probe in this adapter.

Local deterministic parsing occurs before normalized facts leave the collector. Do not persist/transmit raw ubus/UCI/native output, addresses, client identifiers, set elements, hardware IDs or keys. Default output remains endpoint-suppressed; no public-endpoint confirmation mechanism is added.

## 5. Implementation tasks (only after owner approval)

### Task 1 — Optional selectors and immutable scope (one commit)

**Files:** `types.go`, `registry.go`, `question.go`, `openwrt.go`, `openwrt_test.go`.

- [ ] Write failing `TestOpenWrtBindingScope`: omitted-field byte/digest compatibility with accepted Linux fixtures; typed bounds/kind restrictions and defensive-copy mutation isolation; logical binding tied to gateway; rename neutrality; rebinding/native-device drift; malicious names/argv/closure bits rejected.
- [ ] Run `go test ./internal/netpolicy -run TestOpenWrtBindingScope -count=1`; require RED, then implement only the optional DTO/validation/revision/digest seam.
- [ ] Re-run PASS plus existing registry/request/privacy tests. No native process runs or legacy state writes. Commit `feat(network): bind optional OpenWrt evidence selectors`.

### Task 2 — Pure platform normalization (one commit)

**Files:** `openwrt.go`, `openwrt_test.go` (small handwritten JSON/token fixtures inline; no production captures).

- [ ] Write `TestOpenWrtNormalize` covering:
  1. supported fw4 logical source + exact set + active classifier + RPDB choice;
  2. forwarding allowed but different selected path;
  3. desired main route but earlier marked-policy override;
  4. active scoped guard despite opposite stored kill-switch bit, and stored-enabled without active guard;
  5. matched vs unmatched destination-set branch;
  6. unknown earlier accept/jump/hook, installed-but-uncalled or wrong-hook regular chain, fwmark mask/priority conflict, NAT/rewrite or offload => incomplete coverage;
  7. stale/rebound/wrong-source/family/device and mixed runtime samples;
  8. GL.iNet extension on the same generic object, including unmatched/fallback behavior; fw3/unknown firmware partial capabilities with firewall/guard unknown;
  9. router-origin/subnet-name evidence cannot become client-origin proof;
  10. imported/synthetic data cannot become runtime/production evidence.
- [ ] Run `go test ./internal/netpolicy -run TestOpenWrtNormalize -count=1`; require RED. Implement a finite supported subset only; fixed semantic fingerprints exclude counters/handles that are not configuration identity. No universal rule interpreter or vendor verdict logic.
- [ ] PASS: assert forwarding permission, FIB selection, observed path and guard facts are independent; unknown wins over unjustified completeness. Commit `feat(network): normalize scoped OpenWrt gateway facts`.

### Task 3 — Admitted fixed reader and generic dispatch (one commit)

**Files:** `openwrt_read.go`, `openwrt_test.go`, narrow `linuxwg.go` dispatch.

- [ ] Write `TestOpenWrtReadBoundary`: exact argv/selectors/namespace, no native call before admission, revocation/expiry/rebind before each read, unsupported local tools/rights/backend, output/row/depth/operation bounds, changed before/after semantic snapshots, no credential/config/log read, no mutation or probing. Inspect/discover remain metadata-only.
- [ ] Run focused test RED; implement existing local reader mechanics only. Read compatible active state before/after; a change during sampling invalidates composite path/guard evidence. Never promote stored flags or caller JSON into effective coverage.
- [ ] Feed matching scoped facts to existing collection/evaluation, not a vendor verdict. Preserve the four-property gateway and conditional VPN profiles; extra facts do not enlarge their claim. Existing access/isolation remains UNVERIFIED unless its existing source/probe/baseline/observer/coverage requirements independently hold. This read-only adapter does not invent a client vantage.
- [ ] PASS focused + full existing Linux/CLI tests; legacy contracts/state byte sentinels unchanged. Commit `feat(network): collect bounded OpenWrt gateway evidence`.

### Task 4 — Synthetic cross-model gate and precise support docs (one commit)

**Files:** `openwrt_test.go`, existing `integration_linux_test.go`, `docs/network-verification.md`, README only if needed.

- [ ] Run an authorized **isolated** Linux fixture: fresh synthetic namespace with real kernel RPDB, routes, nft sets/guards, and clearly labeled fixture ubus/UCI output. Exercise generic dispatch, active runtime reads, stored/runtime disagreement and an injected real priority/guard/set change. No private device or host configuration. Setup mutations are test-coordinator-only; adapter reads leave fixture state unchanged.
- [ ] Prove supported normalized facts match the kernel, drift/unknown overrides/fw3 gaps remain partial, and no forwarding-only/path-only fact verifies a guard. Reuse the existing closed-fixture provenance ONLY there. Assert the public gateway/VPN profile remains finite despite extra native evidence.
- [ ] Fixture ubus/UCI stubs prove parser/orchestration, **not real firmware compatibility**. Before any real firmware support claim, run the same read-only adapter on an independently owned controlled OpenWrt test image or a separately owner-authorized private dogfood collection; otherwise document “fixture-validated; live firmware UNVERIFIED.” Do not install/download a firmware image or contact any device during planning.
- [ ] Run `go test ./...`, `go test -race ./internal/netpolicy ./cmd/21pins`, `go vet ./...`, Linux amd64/arm64 build and existing real Linux/WireGuard/DNS gate. No SKIP counts as native release evidence. `git diff --check`; only planned slice files staged, unrelated website changes preserved.
- [ ] Update docs with exact backend/profile capabilities, unknown coverage and stored-vs-runtime caveats. No new public vendor commands, automatic repair, expanded grant semantics or all-GL.iNet support claim. Commit `test(network): validate OpenWrt evidence against generic contracts`.

## 6. Review / stop gate

Independent fresh-context plan review must check scope, reachability of admission/collection, omitted-binding compatibility, source identity, precedence completeness, backend limitations, privacy and fixture-vs-production assurance. Parent is sole writer; reviewers read only. Resolve blocking findings before presenting for approval.

**After review: stop for explicit owner approval.** No Task1, implementation, live read, probe, image/VM setup, new trust or later adapter before that approval. The next cross-model target remains Tailscale only after OpenWrt/GL.iNet gateway validation is accepted; it is not authorized here.

## Public semantic references (not collection authority)

- OpenWrt ubus network API: https://openwrt.org/docs/guide-developer/ubus/network — status is runtime information, not the whole effective firewall.
- OpenWrt firewall configuration: https://openwrt.org/docs/guide-user/firewall/firewall_configuration — stored UCI versus active backend.
- GL.iNet VPN dashboard: https://docs.gl-inet.com/router/en/4/interface_guide/vpn_dashboard/ — matched/unmatched traffic and fallback settings.
- GL.iNet kill switch: https://docs.gl-inet.com/router/en/4/faq/block_non_vpn_traffic/ — tunnel versus enhanced policy-mode guard, version-specific behavior. UI labels/defaults are not native proof.
