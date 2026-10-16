# Amendment: generic network evidence context provenance

**Status: independently APPROVED round2; design only, implementation requires owner approval.** [Review](../reviews/2026-10-16-network-context-provenance-review.md). The owner accepts the real-fw4 result as **OWNER_BLOCKED on a generic provenance defect**, not a vendor exception. No product source, OpenWrt guest, boot budget, Tailscale, authority or credential change is authorized by this amendment.

Baseline: existing product code `214aad5`, current report `3769fe5`; [controlled result](../reviews/2026-10-16-openwrt-fw4-checkpointed-retry.md). Its failed composite binding/UNVERIFIED condition is sufficient to require this safety correction; the report does not invent separately unretained component verdicts.

## Invariant and smallest change

**A command's execution namespace is not the namespace/authority of every source it consults.** Add one small generic observation-provenance envelope, carried into facts as sealed dependency references. Keep verdict aggregation generic; do not add vendor branches, public network objects, grant semantics, mapping-import endpoints or dependencies.

Rejected alternatives: reject one platform/foreign namespace by name (hides the generic defect); annotate every command result with the caller namespace (repeats it); build a persistent cross-platform authority/mapping service (unnecessary new trust/storage).

### Four independent references

| Reference | Meaning | What it does not establish |
|---|---|---|
| Execution | Verified/pinned namespace in which the reader executes | Dataplane ownership or daemon authority |
| Dataplane | Verified namespace of the actual kernel object/socket/observation | Control-plane ownership or intended registered identity |
| Control plane | Serving daemon/configuration authority and its observed instance/scope | The namespace managed by that authority, or runtime enforcement |
| Registered binding | Immutable object ref/revision and expected context from the frozen question | An observation or proof that the context is currently represented |

Use existing namespace FD checks/context IDs and immutable refs. Internally keep available object/lifetime witnesses (e.g. namespace FD, interface index in that namespace, daemon/socket instance and restart/freshness evidence) for the bounded collection. A namespace alias, device name, matching address, socket path, caller network namespace, or daemon process network namespace alone is not an independently validated control-plane→dataplane mapping. Unknown is explicit; never substitute current/default context. A native namespace FD/object handle must remain open continuously through acquisition and every immediate identity-dependent join, until that bounded premise set is sealed; a one-time stat/string is not a pin. Release handles in the existing bounded cleanup once the premise set closes—no background cache or indefinite FD retention. The seal records the original handle-held interval and attests that observation window, not present liveness after release. A later verification cannot infer incarnation continuity from a reused name/inode/context string: require a still-live original anchor or independently validated continuity, otherwise retain a candidate/UNVERIFIED. Authority restart, alias replacement/removal and unproven lifetime cannot silently inherit eligibility. Same-operation evaluation of the original sealed window remains distinct from minting a later observation; no TTL/time refresh. Unknown/stale lifetimes fail closed; this amendment adds no promise of cross-restart context validity or durable identity migration.

### Private envelope, not a new public authority

Conceptually: `observation { normalized value, source kind, execution ref, optional dataplane ref, optional control-plane ref, subject ref/revision, native object scope, time window, optional mapping witness }`.

Source kinds are kernel, control-plane and stored configuration (plus existing metadata/fixture distinctions). One premise names one subject; a composite fact carries a small bounded list of these premise references. Its registered expectations are projected from a deep-frozen generic `Question` and existing metadata/request digest, **not copied from the observation itself**.

Native collection/private validators mint the envelope and a claim-bound eligibility seal. Bind seal identity to the property/value/tuple, immutable refs, request digest, relevant time window and dependency/provenance digest; deep-own inputs so later mutation cannot upgrade them. The existing private validation/fixture distinction remains necessary but alone is not sufficient provenance.

Serialized summaries are descriptive only. No JSON/private-file reload, imported `trusted`/`closed`/`same namespace`/mapping flag, matching digest, or mutable public struct field may recreate an eligibility/mapping seal. Registry import remains metadata-only and rejects authority fields. No new signer, secret, CA or grant permission is introduced.

## Acquisition and correlation rules

1. **Kernel:** execution after verified FD entry can establish dataplane provenance only for a known fixed read operation whose actual object belongs to that namespace. Classify existing read callsites/operations, not arbitrary tool names: an `ip` command capable of selecting another namespace/file is not automatically A evidence. Resolve/pin the actual object's namespace and object scope; preserve before/after drift checks. WG device/peer state does not also prove its transport socket's birth/egress namespace. Probe/observer socket provenance follows the FD's verified creation/attachment context, not a later reader thread.
2. **Control plane:** Unix-socket client execution does not bind the serving daemon to the caller namespace. Capture independently validated serving-authority identity when available; otherwise leave it unknown. Daemon output remains useful control-plane/candidate evidence even if dataplane context is unknown/different. Do not infer the managed dataplane from the server process's namespace.
3. **Stored configuration:** UCI/file-backed configuration has stored/control-plane provenance only. It cannot acquire runtime dataplane authority through namespace entry or a coincident configuration value.
4. **Runtime claim:** each required premise must have its own verified dataplane context matching its subject's registered expectation, or an explicit independently validated mapping plus the required native object witness. Logical binding claims depending on control-plane association need that association proven as well; a coincident kernel device/name/address is not a substitute for it.
5. **Multi-context facts:** validate source, gateway, VPN, endpoint and observer premises against their respective expected refs/roles. Legitimate source-A→service-B observations are not rejected merely because A!=B. Conversely, evidence for B may not be relabeled A. Do not compare every dependency only to the question target.

### Exact-scope mapping capability

A private mapping witness binds a verified control authority instance/config epoch to a verified dataplane context/native object, immutable subject revision, allowed observation/claim scope and bounded freshness window. Bind to the question/dependency digest; no name-only, all-namespaces, transitive, stale, restart-reused or revision-reused mapping. Evidence outside that exact scope remains candidate/UNVERIFIED. An adapter may request correlation; the generic private validator checks its independently acquired witnesses, not the adapter's Boolean assertion.

**First implementation is deliberately conservative:** implement the generic mapping contract and synthetic positive/negative regressions, but no guessed production ubus/netifd→kernel mapping resolver. Unknown serving/mapping provenance stays partial even in the apparent default namespace. A future production resolver requires its own independently reviewed proof mechanism; daemon PID/netns/path or UCI equality alone is insufficient. Synthetic mapping witnesses work only in existing fixture mode and cannot mint production authority.

## Fact eligibility, candidate retention and verdicts

Generic claim requirements (default for an unclassified claim is **no runtime eligibility**):

| Claim family | Required provenance |
|---|---|
| Declaration/reader availability | Frozen registered ref and the limited execution/source premise actually claimed; no implied dataplane binding |
| Interface/logical binding | Subject-owned kernel object in its registered dataplane context; if logical association is a dependency, exact proven control-plane correlation too |
| WG device/peer/freshness, routing/nft candidates | Each actual device/peer/ruleset/FIB subject's dataplane context and native object scope; no implied WG transport context or global closure |
| DNS/probe/path/boundary/observer composites | Every source/service/gateway/observer premise bound to its own expected role/context and actual socket/observation scope |
| Stored/control-plane candidates | Their bounded source/configuration provenance; never inferred runtime ownership or enforcement |


- Add generic provenance validation in fact admission (`validFact` or a shared helper), before true/false verdict use. All native-producing paths supply dependencies; missing provenance is not grandfathered as runtime authority. Metadata/reader-availability facts use their actual limited claim requirements, not invented dataplane proof.
- Runtime binding, route/path, boundary/guard, freshness and observer/DNS claims explicitly state which subject/context premises they need. The small generic property requirement table contains no vendor names. In particular the four-property gateway profile is unchanged, but interface binding cannot pass with unproven logical/context correlation.
- Retain valid normalized candidate/stored facts in an additive `Assessment.Candidates` collection (and `Collection.Facts`), with source kind and unknown/mismatch reason. They are not listed as satisfying required-property evidence refs. Do not silently drop them from CLI/save output and do not serialize raw configuration, socket paths, PIDs, addresses or hardware identifiers.
- Unknown/mismatched provenance does **not** become a false runtime fact: an otherwise unsupported claim is missing/UNVERIFIED. An independently valid contradictory fact still produces VIOLATED under the unchanged generic aggregation. Neither an invalid false candidate nor an invalid true candidate changes a verdict.
- Imported/deserialized candidate summaries remain candidates. Existing unsigned saved network assessments remain readable but cannot regain native provenance just because they are local/private files or have matching refs/runtime digests. In-memory sealed historical evidence retains original timestamps/windows/refs and is usable only under its original proven scope/freshness. Baseline selection must validate and retain the original private eligibility dependency, original frozen request and original provenance/lifetime/window. A derived `isolation.baseline` fact carries that original sealed dependency/provenance digest plus its exact current comparison scope; it must not receive an independent fresh seal from `c.fact` using copied public fields. A baseline observed from source A remains A evidence, never relabeled as the isolated source B. Old or deserialized baselines without an existing independently authenticated provenance path become candidate/UNVERIFIED; do not add receipt signing or silently re-attest the past. **This conservative historical-baseline eligibility change must be documented explicitly.** Legacy signed execution/SSH receipts are untouched.

## Required regressions and acceptance

1. Verified execution A + actual kernel object A → eligible A dataplane evidence; object actually B or selector drift → no A authority.
2. Execution A + system/default-serving Unix control plane → no A logical/interface proof without exact mapping, including same device names and even coincident addresses/indices across namespaces.
3. Independently validated mapping succeeds only for its exact authority instance/object/context/ref/revision/claim/window; wrong subject, authority, target, scope, restart, mutation or expiry fails.
4. UCI stored flag retained as configuration/candidate, never runtime binding/enforcement merely through execution A.
5. Unknown/mismatch true and false candidates survive output but cannot yield VERIFIED/VIOLATED; a valid independent contradiction still yields VIOLATED.
6. Public/imported/serialized trust fields, copied summaries, forged mappings and mutated sealed inputs cannot upgrade authority.
7. Same-context Linux/WG kernel evidence, source-bound DNS and legitimate multi-context observers remain valid at their actual established scopes; WG transport context is not inferred.
8. Historical baseline reuse preserves exact original record/window and requires provenance; saved unsealed/legacy network records do not self-upgrade. Adapters emit facts/candidates/capabilities only; the evaluator alone emits generic verdicts.

Completion after a separately approved implementation: regressions/full Go/race/vet, both Linux builds, existing Node/Pi checks, and existing isolated Linux/WG/DNS plus synthetic control-plane/context tests pass without unsafe grandfathering. A synthetic namespace/Unix-socket control-plane harness must reproduce the original class without OpenWrt or private devices. No real-fw4 compatibility, production mapping or future boot is authorized by implementation approval alone.
