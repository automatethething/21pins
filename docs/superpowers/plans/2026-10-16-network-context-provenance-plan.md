# Generic network context provenance implementation plan

> **For agentic workers:** use @superpowers:executing-plans with exactly one writer in an isolated worktree. **IMPLEMENTATION AUTHORIZED by the owner's “Finish 21pins please” directive. No OpenWrt guest or Tailscale.**

**Review:** independently APPROVED round2 — [review record](../reviews/2026-10-16-network-context-provenance-review.md). **Owner implementation approval RECORDED; complete Tasks 1–5 without expanding scope.**

**Goal:** prevent execution context from laundering control-plane/configuration observations into runtime facts for a different registered dataplane context.

**Architecture:** small private provenance/dependency envelopes and scoped mapping witnesses, bound to frozen questions and fact eligibility. Generic admission filters runtime claims; adapters still emit facts/candidates, never verdicts. No production control-plane mapping resolver in this slice.

**Tech stack:** existing Go/std library, namespace FD helpers and isolated Linux regression harness; no new dependency, grant/schema authority, signer or transport.

**Specification:** [reviewed spec amendment](../specs/2026-10-16-network-context-provenance-design.md). Product baseline `214aad5`; current docs/test-harness HEAD `3769fe5`. Existing website changes must stay byte-identical. User accepts controlled-fw4 result as OWNER_BLOCKED; there is no remaining fw4 boot permission.

## File ownership / limits

New: `internal/netpolicy/provenance.go`, `provenance_test.go`, `provenance_linux_test.go` (Linux-isolated cases). Existing seams: `evidence.go`, `question.go`, `linuxwg.go`, `namespace_linux.go`/`namespace_other.go`, `dns_collect.go`, `dns.go`, `observer.go`/`observer_linux.go`, `openwrt_read.go`, `openwrt.go`, `verify.go` and their existing tests. Touch each only where it produces, correlates, admits or projects provenance; no general refactor. `types.go`/registry import validation only if needed to keep declarations distinct from proof and reject authority fields—no new public mapping/trust schema.

Product documentation scope: `docs/network-verification.md`, README limitation paragraph, this plan/spec/review only. LLM proxy, execution grants/CK identity, SSH, signed legacy receipts and existing operational hosts remain untouched.

Administrative handoff only (not a runtime/implementation feature): governing workspace instructions require the existing Flowstate PRD/portfolio/manifest to reflect material implementation reality. Update those records only after verified milestones; this does not broaden `internal/netpolicy` scope.

## Task 1 — sealed observation/fact context contract

**Files:** new `provenance.go`, `provenance_test.go`; focused `evidence.go`, `question.go`/`linuxwg.go:Question` changes; existing evidence/verify tests.

- [ ] RED: `TestProvenancePlanesDoNotInheritExecution`, `TestContextMappingExactScope`, `TestProvenanceMutationAndImportCannotUpgrade`, `TestCompositeSubjectsUseTheirOwnContexts`. Wrong/unknown plane, same-name devices, wrong ref/revision/authority/object/claim, stale/restarted/expired mappings and mutated input must not create runtime eligibility.
- [ ] Run `go test ./internal/netpolicy -run 'Test(Provenance|ContextMapping|CompositeSubjects)' -count=1`; record expected failures before implementation.
- [ ] Add the small envelope/source-kind/context-ref model from the spec, a bounded per-subject dependency list, and private exact-scope mapping witness. Deep-freeze generic question context expectations from registered objects and the existing metadata/request digest. Reuse existing OpenWrt deep ownership rather than leave two divergent snapshots. Observation values never supply their own expected context.
- [ ] Mint private eligibility only from independently checked premises; bind property/value/tuple/ref revisions/window/request/provenance so copied or mutated public fields cannot reuse a seal for another claim. Zero/missing provenance is not runtime authority. Fixture mapping constructors stay synthetic-only; there is no arbitrary production mapping mint function accepting a Boolean.
- [ ] GREEN the tests, including JSON roundtrip/forged `trusted`, `closed`, `same_namespace`, mapping state and prior-provenance summaries. Imported declarations stay metadata. Commit this unit with tests; do not yet enable a native success fallback.

## Task 2 — truthful native acquisition, not command-location inference

**Files:** `linuxwg.go`, `namespace_linux.go`, `namespace_other.go`, new `provenance_linux_test.go`, namespace/native reader tests.

- [ ] RED: known kernel read in verified A yields A object provenance; a different actual object/context, selector/alias drift and same ifname/ifindex in B cannot become A evidence. A filesystem Unix-socket server outside A must not inherit A from its client. Include reader restoration/drift failure.
- [ ] Run the matching unit tests before implementation; native tests run only later in an owned isolated Linux runner, not on a host/private router.
- [ ] Introduce a minimal internal observation-returning acquisition seam. Existing raw execution may remain low-level, but it grants no provenance by itself. Audit fixed read callsites and classify **operation/object semantics**, not all `ip`/`wg`/`nft` outputs by executable name. Reject unknown selectors/source semantics rather than assume scope.
- [ ] Reuse pinned FD entry and before/after checks; hold native handles continuously through acquisition/correlation until the bounded premise set is sealed, not just a one-time stat. Record the held interval, then close handles in existing bounded cleanup; add no background cache/indefinite lease. Establish the actual kernel object's namespace/object token. Same-operation evaluation attests only the original sealed window; later reuse needs a still-live original anchor or independently validated continuity, never equal names/inodes alone. Unknown/recreated incarnation stays candidate/UNVERIFIED. Test release/reuse and namespace-alias replacement explicitly. Probe/listener/monitor FDs keep their verified creation/attachment context. WG device/peer provenance is not transport-socket birthplace/egress proof.
- [ ] Classify Unix daemon output by independently established serving authority (or unknown), and file/UCI data as stored configuration. Do not equate daemon process netns/path with its managed dataplane or introduce a new discovery/credential/daemon-inventory operation.
- [ ] GREEN unit tests; compile Linux amd64/arm64 to cover native/portable seams. Commit.

## Task 3 — generic eligibility, candidates and historical evidence

**Files:** `evidence.go`, `verify.go`, `linuxwg.go`, `dns_collect.go`, `dns.go`, `observer.go`/`observer_linux.go`; `evidence_test.go`, `verify_test.go`, `baseline_test.go`, DNS/observer tests.

- [ ] RED: invalid true/false provenance cannot change verdicts; candidates survive collection→assessment→save/display; valid false runtime evidence still yields VIOLATED. Source-A/service-B/observer-C dependencies are matched to their own registered subjects, not all to the target. Existing fresh same-context WG/kernel/DNS observations stay eligible.
- [ ] Audit every `newFact`/`collector.fact`/`sessionFact` producer and observer/baseline path; attach the precise used premises and limited claim requirements. Small generic property requirements contain no vendor names; execution/metadata-only facts must not claim dataplane ownership. Missing provenance fails closed—no blanket legacy-runtime default.
- [ ] Add provenance admission to `validFact` (or one shared helper called there), before the existing true/false aggregation. Keep VERIFIED/VIOLATED/UNVERIFIED semantics, finite gateway/VPN profiles and policy/path/guard distinctions unchanged.
- [ ] Add bounded additive `Assessment.Candidates`; preserve normalized candidate/stored facts with descriptive source/relation/reason, not raw config/identifiers or required-property success refs. Candidate failure/mismatch does not become a false runtime fact.
- [ ] Close `dns_collect.go:baselineObservation` as an alternate authority path: require and validate the original in-memory private eligibility dependency, frozen original request and provenance/lifetime/window. Any derived `isolation.baseline` fact retains that sealed dependency/provenance digest and exact current comparison scope; prohibit minting a fresh independent seal via `c.fact` from copied public fields. Keep original source A distinct from current isolated source B and never rewrite observation time. Add `TestBaselineCannotRemintFromPublicFields` and JSON-roundtrip/mutated-original-request regressions. Readable unsigned saved/legacy network assessments without independently authenticated provenance remain candidates/UNVERIFIED, even with matching runtime digests or private file ownership. Do not add signing/new secrets or re-attest past traffic. Preserve legacy signed execution/SSH receipt behavior.
- [ ] GREEN focused tests and `go test ./internal/netpolicy`; record the conservative persisted-baseline eligibility change in docs. Commit.

## Task 4 — adapter composition, no vendor exception or invented mapping

**Files:** `openwrt_read.go`, `openwrt.go`, `openwrt_test.go`, relevant `integration_linux_test.go` fixtures; common provenance tests.

- [ ] RED: reproduce execution A + system/default control plane + mirrored device name/native identity mismatch; required logical/interface binding remains missing/UNVERIFIED. Also test coincident names/addresses/indices (not mapping proof), stored UCI separation, and exact validated synthetic mapping versus wrong-scope mapping.
- [ ] Thread observation provenance through the private snapshot/normalizer/fact composition. Keep logical/configuration/native candidate information even when CP identity or mapping is unknown; ensure every claim depending on that association is downgraded, not just one output property. Independent eligible kernel facts may remain useful at their actual declared scope.
- [ ] No production ubus/netifd↔dataplane mapping resolver is added. Default namespace, client namespace, server PID/netns/path and UCI equality cannot silently supply one. The generic mapping contract's positive fixture is synthetic-only; a fixture success never becomes production/native authority.
- [ ] Preserve native parsing, collection budgets, capabilities/partial flags and stored/runtime digests. Do not classify an unsupported expression as supported, fabricate source/path/closure facts, emit adapter verdicts, or add vendor checks to `Evaluate`.
- [ ] Update old synthetic positive tests only where they relied on the now-rejected inference: without mapping they must expect candidate/UNVERIFIED; add a separately proven synthetic mapping case for positive correlation. Never weaken the foreign-namespace negative or use `fixture`/`closed` as provenance proof.
- [ ] GREEN focused adapter/provenance tests; commit. This does not establish real firmware compatibility.

## Task 5 — isolated regression/review and approval-safe handoff

- [ ] Add the Linux-only `TestKernelAndUnixSocketContextProvenance`: real fresh namespaces with mirrored device identities and an owned filesystem Unix-socket control-plane fixture. Verify actual kernel ownership versus the other serving authority. No OpenWrt image/guest, real ubus service/private device or native ip/wg/nft PATH stub. This synthetic control-plane fixture proves the generic boundary, not firmware support.
- [ ] Run `go test ./...`, `go test -race ./...`, `go vet ./...` in the exact repo/worktree, each tool invocation<=120s; repair/retest safe implementation defects without expanding expected semantics.
- [ ] Build static Linux binaries with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o <owned-temp>/21pins-amd64 ./cmd/21pins` and corresponding `GOARCH=arm64`; run existing `npm` package test script from its own directory, not an invented runner syntax.
- [ ] In an explicitly owned disposable Linux runner under the existing isolation gate, run `PINS21_ISOLATED_NETWORK_TEST=1 go test -race ./internal/netpolicy -run '^(TestLinuxWGDNSE2E|TestKernelAndUnixSocketContextProvenance|TestOpenWrtKernelCrossModel)$' -count=1 -v`. Require actual execution/no SKIP for these gates. The last test remains synthetic ubus/UCI orchestration, not a firmware guest. Preserve existing permissions, namespace cleanup, leak/control/UNVERIFIED behavior and binary EDE/probe scopes. No production router, host-network change or new trust.
- [ ] Independently review the generic provenance/eligibility and adapter/dependency migration; one writer fixes findings, then reruns affected gates. Inspect exact CWD fleet/sessions and verify complete owned-runner/temp/namespace/socket cleanup before closure.
- [ ] Document source-scoped success versus candidate/UNVERIFIED, persisted unsigned baseline limits and known fw4 stop; preserve endpoint suppression and existing signed authority. No firmware-support assertion, Tailscale work or fw4 boot follows automatically.

## Authorization boundary

The owner's “Finish 21pins please” directive authorizes Tasks 1–5 as reversible local development and verification work. It does **not** authorize another OpenWrt guest, real router/device access, credentials/trust changes, deployment, a production mapping resolver, fw3, Tailscale, or a public compatibility claim. A firmware revalidation proposal may be considered only after the generic fix is independently verified and still requires a separately explicit boot budget.
