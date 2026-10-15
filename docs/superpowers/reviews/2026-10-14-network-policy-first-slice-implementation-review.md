# Network policy first slice — implementation validation

## Scope

Owner-approved eight-task local implementation, one writer. Generic registry/policy/admission/evidence/verdict contracts were committed before discovery/native collectors. Public endpoint display stays suppressed; no confirmation command/field/state. Gateway and VPN have finite pinned profiles; neither implies attached-policy compliance or universal health.

No production deployment, publication, existing host/interface/sysctl/firewall/DNS/VPN changes, new privileged transport, native SSH/LLM/grant/legacy-receipt changes or later adapters. All native fixture mutations occurred only in fresh owned namespaces inside a separate disposable local Linux runtime. Existing peers, roles, CA custody/recovery and unrelated website edits are outside this slice.

## Independent code review

Fresh read-only reviewers, parent sole writer:

- Initial broad authority/evidence reviews exceeded119s and returned no findings. They are failures, not approvals.
- Narrow authority seam (`authorize.go`, `question.go`, `cli.go`): **No issues found**; run `a174408b-172a-4412-a156-d16d8328f227`.
- Narrow evidence seam: transport-wide hit aggregation could misattribute repeated attempts; run `e4bf7387-ca9c-4327-a4d7-77d53919a6b4`. Fixed by an explicit fail-closed v1 native boundary: one bound source/endpoint/realm/family/port, at most one attempt per transport; mismatched/repeated scope stays UNVERIFIED. Controls use distinct challenges.
- Follow-up confirmed attribution fixed but found historical metadata copying could select a preceding unvalidated lookalike; run `3639448a-ba56-4e81-bbe8-c0f5a77f36fd`. Fixed by returning the exact validated prior fact once, preserving its original times/windows/reference. Regression puts the invalid lookalike first.
- Native review flagged full fragment payload capture before port validation; run `bd402afd-5857-45d7-aa19-f42bd75eadcf`. Fixed without silently hiding fragments: copy one payloadless IPv4 version byte only, mark coverage incomplete. Normal query data now also requires exact random DNS question in the kernel filter. Split TCP queries similarly remain unknown; no reassembly feature.
- Final fresh resolution review: both remaining corrections verified, **No issues found; merge verdict OK**; run `c62e99e5-4d60-41f4-9869-4dda15a7dcb4`. This is bounded seam review, not a claim that every existing repository surface was re-audited.

Local review additionally hardened first-terminal nft verdict ordering, conflicting selectors/global overrides, stale matching-policy rejection, explicit access-mode expansion, source-interface socket binding, opened-namespace-FD identity, minimal native environments, filter-before-activation/CLOEXEC, final kernel drop accounting and native session expiry. Each nontrivial seam has a runnable focused check or the real integration gate.

## Real native integration — PASS, not SKIP

Final command on the isolated Linux runner:

```sh
go test -race -tags=netpolicy_integration ./internal/netpolicy -count=1 -v -timeout=100s
```

PASS: real end-to-end case9.49s, whole package10.55s, no skip/race report. CLI orchestration runs in-process to inject private fixture-only closure/identity; actual main-dispatch subprocess regression is covered separately. This is not a claim that the production binary exposes a closure override.

The actual fixture uses four fresh namespaces, synthetic keys and identity/grants, native WireGuard authenticated peers, source-specific nft guards/NAT, real UDP/TCP DNS listeners and kernel-filtered source-bound observers. It proves:

- Metadata import → passive discover/inspect → offline request → existing-grant admission → real verify → immutable normalized record.
- Exact four-property gateway and conditional six-property VPN profiles.
- Real trusted UDP/TCP protected DNS access/path; real denied source with public controls, current effective guard and historical positive baseline.
- Removing a real guard produces an actual protected-query leak and VIOLATED.
- Unknown policy closure, missing native tool/probe capability, broken positive control/service produce UNVERIFIED, not false violation/verification.
- Historical baseline does not refresh its original time/provenance; actual observer windows retained.
- Gateway/VPN scoped results remain distinct from the attached guest policy's actual leak.
- Legacy provider/grant/signing state bytes unchanged; endpoints/peer IDs absent from default output.
- Observer sockets close; DNS listeners, synthetic keys/records and all four namespaces are cleaned. No fixture collector remains active.

This is synthetic/test provenance, never customer-network assurance. Production shared/unknown override coverage remains UNVERIFIED and has no public “trust closure” switch.

## Regression / release gates

- `go test ./... -count=1` — PASS, all existing/new packages.
- `go test -race ./... -count=1` — PASS, all existing/new packages.
- `go vet ./...` — PASS.
- Linux amd64 + arm64 CLI cross-build — PASS.
- Existing Node/Pi SSH harness with installed Pi loader —7/7 PASS,0 SKIP.
- Real Linux complete package with race detector / integration tag — PASS, including kernel-filter program test and actual WG/DNS allow/deny/leak cases.
- Dashboard actual list renderer, actual draft viewer and queue validator — PASS;5 still-pending entries, approved21pins drafts removed.
- `git diff --check` — PASS.

No failed/skipped native fixture counts as passing. Final local integration rechecks are recorded in the parent session.

See [operator-facing commands and limitations](../../network-verification.md). No push/deploy/publication is part of this objective.
