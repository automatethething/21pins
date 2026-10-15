# Network policy first-slice implementation plan — independent review

**Status: APPROVED (round2). Owner approval still required BEFORE implementation.**

Plan: `../plans/2026-10-14-network-policy-first-slice.md`
Spec: `../specs/2026-10-14-network-policy-verification-design.md`

Reviewer: fresh-context, read-only `openai-codex/gpt-5.6-terra:medium`; parent remained sole writer. No implementation, infrastructure reads/probes, credential access or deployment.

## Round1 — Issues Found

1. Grant-only state access lacked a sufficiently concrete safe-reader seam before `store.New` dispatch. Corrected with `ReadGrantProjection`: existing file read-only; bounded grant-only DTO; no provider/signing object construction, store init/migration/write or sensitive output. Shared encoded bytes necessarily pass through the local decoder; the plan does not claim otherwise. Sensitive sentinel/unchanged-state tests required.
2. Effective nftables coverage could imply prohibited global collection. Corrected to exact registered family/table/chain reads; no global ruleset dump. Claims requiring unknown override coverage remain UNVERIFIED. Complete fixture-namespace closure is synthetic/test-only provenance, not a claim about shared customer environments.
3. Advisory: WireGuard expert inspection had ambiguous live-read behavior. All inspection is explicitly registry/cached-capability metadata only; native reads occur only through admitted verify.

Run: `537dba29-e23c-4baa-afb3-1abffb30e5dc` (completed).

## Round2 — Approved

Reviewer found no remaining issues or advisory notes:

- Eight-step scope/sequencing matches the owner-amended design; later platforms/protocols/SDK remain excluded.
- Existing seven-pin evaluation and native subject helpers support request-bound admission without new grant semantics.
- Read-only grant projection is concrete, bounded and fail-closed, with no provider/signing-store creation or writes.
- Registered native-chain reads, unknown/shared namespace coverage and isolated-fixture provenance are fail-closed.
- Discovery/inspection are passive metadata operations; offline request construction performs no native reads/probes.
- Protected topology remains protected by default; public endpoint disclosure is restricted to a confirmed exact inspected resource.

Run: `efe6a7d2-f32e-48f1-afe8-2cab13dcd598` (completed).

## Handoff

Review approval authorizes no implementation, new trust, probe, publication or infrastructure mutation. Owner reviews the plan and explicitly approves its execution. Implementation remains entirely unstarted.
