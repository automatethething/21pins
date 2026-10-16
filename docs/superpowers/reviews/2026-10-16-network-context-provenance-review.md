# Generic context provenance — independent design/plan review

**Final verdict: APPROVED round2; owner implementation approval pending.**

# Context Provenance SPEC/PLAN Review — Round 2

## Review
- Correct: The spec separates execution, dataplane, control-plane, and registered-binding references (`docs/superpowers/specs/2026-10-16-network-context-provenance-design.md:13`) and requires exact private mapping witnesses rather than daemon/client namespace inference (`:42`).
- Correct: Handle lifetime is bounded and sealed-window based; later reuse requires a live original anchor or independently proven continuity (`:22`).
- Correct: Default-deny generic claim requirements, candidate retention, and evaluator-only verdict emission are specified (`:48-65`).
- Correct: The prior baseline-remint P1 is explicitly closed: baseline reuse requires the original private eligibility dependency, frozen request, provenance/lifetime/window; derived facts retain the original sealed digest and cannot reseal copied public fields (`:65`; plan Task 3, `docs/superpowers/plans/2026-10-16-network-context-provenance-plan.md:50`).
- Correct: The implementation plan covers native acquisition, multi-subject/composite dependencies, candidate handling, synthetic mapping-only positives, and an isolated Linux/Unix-socket regression without a production daemon mapping resolver (plan Tasks 1–5, `:21-72`).
- Correct: Scope and approval boundaries are coherent: no product implementation before the explicit owner phrase, no fw4 boot, Tailscale, production mapping resolver, or authority expansion (`:73-77`). The Flowstate bookkeeping is correctly limited to mandated administrative planning handoff, not product scope (`:19`, `:75`).

No issues found.

- Merge verdict: **APPROVED**
## Round1 resolution

The baseline authority-laundering finding was fixed explicitly: the derived isolation.baseline retains the original private dependency/frozen request/provenance/window, never an independent seal from copied public fields. The scope note was clarified: required workspace metadata is administrative planning handoff, not a product feature. No product code/test edits were made.

## Independent neutral advisory

Claude reviewed a manually minimized, repository-free abstract brief. Its continuous native-handle/lifetime concern was incorporated: hold through the sealed premise set, release via bounded cleanup, no later incarnation inference or background FD cache. A suggestion to defer the control-plane axis was not adopted because the owner explicitly requires it. No source, logs, identifiers, credentials or infrastructure context were sent.

## Round1 record

## Review
- Correct: The spec defines four independent contexts and explicitly rejects execution-context inheritance for Unix daemons, UCI, same-name objects, and WG transport. It requires exact private mappings, bounded composite dependencies, candidates, and conservative unsigned-baseline handling. The plan maps these to generic admission in `validFact`, synthetic mapping regressions, and no production resolver.
- Finding: P1 — Historical baseline closure needs an explicit non-reminting rule. `dns_collect.go:9-35` currently reads `Assessment.Evidence` directly, bypassing `validFact`, then `dns_collect.go:108-120` creates a new eligible fact via `c.fact`. Plan Task 3 says to “close” this path, but does not explicitly require the projected baseline fact to retain/validate the original private eligibility dependency rather than mint a fresh seal from copied public fields. Add: baseline reuse must require the original in-memory sealed fact and original frozen request/provenance/window; any derived `isolation.baseline` fact must carry that sealed dependency/provenance digest, not obtain independent eligibility from `c.fact`. Deserialized/JSON facts must always remain candidates.
- Finding: P1 — Remove the unrelated Flowstate synchronization from plan scope. The plan’s file-limits section (`...plan.md:17`) includes “synchronize Flowstate PRD/portfolio/manifest/approval queue,” despite this being a generic internal netpolicy amendment and the owner requiring no product edits now. Limit documentation changes to the listed 21pins verification docs, README limitation, plan, and review record.

- Merge verdict: BLOCK until the two bounded plan corrections are made.