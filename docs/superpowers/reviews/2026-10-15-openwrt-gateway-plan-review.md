# OpenWrt / GL.iNet evidence plan — independent review

**Final plan status: APPROVED (round3). Owner implementation approval: GRANTED.** Four implementation tasks subsequently completed; see [implementation validation](2026-10-15-openwrt-implementation-review.md).

Plan: [four-task read-only gateway evidence slice](../plans/2026-10-15-openwrt-gateway-evidence.md). Product gate: [synthetic CLI review](2026-10-15-network-cli-product-smoke.md), no blocking product-model issue. Mass-market presentation/readiness findings are not hidden or implemented in this adapter plan.

Parent is sole writer. Each reviewer received a fresh bounded read-only brief, exact project CWD and explicit prohibition on source edits, commands, live access, secrets and delegation. Review agreement grants no implementation/collection/publication authority.

## Round1

Run `17ffc729-15f6-4f5f-8a5f-f91167fd8a3a`: **Issues Found**.

- Undefined `BoundChain` / `BoundSet` fields and validation could leave immutable native scope ambiguous. Fixed: exact DTO fields, identifier grammar, family/type/cardinality/hook constraints and canonical ordering.
- “Supported classifier” lacked a finite mark-evaluation contract. Fixed: supported conjunctions/constant assignments, actual mark/mask/order correlation, bounded calls/returns and unsupported-expression/override handling. Unknown cannot become a desired route lookup or effective guard.

## Round2

Run `0ed9aa4f-4182-4381-82fb-d7ee450e2150`: **Issues Found**.

- Mutable slice/pointer ownership could change admitted scope after validation. Fixed: canonical deep copies at validation/storage/question/exposure boundaries, immutable read snapshot and input/return mutation regressions.
- Parsed regular chains could be installed but uncalled. Fixed: require a corroborated compatible active base-hook path for the requested source/tuple; missing/unreachable/wrong-hook paths remain partial/unknown. Forwarded client origin cannot be substituted by router-output evidence.

## Round3

Run `b50164b0-80f0-4652-a76c-69153dcf27ac`: **Approved**.

Reviewer confirmed bounded/actionable tasks; DTO/ownership/digest rules; finite classifiers and active reachability; source identity; stored versus runtime; unsupported/fw3 and fixture-versus-firmware limits; admitted fixed local collection without arbitrary commands, remote transport, probing or secret collection. No remaining blocking findings or advisories.

## Owner gate

At plan-review time no adapter code or fixture had started. Owner subsequently approved the four tasks, now fixture/kernel validated; no live device read, new grant/privilege/trust, private dogfood or Tailscale implementation occurred. Initial firewall evidence is explicitly fw4/nft only; unknown/fw3 evidence remains partial, not advertised support. The approved plan is no longer waiting in Key Drafts. This is a separate approval from the accepted Linux/WireGuard/DNS slice.
