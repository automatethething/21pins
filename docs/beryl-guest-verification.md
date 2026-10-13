# Guest isolation VERIFIED — protected DNS / Beryl WireGuard scope

The owner's five-property acceptance criterion is satisfied by the real synchronized guest evidence, the previously verified trusted DNS baseline, and additional owner-supplied ACTIVE Beryl source-scoped policy/runtime routing evidence. Independent local reclassification returns `guest_isolation_verified=true` and `intended_boundary_rejection_verified=true`.

No configuration, firewall rule, route, DNS, Technitium, SSH trust or sudo policy was changed. Neither client suite was rerun; Pi never executed or simulated a client test or administered/probed Beryl. Both original observers closed/cleaned. Their single-use grant is expired; no new probe or observation is needed.

## Real synchronized guest observations

Guest window `2026-10-13T14:54:03.072370Z`–`14:54:09.061591Z`, nonce `pins-84898e289ec6df06.invalid`:

1. Public DNS returned NOERROR/answers and HTTPS worked.
2. Default DNS controls worked, private resolver was not advertised as DNS/failover, and the default/direct synthetic challenge was not observed on the protected path. This establishes recorded default-DNS behavior; it is not an assertion every future query/upstream was captured.
3. All direct private DNS UDP/TCP control/challenge requests failed to complete. The SAME private DNS endpoint had a real trusted UDP/TCP positive baseline at14:19, with source-bound gateway/resolver correlation and policy EDE; see `beryl-trusted-correlation.md`. No new trusted DNS or admin-port baseline is required.
4. Exact nonce absent at BOTH gateway and resolver. Gateway capture1791903234.4150271–1791903252.4364777 and resolver capture1791903234.3261144–1791903255.3503878 each fully bracket the client window. Metadata snapshots1791903230.5844307–1791903259.5749369 also bracket it. Technitium active; observer closure/cleanup verified.
5. Intended boundary attribution is now established by the active policy evidence below, rather than by timeout/absence alone.

TCP22/5380 failures are supplementary negatives, not mandatory trusted-positive baselines. No specification requires ordinary trusted Beryl clients to reach them. Their administrative-plane reachability is not certified by this verdict. Peer RX+64/TX+0 and unchanged handshake are not treated as a nonce-specific denial event or inferred keepalive trace. Redacted authorization/address values are neither required nor stored.

## Deterministic boundary evidence

Owner supplied an ACTIVE FI policy:

- enabled and killswitch enabled;
- source selector is interface `lan`, not `guest`;
- destination set is bound to the tested protected DNS endpoint (address remains redacted);
- selected private tunnel is `wgclient1`, mark `0x1000`;
- runtime routing confirms that mark selects table1001 and its protected route uses that tunnel;
- no equivalent guest-source FI policy exists.

The generated guest leak boundary is enabled: incoming interface `guest`, priority9920, action `blackhole`, disabled=0.

This is structural source-policy separation, corroborated by the differential real test: trusted protected DNS succeeds, guest public networking succeeds, guest protected transport fails, and no guest nonce reaches the protected gateway/resolver. The verdict relies on the owner's attestation that this is the active/effective policy for the same destination/test context, not merely an inactive configuration file or a different destination set.

GL.iNet-managed `firewall.guest2wgclient1` / `gl_vpn_rules=1` is generic forwarding plumbing. Forwarding permission does not itself assign the LAN-only FI mark, select its table or create a guest-source policy. It was NOT deleted or changed and is not an independent verification failure.

Two independent neutral reviewers agree the active source-policy/table/guest-guard evidence plus synchronized observations is sufficient for this bounded operational attribution. No mandatory per-probe counter delta is needed.

## What a counter would additionally prove

A test-linked counter/trace would identify which PARTICULAR enforcement operation consumed a particular packet: the generated blackhole versus source-policy exclusion or another adjacent enforcing stage. That is finer packet-level forensic attribution, not an additional required fact for proving the intended guest exclusion from this protected FI DNS path.

We do NOT claim that a specific blackhole counter incremented, that every guest packet was blackholed, or that a historical deny log was retrieved. Historical log availability remains unknown; it is no longer a blocker because the independent active-policy evidence is sufficient. The earlier mandatory-counter/admin-baseline framing is superseded.

If active-policy/destination binding were uncertain, historical matched-rule evidence or a narrowly attributable counter-before/unique-probe/counter-after observation would remain an alternative. Aggregate background counter changes cannot substitute for either validated policy or test-specific evidence. No such probe is required or authorized merely by this final verdict.

## Classifier safeguards

`classify()` accepts either independently validated test-linked reject evidence or independently validated active source-scoped routing evidence. The routing form requires: active policy, trusted-only source scope, guest-equivalent policy absent, enabled leak blackhole/killswitch, verified protected destination and marked-tunnel binding, applicable policy and UDP/TCP scope. Missing or false facts fail closed.

Neither form can be supplied by raw client JSON or a CLI witness switch. The live wrapper does not automatically fabricate a policy audit; the actual retained result was reclassified separately using the owner's read-only router evidence. The original output's false classification accurately reflected what was missing at that time; it is not rewritten as an original counter trace.

## Scope and terminal hygiene

VERIFIED for the recorded IPv4 protected DNS/port53 and Beryl→WireGuard→Technitium separation under the owner's criterion. Not a general admin-plane, IPv6, every-private-host or all-future-traffic audit; not cryptographic physical-client attestation. Trusted DNS E2E remains VERIFIED. Installed helper roles/manifests are unchanged; missing immutable native proof pins are not silently populated or broadened.

No active observers or linked work remain. No human action, configuration change or client rerun is required for this bounded objective.

Offline checks (pure fixtures/algorithms, no client or network simulation):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_beryl_guest.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_beryl_synchronized.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/beryl-query-observer.py --self-test
```
