# Trusted-client evidence: historical correlation not verified

Latest: owner approved the owner-started synchronized workflow. It is prepared and offline-tested, NOT yet run. See `beryl-synchronized-proof.md` for the single owner command, exact-nonce readiness gate, binary policy-EDE evidence, bounded cleanup and limitations. No server collector was started during preparation; new one-use authorization remains unconsumed. Trusted E2E and guest isolation remain unverified pending actual evidence.

## Single authorized follow-up attempt — closed, exception expired

The owner authorized exactly one read-only nonce-only server window through existing management. Pi did NOT execute/simulate the client or change host/network/trust configuration. Before launch, the private readiness marker was absent; kernel-filter readiness was positively verified at `2026-10-13T13:13:20.211060Z`. The bounded95s observer closed cleanly with zero source-bound synthetic queries. The post-observer pinned-peer snapshot was at `2026-10-13T13:14:56.937619Z`; owned PID22028 has exited. The exception was consumed and is now expired; no subsequent management observation is authorized.

Owner subsequently supplied trusted-client nonce `pins-d55b10aec842f2d0.invalid`, window `2026-10-13T13:16:48.627616Z`–`13:16:51.008422Z`. Its reported start is111.69s AFTER the completed post-observer snapshot. Therefore no overlap or exact nonce/query correlation exists. Clock mismatch is also not ruled out; zero captured challenge still supplies no positive correlation. Do not interpret the empty window as DNS failure.

Pinned-peer traffic advanced during the EARLIER server window (RX+4780 bytes, TX+7236 bytes; latest handshake1791897147→1791897269). These earlier deltas cannot be attributed to the later client nonce/window. They are NOT trusted-client E2E proof.

Client public DNS/HTTPS and private allowed UDP/TCP controls succeeded; private blocked/challenge UDP/TCP returned NXDOMAIN. All supplied explicit_block_or_filter_EDE fields are false. This does not prove filtering failed, but NXDOMAIN alone does not prove policy-generated blocking. No contemporaneous resolver policy record was collected/exposed.

Trusted E2E remains UNVERIFIED; guest isolation remains unverified and unauthorized. No second window or status polling was started. Temporary local collector/result material is retired after recording these minimized facts.

A further attempt requires a NEW one-use exception, not reuse of the consumed grant. To avoid another expired RUN NOW window, prepare an owner-started synchronized terminal workflow that starts the server witness and waits for readiness immediately before the OWNER executes the client command. Pi must never run/simulate that client. Ensure the next witness can report the actual filtering decision (explicit EDE or a source/test/time-filtered resolver policy event), not only challenge arrival. Resolve those capabilities before asking the owner to repeat the client test.

## Owner-supplied successful client observations

Trusted client window: `2026-10-13T12:50:22.599628Z` through `2026-10-13T12:50:24.933306Z` (epoch1791895822.599628–1791895824.933306).

Exact synthetic challenge: `pins-6e653a730174ba45.invalid`.

Public DNS NOERROR/answer and HTTPS work. Private allowed control NOERROR/answer on UDP/TCP; blocked control NXDOMAIN on UDP/TCP; synthetic challenge NXDOMAIN on UDP/TCP. Client harness correctly says fresh server correlation required and E2E_complete=false. This verifies reported client behavior, NOT independently correlated trusted E2E. Guest isolation remains wholly separate/unverified.

## Verification-only execution through existing 21pins scopes

`TestApprovedBerylTrustedCorrelationReadOnly` executed only `beryl inspect`, `dns test`, `technitium status`, `technitium filtering` using existing real certificates/API approval/bastion/target pins. No enrollment, guest-agent bypass, packet collector, configuration update, WG/DNS/firewall/route/host changes.

Actual results:

- Beryl configured peer inspected; all4 peer mappings preserved, recent-handshake=true, latest timestamp1791896169 (`2026-10-13T12:56:09Z`). This is AFTER and OUTSIDE the supplied two-second client window, not a recovered timestamp/traffic baseline for it.
- Current DNS UDP/TCP fixed-control test and Technitium service verification pass.
- `technitium filtering` denies with `filter_probe_unconfigured`. Existing immutable manifest lacks real blocked-domain pins; do not change its digest/rules/trust or substitute a root bypass.
- Both verification leases completed and requester/API temporary credentials removed.

Installed WG scope has only `beryl enroll`/`beryl inspect`; the latter exposes current configuration, bounded recency and latest handshake, not historical handshake records or transfer counters. Installed DNS scope exposes its fixed queries/service checks and unavailable-proof operations, not arbitrary query selectors or resolver logs. No installed operation can retrieve this nonce, client-source/protocol/timestamp audit rows, or historical policy/EDE result.

Earlier bounded passive observation was an existing-management diagnostic, NOT an installed 21pins command. Its clean window ended before this supplied run and captured zero nonce traffic. It cannot be used retrospectively, and the current request explicitly restricts this attempt to scoped 21pins access only. No management/root bypass was performed.

## Exactly missing evidence

1. A gateway handshake/traffic observation bracketed around the supplied window, attributable to the pinned peer; current latest handshake is not historical proof.
2. A timestamped intended-resolver query/packet record for this exact nonce, from the intended Beryl tunnel source, with UDP and TCP correlation. No such record is available through installed scopes.
3. Contemporaneous policy-generated blocked-control evidence, such as explicit Blocked/Filtered EDE or a filtered resolver audit event. NXDOMAIN alone is not proof of filtering. Prior server-local EDE observations are not this historical client transaction; owner may preserve the actual harness EDE field if present, but that alone does not supply the missing nonce witness.

Trusted E2E remains UNVERIFIED. This is a capability/evidence limit, not an assertion the successful client queries failed.

## Prepare exactly one coordinated rerun — do not run yet

Resolve the server witness authority FIRST; repeating the client within unchanged installed roles cannot create nonce-query evidence those roles cannot expose. No role/trust/host-config expansion is proposed under this verification-only request.

Minimal possible scope exception, only if the owner authorizes it: use the **already-existing management path**, no new trust or credentials, for one ≤100s source/nonce-only server observation (existing validated `beryl-query-observer.py`) and bounded before/after peer-traffic readings. Keep root-side kernel filtering, no Ethernet/MAC/public-IP/personal query collection or raw output/storage, no service/network/settings changes. This is outside the current only-21pins restriction and must NOT run without an explicit exception. Existing read-only 21pins `beryl inspect` supplies before/after handshake and DNS scope supplies service/control checks.

Once witness authority is available: owner at trusted Beryl-client Terminal → fresh server baseline → confirm observer ready → one RUN NOW → owner runs `python3 /Users/claw/flowstate/repos/21pins/scripts/beryl-client-proof.py --network trusted` → capture exact fresh nonce/UTC/protocol counts and actual EDE field → fresh post-handshake/traffic check → stop/clean observer and close certificate leases. Require all correlations before recording trusted E2E verified. Then plan guest test separately. No repeated polling or unobserved client reruns.

## Human actions required

In this Pi chat either preserve the only-21pins restriction (correlation remains unavailable), or explicitly reply **`Allow one read-only nonce-only server correlation window via the existing management path`**. This grants only the described verification exception, NOT any host/WG/DNS/firewall/routing/trust mutation or Beryl login/admin/probes. Do not paste keys, tokens, profiles, packet dumps, MACs, public IPs or raw logs. Expected signal: Pi coordinates one fresh observer-ready window and correlates the new status-only client JSON, not another installation or a claim of guest isolation.
