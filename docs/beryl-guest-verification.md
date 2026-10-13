# Guest isolation — expected behavior observed, NOT VERIFIED

Trusted-network E2E remains VERIFIED. The owner executed the separate guest attempt; both observers closed and cleanup is verified. Guest classification remains NOT VERIFIED; the single-run grant has expired. No configuration/trust/policy changes or trusted-client rerun occurred.

## Actual guest evidence and read-only gap reconciliation

Real owner guest window: `2026-10-13T14:54:03.072370Z`–`14:54:09.061591Z`, nonce `pins-84898e289ec6df06.invalid`. Independently recomputed epochs confirm BOTH active observer windows fully bracket it: gateway1791903234.4150271–1791903252.4364777; resolver1791903234.3261144–1791903255.3503878. Gateway metadata snapshots1791903230.5844307–1791903259.5749369 also bracket the run.

Established observations:

- Public DNS NOERROR/answer and public HTTPS work on the owner-attested guest network.
- None of six direct private DNS UDP/TCP control/challenge requests completed; private resolver was not advertised as DNS/failover.
- No test nonce was observed at the monitored decrypted Beryl-peer gateway interface or intended private resolver during full observation coverage; Technitium was active. This is bounded/source/path-specific absence, not an assertion all possible traffic was monitored or a proof of causal rejection.
- Client TCP connections to private DNS-host admin ports22/5380 did not succeed. Gateway RX+64/TX+0 and unchanged handshake are not a nonce-specific denial event; no keepalive or drop-cause inference.
- Both observers/owned markers closed/cleaned, no automatic retry; trusted test not rerun. Redacted authorization-field value is not required or stored.

Existing evidence closes the REQUIRED trusted **DNS/port53** baseline: real trusted UDP/TCP allowed replies plus source-bound query/service/policy proof at14:19. Specification review found no requirement that ordinary Beryl trusted clients can reach TCP22/5380. Those are supplementary negative probes, NOT verification gates; no trusted admin-port check is required. The earlier mandatory admin-baseline flag was an overconstraint and is removed.

A narrow local report/record lookup found only the known private-DNS topology report, no Beryl/guest-specific policy report. Existing known local topology report contains server INPUT/FORWARD-drop/DNS-source-ACL evidence, but no guest nonce/window, UCI command or Beryl firewall-config export. It is not Beryl guest-edge policy/counter evidence. Known narrow owner transcripts contain the explicit no-Beryl-SSH/admin/probe restriction and no existing router-policy export. Installed21pins has no Beryl host; its WG role only enroll/inspect and DNS role fixed query/test/status/missing-proof literals cannot retrieve Beryl guest rules, routes or counters. No already-authorized Beryl policy-reading mechanism is evidenced. No router access or new management trust was attempted.

## Corrected acceptance and reclassification

The required properties are: (1) public Internet works, (2) effective default DNS works without protected private DNS advertisement/use observed for the challenge, (3) verified trusted private DNS endpoint fails guest requests, (4) exact guest nonce absent at both protected observation points during full coverage, (5) rejection attributable to intended Beryl guest boundary.

Reprocessing the EXISTING owner record using the corrected classifier passes the observable gates for1–4. The ONLY remaining required failure is `intended_boundary_rejection_not_proven`. Default-DNS findings are scoped to recorded controls/challenge, not a claim all possible future queries/upstream resolvers were monitored. The wrapper never accepts a causal witness from raw client JSON: an independently validated policy-audit result is required. Tests verify that validated attribution permits VERIFIED WITHOUT admin positives, whereas silence, aggregate counter state, wrong/unattributed witnesses, private query leakage and missing trusted DNS proof cannot pass.

Whether Beryl retains a historical deny/log event for14:54:03–14:54:09 is **UNKNOWN**, not established absent. Available local records do not contain it and there is no identified already-authorized router policy-reading channel for Pi. No Beryl SSH, management probe or new credential access was attempted. No full synchronized suite rerun or admin-port baseline is necessary merely to reevaluate these records.

## Minimal conditional boundary verification proposal

First use a preexisting, test-linked historical deny record if one exists: existing rule identity/action, correct guest source/destination/protocol direction and14:54 test association. A current toggle or cumulative counter alone does not close attribution.

If that record does NOT exist, prepare ONE owner-started bounded attempt, no chat-dependent capture window:

1. Read and identify the existing compiled guest→private/WireGuard reject/drop/prohibit rule and routing/zone context. Verify it actually matches the known-positive private DNS target/guest source and relevant transports; never invent a rule or change it.
2. Pre-generate one fresh nonce and arm exact-nonce observers at gateway and resolver; verify actual readiness.
3. Immediately read the selected existing rule counter BEFORE the probe. Do not reset counters or enable logs.
4. Owner emits ONE nonce-bearing UDP DNS query to the already-known-positive private DNS endpoint. Record exact send/UTC/protocol/flow evidence, no raw unrelated data.
5. Immediately read the SAME rule counter AFTER. Require an attributable expected delta for that probe—not merely a nonzero broad counter that could reflect other guest traffic—and verify source/path/destination/compiled rule matches. If counters are aggregate and attribution cannot be separated read-only, the result remains NOT VERIFIED.
6. Confirm that nonce is absent beyond the boundary during the bracketed probe; stop/clean both observers and minimal temporary resources. Read-only policy identity must remain unchanged. No trusted E2E rerun, full guest suite, logging/rule/router/host change.

Historical evidence must identify the applicable compiled rule/policy version and continuity for the completed test; a rule recompiled later cannot automatically attest earlier behavior. A new narrow confirmation records its own timestamp and unchanged-policy relationship to the retained guest observations, not a fabricated historical packet trace.

A protocol-independent matching rejection rule allows one probe to establish the shared boundary. If UDP/TCP use distinct rules, do not claim a UDP counter validates the other rule: inspect an existing equivalent TCP witness or explicitly identify the additional minimal probe before running anything.

If the historical witness or narrowly correlated counter attempt establishes property5, `guest_isolation_verified=true` is justified under the owner's five-property acceptance criterion. It is NOT VERIFIED until then.

## Current Human actions required

Use your existing Beryl management interface in read-only/view mode, its guest→private/WireGuard firewall/routing policy and existing deny/audit history, to determine whether it retains a matched reject/route decision for the14:54:03–14:54:09 test. Share ONLY minimized rule identity, guest/private direction, action, timestamp and a test-specific match/count (not raw logs, credentials, addresses, MACs or unrelated traffic). If you want Pi to perform that inspection, explicitly identify and authorize the bounded read-only mechanism; no Beryl login/probe channel is currently authorized for Pi.

Do NOT run either synchronized wrapper or the previously suggested admin-baseline command. Reply here with the minimized historical rule match, or state that no historical test-linked event exists. If direct read-only inspection is desired, identify the existing owner-controlled mechanism and its bounded permission; do not send credentials. Expected success is an independently validated test-specific boundary witness, after which Pi can reclassify the retained guest record without replay. If none exists, Pi can prepare the minimal counter-before/one-probe/counter-after attempt described above; no live probe has started.

The procedure below is historical, not authorization to replay.

## Prepared owner-started execution

Owner replied “ok I'm connected to the guest network” after the synchronized guest-workflow proposal. The guest-only owner command is now prepared and offline-tested, NOT run by Pi. It uses the same no-chat-delay synchronization that worked for trusted: two server witnesses are armed first, actual matching kernel readiness confirmed, then the owner's client executes immediately. No idle indefinite collector or silent window rearming. Main95s+cleanup≤20s, each remote observer85s; all operations below120s.

The diagnostic can detect private reachability/protected-path leakage. Without affirmative boundary-denial evidence, **negative behavior remains NOT VERIFIED**, not a policy pass. Those missing capabilities are explicit in the final classifier; no configuration change or synthetic substitute manufactures them.

## Evidence criteria / preparation plan

- Owner attests actual guest network; public DNS/HTTPS positive controls must succeed.
- Use one pre-generated exact nonce for direct private DNS UDP/TCP attempts and default-DNS challenge, including potential guest DNS-proxy leakage. Record bounded transport/error/control results, never raw replies or unrelated data.
- Observe the exact nonce at BOTH the pinned peer's decrypted gateway interface and intended resolver. A resolver-local raw socket alone can miss packets dropped by the resolver host firewall, so it cannot establish that no query traversed the protected tunnel. Gateway observation must exclude Ethernet/MAC headers and all nonnonce packets at the kernel boundary; no broader capture to make tests easier.
- Read only selected pinned-peer mapping/session/counter metadata, resolver health and nonce arrival timestamps. No endpoints/public IPs, keys or unrelated peer/history output.
- The required protected endpoint is private DNS/port53, already verified from trusted. TCP22/5380 probes are supplementary; their trusted-positive baselines are not required by the specification or owner's corrected acceptance. No fresh trusted-client test is needed or authorized.
- Require affirmative test emission/path evidence and an attributable intended-boundary policy rejection before VERIFIED. Public success plus timeout plus zero nonce arrival is **not** proof of where/why it stopped. It could reflect local route failure, a dead path or another firewall. A boundary-generated, test-correlated administrative rejection or existing narrowly filtered deny event can supply causal evidence; generic connection-refused/RST without boundary provenance does not.
- No guest edge/router login, administration or Pi probing is authorized; no logging/firewall/route changes to manufacture causal evidence. If existing read-only observations cannot expose a positive boundary witness, report NOT VERIFIED with the missing witness, even if behavior is consistent with isolation.
- Once the single attempt is classified, stop/verify cleanup, expire the grant and report each of the five objectives separately. Guest VERIFIED requires all of them, not silence alone. Never alter the already-verified trusted status.

Independent neutral reviews agree that public positives + private timeouts + destination non-arrival do not establish intended-boundary rejection. Their suggestions to infer a policy from a generic RST or broaden traffic collection are not accepted.

## Human actions required

Stay connected to Beryl's **guest** network. In your Mac Terminal run exactly once:

```sh
python3 /Users/claw/flowstate/repos/21pins/scripts/beryl-guest-synchronized-proof.py --owner-run
```

Do not run the trusted wrapper. This command uses the existing management identity/strict host pins, prepares exact-nonce witnesses on the gateway and resolver, checks clocks/readiness and prints **`observer ready / RUN GUEST TEST`** in Terminal immediately before automatically running your guest client test. Pi never launches it live. Both collectors stop/clean before the final JSON; the one-use grant is consumed even on failure. No automatic retry.

Paste only the final JSON line including `classification` and `observer_cleanup_verified`. Never credentials, raw logs/packets, profiles, MACs or public IPs. If it fails or cleanup is unverified, send that JSON and do not rerun. Expected result either identifies private access/leakage or reports the specific evidence missing for full guest VERIFIED. The current classifier deliberately cannot claim full VERIFIED from silent drops alone.

## Observer implementation and pure checks

Gateway capture uses protocol0 AF_PACKET/SOCK_DGRAM, installs exact-nonce IPv4 kernel filters BEFORE binding only `wg0`/ETH_P_IP, and receives network-layer bytes with `recv()` (no Ethernet header or sockaddr MAC metadata). Fail closed unless sysfs interface type is ARPHRD_NONE65534. No promiscuous mode or policy changes. Resolver capture retains exact-nonce AF_INET filters; both record actual start/end epochs to require full overlap for negative observations. Nonce may expose guest default-DNS proxy traversal as well as direct private attempts.

Two independent abstract reviewers accepted cooked/MAC-free tunnel capture and Python host-order bind protocol; existing dynamic IP/TCP offsets and Linux NULL-buffer purge already address framing/queue concerns. No broader tuple-only capture is used to recover segmented TCP queries.

Offline checks only (no guest/trusted client or network simulation):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_beryl_guest.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_beryl_synchronized.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/beryl-query-observer.py --self-test
```

Trusted-network proof remains VERIFIED and is not rerun.
