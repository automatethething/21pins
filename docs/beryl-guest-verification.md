# Guest isolation — authorized, NOT yet tested

Trusted-network E2E remains VERIFIED. The owner authorized one separate read-only guest attempt, with no configuration/trust/policy changes and no trusted-client rerun. No guest observer or client test has been started; this new grant is unconsumed.

## Prepared owner-started execution

Owner replied “ok I'm connected to the guest network” after the synchronized guest-workflow proposal. The guest-only owner command is now prepared and offline-tested, NOT run by Pi. It uses the same no-chat-delay synchronization that worked for trusted: two server witnesses are armed first, actual matching kernel readiness confirmed, then the owner's client executes immediately. No idle indefinite collector or silent window rearming. Main95s+cleanup≤20s, each remote observer85s; all operations below120s.

The diagnostic can detect private reachability/protected-path leakage. Without affirmative boundary-denial evidence and trusted-path admin-target baselines, **negative behavior remains NOT VERIFIED**, not a policy pass. Those missing capabilities are explicit in the final classifier; no configuration change or synthetic substitute manufactures them.

## Evidence criteria / preparation plan

- Owner attests actual guest network; public DNS/HTTPS positive controls must succeed.
- Use one pre-generated exact nonce for direct private DNS UDP/TCP attempts and default-DNS challenge, including potential guest DNS-proxy leakage. Record bounded transport/error/control results, never raw replies or unrelated data.
- Observe the exact nonce at BOTH the pinned peer's decrypted gateway interface and intended resolver. A resolver-local raw socket alone can miss packets dropped by the resolver host firewall, so it cannot establish that no query traversed the protected tunnel. Gateway observation must exclude Ethernet/MAC headers and all nonnonce packets at the kernel boundary; no broader capture to make tests easier.
- Read only selected pinned-peer mapping/session/counter metadata, resolver health and nonce arrival timestamps. No endpoints/public IPs, keys or unrelated peer/history output.
- Protected-destination negatives count only for destinations with real trusted-path positive evidence. Trusted DNS is already proven; do not invent trusted reachability for admin ports merely because their services listen or bastion access works. No fresh trusted-client test is authorized.
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
