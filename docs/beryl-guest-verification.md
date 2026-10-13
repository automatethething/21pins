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

Existing evidence DOES close the trusted **DNS** baseline: real trusted UDP/TCP allowed replies plus source-bound query/service/policy proof at14:19. It does NOT supply trusted direct-client TCP22/5380 positives. The native VM220 SSH certificate smoke uses the management bastion, not the Beryl trusted-client path; service existence or listening sockets would not supply that missing baseline either.

A narrow local report/record lookup found only the known private-DNS topology report, no Beryl/guest-specific policy report. Existing known local topology report contains server INPUT/FORWARD-drop/DNS-source-ACL evidence, but no guest nonce/window, UCI command or Beryl firewall-config export. It is not Beryl guest-edge policy/counter evidence. Known narrow owner transcripts contain the explicit no-Beryl-SSH/admin/probe restriction and no existing router-policy export. Installed21pins has no Beryl host; its WG role only enroll/inspect and DNS role fixed query/test/status/missing-proof literals cannot retrieve Beryl guest rules, routes or counters. No already-authorized Beryl policy-reading mechanism is evidenced. No router access or new management trust was attempted.

Thus the two remaining gaps are NOT closed by available evidence:

1. A deterministic intended-boundary witness tied to this test (matched guest→private/WG reject rule and test-correlated deny event/counter delta, or equivalent attributable rejection). A policy toggle/rule existing today or a cumulative counter without the test's before/after/flow association is not sufficient.
2. Trusted direct-client TCP reachability for the relevant protected admin ports, or documented removal from scope because they are not actually trusted-reachable targets. DNS-port positives and bastion SSH success cannot be relabeled as admin positives.

**No synchronized full rerun is justified yet.** First obtain already-existing historical boundary evidence if it is available through the owner's existing management UI. If it closes gap1, only a narrow owner-run trusted TCP22/5380 baseline is additional live evidence; no DNS E2E or guest rerun is needed. If no historical test-linked boundary record exists, one newly authorized, minimal guest rejection probe under observation of an EXISTING matched rule/counter is required; do not repeat the full suite or enable/change logging/policy merely to make it pass. If relevant admin ports are also blocked from trusted, choose genuinely trusted-reachable protected targets rather than manufacturing a positive baseline.

## Current Human actions required

Use your existing Beryl management interface in read-only/view mode, its guest→private/WireGuard firewall/routing policy and existing deny/audit history, to determine whether it retains a matched reject/route decision for the14:54:03–14:54:09 test. Share ONLY minimized rule identity, guest/private direction, action, timestamp and a test-specific match/count (not raw logs, credentials, addresses, MACs or unrelated traffic). If you want Pi to perform that inspection, explicitly identify and authorize the bounded read-only mechanism; no Beryl login/probe channel is currently authorized for Pi.

Do NOT run either synchronized wrapper again. Reply here whether a historical matched-rule witness is available and whether ports22/5380 are intended trusted-reachable admin targets. If those are intended trusted-reachable targets, the smallest additional live baseline is the following OWNER-only check while connected to Beryl's **trusted** network (no DNS test, login or guest rerun):

```sh
python3 - <<'PY'
import json,pathlib,socket
m=json.loads(pathlib.Path('/Users/claw/flowstate/repos/21pins/docs/ssh-technitium-manifest.json').read_text())
out={'owner_attested_client_network':'trusted','protected_admin_TCP':{}}
for port in (22,5380):
 try:
  with socket.create_connection((m['resolver'],port),timeout=2):ok=True
 except OSError:ok=False
 out['protected_admin_TCP'][str(port)]={'reachable':ok}
print(json.dumps(out))
PY
```

This is a TCP reachability observation only, not application login/health or a repeat of trusted DNS E2E. Send only its JSON; two positive results close the admin baseline gap. Any negative result means that port cannot be treated as a trusted-reachable isolation target without further evidence; do not change firewall/service policy to manufacture a baseline.

A new minimal guest rejection probe is only needed if the historical causal witness is absent, under fresh specific authorization and simultaneous read-only observation of an existing matching rule. No full synchronized client-suite rerun is automatically necessary. No secrets should be pasted, and no network/policy/configuration change is requested.

The procedure below is historical, not authorization to replay.

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
