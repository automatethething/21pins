# Owner-started trusted Beryl correlation

The owner successfully ran this workflow at14:19:28–14:19:31Z on2026-10-13. Trusted-network E2E is VERIFIED; see `beryl-trusted-correlation.md` for exact nonce/arrival/peer/policy/cleanup evidence. It was never run by Pi. The one-use grant is now expired and guest isolation remains unverified/unauthorized. The command below is retained as historical procedure, NOT authorization to rerun.

## Human actions required

On the same Mac, connected to Beryl's **trusted** network, open Terminal and run exactly once:

```sh
python3 /Users/claw/flowstate/repos/21pins/scripts/beryl-synchronized-proof.py --owner-run
```

The command requires the existing `fipi` management SSH identity/strict host pins and existing private owner manifest; do not copy or paste any credentials. It prints `observer ready / RUN NOW` only after actual matching kernel-filter readiness, then automatically executes the client proof YOU launched. There is no chat round trip or second command before the client begins.

Paste only the final JSON line, including its `correlation` and `observer_cleanup_verified` fields. No raw logs, packets, keys, tokens, profiles, MACs or public IPs. Expected passing evidence: nonce UDP/TCP arrival, overlapping UTC timestamps, pinned-source mapping plus fresh peer traffic/recent authenticated handshake, successful allowed/public controls, explicit policy-generated Blocked/Filtered EDE on UDP and TCP, and verified observer cleanup. If any field is false, the outcome is NOT VERIFIED; do not rerun without a new single-attempt grant. If cleanup is unverified, report that JSON rather than starting another collector.

## Sequence and ceilings

1. Check for an existing ready/stop marker; fail closed, never delete somebody else's collector state.
2. Read only root-pinned peer mapping, transfer counters and latest handshake; raw identities/table remain server-local.
3. Generate one64-bit test nonce. Start85s passive observer through the already-authorized fixed management route; root kernel filter matches private tuple and **entire exact nonce**, not all synthetic traffic. No Ethernet/MAC capture, arbitrary query selectors, logs/history or raw output.
4. Read matching exclusive0600 root readiness marker. Reject startup exceeding20s or detectable client/server clock mismatch. Only then immediately launch owner client proof, capped45s.
5. Client public DNS/HTTPS and private allowed/challenge controls are unchanged. Blocked-control responses are decoded from connected UDP/TCP DNS with explicit EDNS OPT, transaction/question validation and bounded response parsing. Old macOS `dig` may omit EDE text; binary decoding avoids conflating that display limitation with missing policy evidence. NXDOMAIN alone still never passes filtering.
6. Matching exclusive/no-follow stop marker ends observation. Close sockets and remove owned root ready/stop files; read pinned-peer post-state. Output only test results, nonce counts/epochs, peer deltas/handshake and booleans, no absolute traffic totals or raw DNS bodies.

Main execution100s + bounded cleanup≤15s; collector85s, fixed guest93s, client45s, all subprocess waits≤120s. No daemon, timer rearming or automatic retry; no configuration/trust changes. No temporary local output/credential files. A canceled/failed SSH cleanup is explicitly unverified; remote observer still has its own85s ceiling. Ctrl-C stops the attempt and requests collector closure.

## Evidence limits

Positive peer counter deltas alone are not attribution: management or other traffic can contribute. Exact nonce source-bound UDP/TCP arrival, test timestamps and successful owner responses are mandatory. A new handshake timestamp is not forced; a recent authenticated session with new traffic is sufficient session-liveness evidence. This is private-source/pinned-peer operational correlation, not cryptographic attestation of a physical client behind the router.

TCP DNS query segmentation can make the strict kernel nonce filter miss a query. Do not broaden capture to unrelated traffic to compensate: that result is NOT VERIFIED, not a proven network failure. A resolver that does not return explicit EDE remains policy-UNVERIFIED; no false claim of missing filtering and no automatic policy/config change.

## Offline checks (no client/network proof)

```sh
python3 scripts/test_beryl_synchronized.py
python3 scripts/beryl-query-observer.py --self-test
python3 scripts/beryl-client-proof.py --self-test
```

These are synthetic parser/filter/correlation checks, not a simulated or actual Beryl client proof. Pi must never invoke `--owner-run` or the live client helper.
