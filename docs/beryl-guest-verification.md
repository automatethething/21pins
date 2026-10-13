# Guest isolation — authorized, NOT yet tested

Trusted-network E2E remains VERIFIED. The owner authorized one separate read-only guest attempt, with no configuration/trust/policy changes and no trusted-client rerun. No guest observer or client test has been started; this new grant is unconsumed.

## Blocking execution-mode requirement

The requested chat readiness signal followed by an observer remaining active until an arbitrary later owner test/stop conflicts with the mandatory120s ceiling for tool/workflow/background execution. Do not launch another expiring chat-dependent capture, an uncapped daemon, or silently re-arm windows. The safe alternative is the same **owner-started synchronized workflow** used successfully for trusted: prepare server witnesses, owner switches to guest and launches one command, command confirms actual readiness then immediately executes the OWNER's guest client test, classifies and cleans within the bounded attempt. Owner selection is required because the latest guest request explicitly specifies the incompatible chat-first indefinite lifetime.

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

In this Pi chat reply **`Use the owner-started synchronized guest workflow`** to select the bounded, no-chat-delay execution mode. Pi will then prepare the exact guest-only owner command and honest evidence gates; do NOT run the trusted wrapper or any guest probes yet. No credentials, raw logs, packet dumps, MACs or public IPs should be pasted. Expected next signal is a prepared command whose owner execution confirms actual readiness immediately before the guest client test, not a claim an idle observer is already running.
