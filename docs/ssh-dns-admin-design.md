# Future dns-admin: one Beryl WireGuard peer on VM 220

**DESIGN ONLY.** No account, sudo entry, helper, network config or VM 220/221 mutation is performed. `dns-admin` is the owner's requested role name; this scope does **not** grant general DNS administration, network CLI access, interface restart or root shell.

## Precisely bounded future authority

Separate Unix account `pins-dns-agent`, dedicated `dns-admin` principal bound to VM 220's logical host, new command policy version and explicit approval. Do not map observe and dns-admin to the same OS account. Proposed lease: default 15 minutes, hard ceiling 30 minutes, short certificates ≤5 minutes, no requester preapproval. Purpose specifies enrollment/verification; permissions are the explicit role operations, not inferred by the gate from purpose text.

| Literal operation argv | Fixed privileged helper invocation |
| --- | --- |
| `beryl verify` | `/usr/bin/sudo -n /usr/local/libexec/21pins-beryl-peer verify` |
| `beryl enroll` | `/usr/bin/sudo -n /usr/local/libexec/21pins-beryl-peer enroll` |

No client arguments pass through. `wg`, `ip`, `resolvectl`, shells, scripts, alternate peer IDs, extra flags, endpoints/keys/CIDRs/paths/commands and helper bypass do not have rules. Once implemented, target sudoers must permit **only the two exact helper+subcommand entries**, never wildcards, arbitrary arguments, environment preservation or sudo wg/shell. Avoid overlapping group/sudo rules and independently inspect `sudo -l -U pins-dns-agent`.

The root-owned helper and every ancestor are non-writable to the requester. It rejects every argv except a single exact operation and checks root execution. It reads a separate root-only, immutable reviewed pin manifest containing:
- One intended interface, one Beryl public-peer identity and one fixed host resource; no host/interface/peer selector from the requester.
- Exact nonoverlapping permitted IPv4/IPv6 ranges, expected route policy and any endpoint/keepalive values genuinely required by the chosen topology.
- Approved persistence file and its ownership/version; private WireGuard/preshared keys remain in root-only storage, never lease metadata, argv, stdout or repository artifacts.

Actual values must be reviewed locally by the owner later; this document intentionally contains no real keys, endpoints, addresses or infrastructure inventory. The helper uses native tools with fixed argv and explicit clean environment, local locking, bounded runtime and safe parsed results. Never log raw `wg show ... dump` or configuration. Output only allowlisted statuses (pinned peer present, approved ranges match, recent handshake boolean/age bucket and conflict/rollback result); do not expose keys, peer addresses or private configuration.

## Safe enrollment transaction

1. Validate manifest, ownership, expected interface and **one** peer identity; reject overlapping ranges, conflicting existing peer definition or unrelated drift. Do not infer policy or automatically take over another peer.
2. Acquire a scoped lock; securely snapshot only required rollback state locally, mode 0600, bounded retention. No private state leaves the root helper.
3. Make the minimum idempotent update for the pinned peer only; never delete/replace other peers, change interface keys or broad routes/firewalls/resolver config. Persist atomically only at the approved path.
4. Verify intended peer/ranges in live and persistent state. A successful enrollment does not fabricate a handshake: report `configured; handshake not yet observed` if the peer has not connected.
5. On failure restore this transaction's peer/persistence change, verify restored state and remove temporary sensitive material. Fail closed on rollback/validation failure; no partially successful claims.

Verification is read-only and independently compares pinned live/persistent state plus handshake freshness. Enrollment affects networking and persistence and therefore needs a separate narrow reviewed owner-approved installation/change objective, not merely an SSH lease. A lease controls credential issuance, not human authorization for production/network mutations.

## Future release gates

- Isolated fake/native tool tests: wrong peer/interface/ranges, extra args/environment, symlinks/permissions, unrelated-peer preservation, idempotence, concurrent actions, tool failure, rollback and redacted outputs.
- Real target preflight and approval: helper pins and exact sudoers; root-owned gate/policy/principals; current native effective environment/ForceCommand/certificate options; unchanged recovery accounts and tested rollback.
- After explicit dogfood approval only: positive verify/enroll for pinned synthetic or intended peer, all privilege/scope negatives, authoritative configuration and real fresh handshake evidence when available.
- Distinct role approval, signer/principals/ForceCommand policy digests and short-cert lifecycle preserved. Already issued credentials/established channels can remain useful until normal residual windows; helper must be safe and idempotent every invocation.

This design intentionally adds no general privileged executor. The future helper implementation and its owner-selected pins are prerequisites, not work claimed complete today.
