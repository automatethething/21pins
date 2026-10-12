# SSH Work Leases Implementation Plan

> Execution: controller is the sole repository writer; cmux Claude/agy receive abstract independent reviews only. Owner explicitly authorizes execution through isolated verification, not production trust installation.

**Goal:** temporary objective-bound authorization measured in hours, direct OpenSSH credentials measured in minutes, with no SSH proxy or host daemon.

**Architecture:** replaces the Teleport-only proposal. An opt-in Go module uses existing app-token identity and dedicated SSH scopes, immutable host/role/key/objective leases, native ssh-keygen signing, and locked atomic metadata. Client keys remain in private client cache. Existing policy and receipt concepts are reused; monetary approval does not approve SSH privileges. Explicit local/dev CA mode or native SSH-agent-backed production signing keeps CA private material out of application state.

**Stack:** Go standard library, native OpenSSH, Node standard-library harness adapter. No new dependencies.

- [x] Test first: lease/role policy/state transitions, immutable renewal, expiry, public key validation, signer options and secrets exclusion (`internal/sshaccess`).
- [x] Implement cross-process locking/atomic metadata and immutable config checks; review architecture/threat model with Claude before finalizing.
- [x] Implement explicit dev CA/native SSH-agent signer, unique serial allocation, cert deadline/principals/extensions.
- [x] Test and implement loopback/no-CORS `/v1/ssh/leases` API, using fail-closed exact SSH scopes and unambiguous native-token identity; no broad proxy-scope promotion.
- [x] Test and implement CLI (`cmd/21pins/ssh.go`), separate per-lease ephemeral key cache, strict direct SSH, lease close and key cleanup.
- [x] Implement public-only reviewable bootstrap bundle and real isolated trust/config validation; owner runbook covers actual installation/reload/rollback, never automatic production installation.
- [x] Implement `npm/lib/ssh-harness.mjs` objective lifecycle adapter; one writer, worker continuity, terminal-event/signal cleanup, no detached renewal.
- [x] Run all Go tests/vet/race, Node lifecycle tests, and isolated real sshd acceptance/security tests. Repair and rerun failures.
- [x] Write four required SSH guides/threat model, update superseded design and dashboard/portfolio status, security-review abstract actual implementation boundaries with cmux.
- [x] Verify all owner completion criteria and prepare scoped local commit; report isolated dogfood readiness without installing production trust.

Final evidence: all Go tests/race/vet and 7 Node tests pass, including the actual Pi loader and accepted owner-blocked lifecycle. Fresh real isolated sshd/API-only CLI/Node smoke verifies host-role-user isolation, forwarding denial, same-key renewal, closed-lease issuance denial, expired reconnect denial, deliberate established-session survival and local key deletion. Unconfirmed closure retains retry metadata; restored objectives cannot execute and Pi retries termination. Claude and agy final independent abstract reviews both APPROVE with no concrete blockers (not private-source inspection).

Commands always run from the exact repo; each foreground command/wait is capped at 120 seconds. SSH fixture work uses synthetic keys, fixture homes and loopback only; no real credentials, other accounts, production targets or existing account-owned services are accessed. The synthetic forced-command sshd fixture uses only the current OS account. Owner production trust bootstrap remains a separate gate.
