# 21pins temporary SSH — integration-first v1

Status: specification for founder review; not implemented or authorized for deployment.

## Goal and decision

Give an operator one explicit, approved, time-bounded SSH session path to a registered development machine. 21pins requests access and records policy decisions; an existing broker authenticates, approves, issues credentials, enforces access, and disconnects sessions. Never claim that a client-side timer makes machine access temporary.

Three approaches considered:
- **Teleport integration (recommended):** existing broker-native Resource Access Requests, certificate expiry, server-side expired-certificate disconnect, and administrative locks. Requires a compatible, already-authorized deployment and entitlement.
- **Tailscale integration (deferred):** attractive transport, but `checkPeriod` is a reauthentication interval, not an access TTL. No equivalent automatic-expiry contract assumed.
- **Standalone OpenSSH certificates (rejected for v1):** certificate issuance is straightforward; reliable revocation and active-session termination would pull 21pins into infrastructure ownership.

No new broker provisioning, license purchase, identity-provider changes, production host configuration, or public exposure is authorized by this spec. Absence of a compatible broker blocks the integration pilot, not the existing 21pins product.

## Scope and trust boundaries

CLI-only, opt-in, disabled by default. No access HTTP endpoints on the existing LLM gateway. No CA/private-key storage, SSH implementation, tunnel mesh, browser terminal, terminal recording, broad fleet discovery, custom host daemon, autonomous bot credentials, or admin permissions in 21pins.

v1 uses the operator's existing native `tsh` login. Human-approved agent work can run inside that session under the same mapped operator identity; distinct unattended workload identities are deferred. The broker must independently enforce resource/login/expiry restrictions even when the operator invokes `tsh` without 21pins. Local 21pins policy checks are an additional admission gate, not an unbypassable host boundary.

Temporary shell access does not undo file writes, terminate every detached job, prevent in-shell network transfers, or sandbox data. Dedicated isolated development accounts, no root or sudo privileges, and no sensitive/production data are pilot prerequisites. Remote OS ownership/network controls enforce those constraints. Disable broker SSH agent/X11/port forwarding and SCP/SFTP; this does not prevent equivalent operations inside an allowed shell.

## Compatibility and doctor gate

Candidate minimum: Teleport Enterprise 18.9.0 with Resource Access Requests entitlement, matching supported `tsh`, and broker administrative lock support. This is a documented API baseline, not a tested compatibility claim. Implementation must select and pin an exact supported patch/client/server matrix and validate it before pilot enablement; do not deploy an old patch just to match this baseline.

`21pins access doctor ALIAS` validates binary provenance/version, trusted broker profile, authenticated subject binding, broker reachability, the exact enrolled node and OS login, relevant effective role configuration, and capability evidence. Required settings include `disconnect_expired_cert: true`, strict lock enforcement, capped certificate TTL, resource-only requests, and forwarding restrictions. Missing read access or unverifiable configuration is a failed check, not permission to assume defaults. Use an explicitly approved read-only configuration review if ordinary user APIs cannot expose effective settings; no broker admin credential is loaded into 21pins.

Passing doctor means prerequisites match a previously tested configuration, not that doctor has itself proved a live disconnect. Any cluster/version/role/resource change invalidates that evidence. Release requires the isolated end-to-end tests below.

## Proposed CLI contract

These are proposed 21pins commands, not commands that ship today:

```text
21pins access doctor devbox
21pins access machine add devbox --resource <broker-resource-id> --login dev
21pins access machine remove devbox
21pins access request devbox --grant <grant-id> --ttl 30m
21pins access status <access-id>
21pins access connect <access-id>
21pins access revoke <access-id>
```

Registration references an already-enrolled broker node; it never installs anything remotely or edits SSH configuration. Store an immutable machine registration ID plus broker-profile/cluster/resource/login binding. Validate aliases as bounded identifiers, not shell fragments. No wildcard resources, arbitrary host/IP input, arbitrary SSH arguments, remote-command passthrough, or insecure trust flags. Remove/re-add creates a new registration ID and invalidates old access records; alias reuse never redirects an existing approval.

TTL defaults to 15 minutes; integer range 5–60 minutes. Reject invalid or oversized requests rather than silently extending them. Broker constraints may shorten the approved duration; display the effective absolute expiry before connect. No automatic renewal.

## Request → approval → connect

1. Persist a local pending record and random correlation ID before submission. Evaluate the existing grant for verified subject, `ssh.connect`, exact immutable machine target, configured machine data class, active spend window, and zero request cost. Zero cost is not a spending or security exemption; infrastructure bills remain outside this feature.
2. Compare authenticated broker identity with the owner-approved mapping to the verified 21pins subject. No identity guessed from email/name or untrusted command output. Missing/mismatched identity blocks. Existing authority-chain checks are not proof of full delegation-chain enforcement; v1 allows owner-issued, nondelegated SSH grants only.
3. Submit a broker-native resource request as the operator, with the exact node, configured non-root login scope and duration. Approval occurs in the existing broker workflow; no auto-approval or reviewer role in 21pins. A dedicated least-privilege broker request role is a prerequisite; broader base roles or inherited access invalidate the pilot configuration.
4. Broker approval must bind authenticated user, exact resource, allowed login scope, request ID and maximum duration. Operator cannot substitute another login/profile/resource. Local policy grant and broker request are distinct objects; neither is exported as an SSH credential by 21pins.
5. After approval, obtain credentials through native `tsh`. Only allowlisted metadata enters 21pins: request state/identity/resource scope and verified certificate expiry. No reading, copying, printing, or persisting private credentials in 21pins.
6. Immediately before connect, re-check grant, immutable registration, doctor evidence, fresh broker approval/identity/status and actual credential expiry. Effective deadline is the earliest broker access deadline, credential expiry, and approved duration; cap from credential activation and never reset on reconnect. Pending approval has a separate short broker request lifetime; no waiting forever.
7. Persist a local decision receipt before invoking `tsh` through a fixed argument array, never a shell string. Terminal content remains in the operator's terminal, not receipt/log/analytics storage. Show: "SSH session expiry is not a sandbox: accessible data can be copied and detached processes can survive."

Broker status must prove the approved request's credentials are being used. Shared `tsh` profile races or cached broader credentials must not substitute a different identity/access request. If the selected client version cannot provide that guarantee, block until a supported native credential-context mechanism is verified; do not build a custom credential store.

## Expiry, revocation and emergency response

Broker enforces absolute expiry for new and existing SSH sessions even if 21pins exits, the workstation crashes, or its clock changes. Pilot acceptance: no reconnect after deadline and established SSH session ends within 10 seconds of broker expiry under tested conditions. Never substitute a local background timer.

`access revoke` immediately tombstones the local access record so 21pins cannot reconnect. It then reports `revocation_pending` and presents the existing broker administrator workflow for a confirmed server-side lock and session termination. It does not possess administrator credentials or promise one-command global revocation. Request deletion, `tsh logout`, local process termination, or dropping certificates do not prove remote revocation.

Administrative lock scope may be broader than one access record (user/resource). Display that scope before any action; do not invent per-grant locks unsupported by the selected broker. Emergency kill switch is the existing broker administrator workflow, with strict lock enforcement and independently verified session disconnection. Mark `revoked` only after fresh broker evidence confirms the intended lock and no affected active sessions. Unavailable evidence remains pending/unknown, never successful.

Revoking a 21pins policy grant blocks future 21pins connects but does not automatically revoke issued broker access or an open shell. Display the same native broker remediation workflow. Continuous policy re-evaluation inside an open shell is not included.

## Records, errors and recovery

Use a separate hardened local access metadata file; reuse atomic `0600`, non-symlink persistence patterns, not the provider-key store. Persist access ID, immutable registration ID, policy grant ID, pseudonymous subject reference, broker request/correlation ID, requested/effective deadline, observation time, local block flag and broker state. Keep topology local and out of public analytics. No arbitrary free-text reasons/logs; broker request reason uses a synthetic correlation reference only. Local receipts are decision records, not tamper-proof session auditing; broker audit events are authoritative. Retain completed metadata/receipts locally for 30 days, then prune; never delete active or unresolved-revocation records automatically.

States: pending, approved, denied, expired, revocation_pending, revoked, unknown. An approved request is connectable only after all fresh checks pass; a stale observation is not authorization. Grant/identity/config/persistence/status errors fail closed. Bound noninteractive operations to 30 seconds, approval polls to 60 seconds with explicit resume, and connection setup to 30 seconds; interactive session life is bounded by broker expiry. No long-running background workflow is required.

On timeout/crash after submission, reconcile by recorded correlation ID, requester and exact resource using supported broker request listing/search. Do not blind-retry issuance. If lookup is ambiguous, show unknown and require native broker resolution. Native broker expiry limits orphaned access. Concurrent create/revoke/connect must use one local access-state writer; atomically commit the tombstone before any further connects. Broker revocation remains necessary to terminate already-started sessions.

## Acceptance and release gates

Synthetic tests plus an isolated broker fixture must prove:
- Two identities/two nodes: no cross-subject, cross-node, alternate-login, alias-remap, wildcard or broader-base-role access.
- TTL cap, exact effective deadline, reconnect without renewal, approval delay, broker clock authority, and active disconnect after client death.
- Live-session administrative lock: disconnection and denied reconnect; local-only revoke stays pending until verified. Detached work caveat remains visible.
- Missing entitlement/version/config evidence, broker outage, denied approval, stale identity, revoked policy grant and expired certificate all block.
- Native credential-profile races, submission uncertainty and crash/save failure cannot issue duplicate or misbound access.
- No private credentials, raw native errors, terminal data or infrastructure identifiers leak into receipts, diagnostics or analytics; metadata permissions/symlink and concurrency checks pass.

Pilot is one existing broker, two isolated dev identities and two synthetic dev nodes; no production use, purchases, identity-provider reconfiguration or public deployment. Any production/privilege/trust expansion needs its own approval. Spec approval permits implementation planning, not those changes. No public temporary-access claim until all enforcement gates pass.

## Evidence and review

Existing repo: `internal/policy/types.go` and `engine.go` support grants, target/capability/data/spend evaluation and monetary approvals; these do not implement SSH risk approval, full delegation validation or session control. README/TODO and recent commits confirm a Go CLI/gateway with local grants, receipts and native identity handoff.

Public documentation consulted on 2026-10-12:
- Teleport CLI reference: https://goteleport.com/docs/reference/cli/tsh/ — Resource Access Requests and duration/certificate flags. Verify actual installed `--help` before implementation.
- Teleport role reference: https://goteleport.com/docs/reference/access-controls/roles/ — expired-certificate disconnect, strict lock and SSH forwarding options.
- Tailscale SSH: https://tailscale.com/kb/1193/tailscale-ssh — check period is not an access lifetime.

Independent cmux review on 2026-10-12: Claude approved the revised design with no concrete remaining blockers (91% confidence); agy explicitly returned APPROVE (98% confidence). Both agree on broker-enforced expiry/revocation and the honest local-wrapper boundary. Initial review corrections were incorporated: immutable registration, explicit doctor evidence, visible shell-risk warning, native administrator revocation, exact tested version/entitlement gate. agy's initial incomplete review followed fragmented multiline delivery; final agreement is based on a complete single-message resubmission, not that initial result.

No repo/source/private configuration is sent to advisory workers; they review a manually minimized architectural description. Agreement approves the specification's architecture, not an untested broker deployment or new owner authority.
