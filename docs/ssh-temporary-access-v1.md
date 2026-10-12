# Temporary SSH access V1

Give an AI agent temporary SSH access without giving it permanent credentials.

**The authorization can last hours while the underlying SSH credentials last minutes and renew automatically.**

## Architecture

21pins is the authorization/credential-lifecycle control plane. The client creates one ephemeral Ed25519 key per lease and submits only the public key. A workspace-specific CA signs short-lived native OpenSSH user certificates. SSH connects directly from client to host; no traffic, commands, environment, keystrokes or terminal recording passes through the authorization API. There is no Wafers integration, SSH proxy, target daemon or target callback.

This implementation supersedes the earlier Teleport-only design. The current repository is a Go CLI/gateway with private local JSON state, not a hosted application database or production secret vault. It reuses existing app-token identity and atomic private-file patterns. SSH has separate exact permissions and approval semantics: a monetary approval or `proxy:*` token is **not** SSH authority.

## Two lifetimes

- Lease: immutable requester, agent class, host, role/Unix user, objective, purpose, public-key fingerprint and hard authorization deadline. Estimate is advisory. Policy determines default/maximum window; approval reviews the exact deadline. The window starts at opening, so delayed approval does not silently extend it.
- Certificate: default 15 minutes, renewal threshold 5 minutes; configurable role ceiling. `valid_before = min(now + min(cert_ttl, role.max_cert_ttl), lease.hard_expires_at)`. Clock skew affects only `valid_after`, never extends expiry.
- Renewal is on demand before SSH execution, within the same ACTIVE lease, reusing its key. No periodic detached renewer or heartbeat is needed. A long model call can finish and the next authorized SSH operation obtains a fresh certificate without another approval. Renewal never extends the lease or changes scope.

States: PENDING_APPROVAL → ACTIVE → COMPLETED/CANCELLED/REVOKED/EXPIRED. Pending requests can also terminate. Expiry is checked on every authorization/status operation, not trusted from a stale saved status. BLOCKED/LOST_CLIENT are termination reasons. New objectives use new keypairs; retrying the identical public-key request returns the same live lease, not a new window.

## Setup (local development)

Use a separate, throwaway state path for synthetic tests. Never reuse a real provider-key state file for fixtures. All synthetic secrets must be captured into private local files, not chat/logs.

```sh
go build -o ./21pins ./cmd/21pins
./21pins ssh ca init --dev
```

`--dev` explicitly permits a filesystem CA in a private 0700 directory with a 0600 private key. It is not the production default. Without an initialized SSH configuration the gateway's SSH surface is disabled.

Create distinct local app identities using existing `token create`: an agent with `ssh:use`, and an administrator with `ssh:approve`. Capture each one-time credential directly into a private owner-only file. Point `PINS21_SSH_TOKEN_FILE` to the required file (preferred); `PINS21_TOKEN` is also supported. Never give the administrator credential to the agent or submit it to a model.

Owner/admin registers a logical host/role without contacting the host:

```sh
21pins ssh host add devbox --role observe --user agentdev --requester pi \
  --default-lease 4h --max-lease 8h
```

Default is explicit approval. `--preapproved` opts in only the exact requester/host/role. New observe registrations are command-gated and permit only `status`, `platform`, `identity` with fixed argv. Gated roles disallow root, PTY and forwarding; different roles require different Unix users. Other roles require an explicit reviewed `--command-allowlist` JSON rule-array file. Policy changes invalidate renewal and signed rule digests prevent silent target-side broadening. See [command boundary](ssh-command-authority.md).

Start the existing issuer gateway with `21pins serve --ssh-dir <private-ssh-config-dir>`. Requester CLI commands use its loopback API (`PINS21_SSH_API_URL`, default `http://127.0.0.1:8787`); they never open issuer/provider state, load a CA reference, or sign locally. Only CA initialization and host-policy/bootstrap commands are local owner operations on the issuer.

Open and review:

```sh
21pins ssh open --host devbox --role observe --objective verify-service \
  --purpose "verify synthetic development service" --estimate 45m
21pins ssh status <lease-id>
21pins ssh approve <lease-id>
21pins ssh exec <lease-id> -- platform
21pins ssh complete <lease-id>
```

Administrator status/review can inspect the pending immutable scope. `approve` asks for `approve` confirmation; `--yes` represents an explicit administrator decision for scripted approvals. Requesters cannot approve their own lease. For immediately preapproved leases, no separate approval step is needed. Pending leases keep the same client key while awaiting approval.

## Private configuration

On the issuer, `PINS21_SSH_DIR` overrides the default sibling `ssh/` directory beside the existing 21pins state file. Its `config.json` and metadata are private 0600 regular files. `PINS21_SSH_RUNTIME_DIR` overrides the client cache directory. Never make either directory shared or symlink-backed.

Example role policy (durations are configurable, not architectural constants):

```json
{
  "ssh_user": "agentdev",
  "default_lease": "4h",
  "max_lease": "8h",
  "max_cert_ttl": "15m",
  "requesters": {"pi": "preapproved", "claude": "approval"},
  "requester_max_lease": {"pi": "4h"},
  "explicit_approval": false,
  "permit_pty": false,
  "permit_port_forwarding": false,
  "permit_agent_forwarding": false,
  "permit_x11": false,
  "command_authority": {
    "binary": "/usr/local/bin/21pins",
    "policy_file": "/etc/ssh/21pins/commands.json",
    "allow": [
      {"command": ["status"], "exec": ["/usr/bin/uptime"]},
      {"command": ["platform"], "exec": ["/usr/bin/uname", "-s"]},
      {"command": ["identity"], "exec": ["/usr/bin/id", "-u"]}
    ]
  }
}
```

Use `explicit_approval: true` for higher-privilege roles. Preapproval cannot bypass it. Dedicated accounts, exact root-owned helpers/sudo rules and filesystem/network policy remain host responsibilities; the gate never grants root shell. Native options start denied (`-O clear`), then only the exact role gate critical option is added. Gated roles have no PTY/forwarding extensions or user rc. Privileged fixed-peer operations are [future design only](ssh-dns-admin-design.md).

### Authentication versus command enforcement

The original authentication-only observe policy permitted arbitrary Unix-account commands; **it is superseded for production/dogfood**. Native principals alone, no-sudo, no PTY and disabled forwarding still do not enforce executable policy.

Current gated observe signs an exact critical force-command (extensions none), emits matching principal `command=...,restrict` plus account ForceCommand, and executes only a root-owned exact operation allowlist through the installed target gate. The verifier accepts only the expected exact critical-option encoding. Gate scope binds workspace/host/role/Unix user/rules digest, not hostile requested commands; direct shell/subsystem/unknown/altered-argument requests fail closed. Purpose remains immutable approval/audit/renewal metadata, not command-content interpretation.

Target shell/startup environment, root-owned artifacts and effective native configuration are mandatory pre-install checks. Allowed fixed executables are reviewed trusted code, not a universal process sandbox. Production agent CA configuration without command authority is rejected. Legacy authentication-only signer fixtures remain explicit development tests (`--legacy-auth-only` for old CLI fixture), never production observe. See [command authority and tests](ssh-command-authority.md).

Host principals: `21pins:<workspace-id>:<host-id>:<role-id>`. Each host/Unix user accepts only its own configured principals. Never reuse a logical host ID for a different physical host. A different host with the same workspace CA rejects the certificate unless its administrator has incorrectly installed that other host's principal.

## Production CA boundary

There is no production secret vault in the existing repo; the CA private key is **not** stored in its provider-key or signing-key JSON fields.

```sh
21pins ssh ca init --agent --public-key /owner-managed/workspace-ca.pub \
  --agent-socket /owner-managed/dedicated-signer.sock
```

The owner loads the CA into a separately managed native signing agent. 21pins uses `ssh-keygen -U` against that socket and holds only a public-key reference/fingerprint. It never reads a production private-key file. Client SSH processes strip agent sockets and use `IdentityAgent=none`; the signing agent is never forwarded to a target. Managing/loading a real CA is an owner-only action, not part of the synthetic build smoke. CA rotation/recovery is described in the threat model.

## API

Opt in: `21pins serve --ssh-dir <private-ssh-config-dir>`. SSH routes are loopback-only, reject browser Origin, have no CORS, bounded strict JSON bodies and sanitized errors. Ordinary provider routes do not receive SSH authority.

- POST `/v1/ssh/leases`: host_id, role_id, agent_class, objective_id, purpose, public_key; optional estimated_duration/max_duration. Returns immutable lease fields and certificate/issuance metadata if immediately approved.
- GET `/v1/ssh/leases` and `/v1/ssh/leases/:id`: requester-owned leases; administrator review permission can inspect them.
- POST `/:id/approve`: dedicated administrator permission, never self-approval.
- POST `/:id/certificate`: public_key only; all scope comes from the immutable lease.
- POST `/:id/complete`, `/:id/cancel`, `/:id/revoke`: revoke requires administrator permission.

Authentication is derived from the validated app credential, not an input requester. Duplicate active app names, revoked credentials and unreadable/corrupt auth state fail closed. No new database/auth service is introduced.

## Important limitations

**Complete/revoke stops new signing immediately. It does not erase previously issued certificates on other machines. A copied key+certificate can reconnect until certificate expiry. An already-established session or detached remote process may survive expiry.** The harness closes its local sessions and unlinks local key material; that is best effort, not host-side instantaneous revocation or physical secure SSD erasure.

Strict host-key verification is always on, connection sharing is off, and one-shot `ssh exec` is preferred. The CLI resolves an existing local SSH alias, then invokes a clean direct OpenSSH configuration with the allowed hostname/port/known-host paths only; proxy/jump/forwarding/local-command settings are not inherited. `PINS21_SSH_CONFIG_FILE` selects an explicit local alias configuration (used by fixtures). No host address goes into lease/API/audit metadata.

Metadata records only lease identity/scope/deadlines/state and certificate serial/fingerprint/validity. No certificate bodies or private keys are stored in the backend. Native certificate output is cryptographically verified before return. A serialized bounded file lock and reserved monotonically increasing serial avoid cross-process duplicate issuance; failures consume serials. Current authorization and live policy are rechecked before signing and again before delivery, so revocation/configuration change or expiry during signing yields no delivered credential. Preserve the metadata high-water mark with CA backups; rotate the CA after state loss rather than resetting serial history. Metadata has a 16 MiB fail-closed capacity guard; database/retention automation is not included in V1.

See [host bootstrap](ssh-host-bootstrap.md), [harness integration](ssh-harness-integration.md) and [threat model](ssh-threat-model.md).
