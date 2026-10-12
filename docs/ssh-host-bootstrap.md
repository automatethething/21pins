# SSH host bootstrap and dogfood plan

## What V1 does

`21pins ssh host bootstrap <logical-host> --out <private-review-directory> --dry-run` emits only:
- Workspace CA **public** key (`21pins-ca.pub`).
- `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` configuration fragment.
- One principals file per configured Unix user, exact principal with matching `command=...,restrict` for gated roles.
- `commands.json`: exact root-installable operation/executable argv policy. Dedicated Match blocks carry matching ForceCommand and restricted AcceptEnv. See [command policy](ssh-command-authority.md).

It does not connect to a target, create users, edit sudoers, install a private key, overwrite an existing CA, change a firewall or reload a real sshd. Existing output is refused rather than silently overwritten. Generate a fresh bundle for reconciliation, diff public files locally, and review changes. Host identity must not be reused for another physical host.

Optional validation: `--validate-config <locally-prepared-candidate-sshd-config>` invokes bounded native `sshd -t -f` after generation. This validates the caller's complete candidate, **not** an unmerged fragment or every target's effective policy. The real isolated fixture combines emitted files into its own sshd configuration and validates before starting.

Actual host trust installation is a separate owner/admin action. There is deliberately no implicit sudo/remote admin credential handoff. After installation, no per-lease host modification or callback is needed.

## Dedicated noninteractive account defense in depth

For a dedicated `pins-agent` observe account, use the exact proposed [restriction fragment](ssh-pins-agent-match.conf). Append its `Match User pins-agent` block at EOF of the reviewed main configuration, not an early Include where later global directives could fall inside Match. Keep public-key/certificate authentication enabled; disable ordinary authorized-key file/command lookup, alternate principal commands, PTY, all forwarding (including Unix sockets), tunnels and user rc. The revised fragment now also binds signed root-owned gate/user/rule digest, matching principal command option and target ForceCommand. Only status/platform/identity are allowed; no arbitrary commands or SFTP. This is not a universal data/process sandbox. The earlier VM effective-policy comparison did not cover this revised gate and must be repeated after separate approval.

Prefer scoping `TrustedUserCAKeys /etc/ssh/21pins/ca.pub` and `AuthorizedPrincipalsFile /etc/ssh/21pins/principals/%u` inside that same account's Match block rather than globally changing admin/recovery users. Validate keyword support, real public CA/principal contents and the complete candidate before any approved installation. `PermitUserEnvironment` is global-only on some supported systems; check effective `no` rather than placing an unsupported directive in Match.

Verify dedicated-account no-sudo with `sudo -l -U pins-agent` after separately approved account creation and before enabling trust/access; an absent account or policy error is not proof of denial. Keep it out of admin/sudo groups and privileged filesystem/service permissions. Re-run native per-account/context comparisons against the current configuration and verify real certificate/PAM account eligibility. The account restrictions intentionally prohibit interactive PTY even if a certificate mistakenly grants it.

## Trust installation checklist (Linux example; owner only)

1. Select a non-production test machine and a dedicated, least-privilege Unix account. Establish and verify its host key independently. Keep an existing admin session and console/recovery route open.
2. Review generated public CA fingerprint, unique host identity, role/user mapping and intended privileges. Never copy the signing-agent socket, CA private file, agent private key or tokens to the target.
3. Back up the existing sshd configuration and current CA/principals files to a root-only directory. Record an exact rollback procedure. Review existing `TrustedUserCAKeys`, includes and Match blocks; do not blindly replace a previously trusted CA or assume repeated directives merge.
4. Merge the fragment into the candidate configuration. Example final paths (use `pins-agent` for the dedicated-account review):
   - `/etc/ssh/21pins/ca.pub` (root-owned public CA file).
   - `/etc/ssh/21pins/principals/pins-agent` (root-owned public principal allowlist).
   - For a dedicated agent account, `TrustedUserCAKeys /etc/ssh/21pins/ca.pub` inside its Match block.
   - `AuthorizedPrincipalsFile /etc/ssh/21pins/principals/%u` in that same block. Do not globally change existing recovery accounts.
5. Build static target gate (`CGO_ENABLED=0 go build -o 21pins ./cmd/21pins`), verify provenance, install root-owned `/usr/local/bin/21pins` mode 0755 and `/etc/ssh/21pins/commands.json` mode 0644. Require trusted `/bin/sh`, root-owned empty HOME, no user-controlled shell/PAM startup and effective AcceptEnv only `21PINS_UNUSED`; keep PermitUserEnvironment no. Validate gate/policy/executable ancestor ownership and paths. Install public files with root ownership, directories 0755 and files 0644; writable only by administrators. Preserve existing trust or explicitly approve its replacement. Disable normal authorized-key/password access for the dedicated account if the temporary-cert property must be exclusive. Never disable other users' recovery access.
6. Validate the complete candidate with native `sshd -t -f <candidate>` and inspect effective configuration for the test account using `sshd -T -C ...` with locally supplied synthetic/test connection context. Do not paste raw diagnostics or real addresses into chat.
7. Atomically install the validated configuration, run `sshd -t` again, and reload the existing service with its platform-native reload operation (for example `systemctl reload sshd`, or `ssh` on distributions using that unit name). Do not restart blindly. Keep the admin connection open.
8. Prove fresh allowlisted `platform`/`status`/`identity` operations, then deny wrong role/user/host, tampered/missing force policy, policy digest drift, unknown/altered argv, shell/chaining/substitution, direct gate invocation, SFTP/PTY/forwarding and raw permanent keys. Compare native signed force-command, principals command and server ForceCommand exactly. Confirm existing recovery contexts unchanged.
9. On failure, restore the backed-up files, validate with `sshd -t`, reload, and verify the original recovery path. Do not lock out the owner while diagnosing.

These steps are a reviewable plan, not authorization to mutate production sshd trust.

## Isolated acceptance fixture

```sh
PINS21_SSH_INTEGRATION=1 go test ./internal/sshaccess \
  -run 'TestIsolatedCommandAuthority|TestIsolatedOpenSSH' -count=1 -v
```

Runs unprivileged temporary sshd instances bound only to loopback, with synthetic CA/host/client keys. The new test uses the actual signed gate, emitted principal command option, matching server ForceCommand and rules digest; V1 lifecycle retains explicit legacy authentication fixture containment. It uses the current OS account **only inside this forced-command fixture**, not as a recommendation for real infrastructure accounts. It does not modify system/user SSH configuration or contact other accounts/services. StrictModes is disabled only because fixture files are not root-owned; production must keep strict ownership validation. Modern OpenSSH source-penalty rate limiting is disabled only in the fixture so intentional negative auth tests do not suppress subsequent positive tests.

The fixture proves native CA signing, public-only CLI bootstrap, host/role/user isolation, agent and TCP forwarding denial even when the fixture server otherwise allows them, same-key certificate renewal, completed-lease issuance denial, expired reconnect denial and survival of an already-open session. It also runs the built CLI and real Node harness to verify repeated execution/renewal, objective completion and private-key deletion.

Prerequisites: Go, OpenSSH client/keygen/sshd/agent, Node; the test uses no Docker daemon, root, real credentials or production target. Every subprocess is bounded, and temporary server/agent processes/files are removed.

## First real dogfood run (not performed by the build)

Owner decision: choose one existing non-production test host/account and approve the reviewed one-time CA trust installation. No production target is selected or configured by this build.

Then:
- Restrict one preapproved observe/staging role to the intended harness; keep higher privilege explicitly approved.
- Start a project-scoped Pi session with the supplied extension; establish a single objective and open its host/role lease.
- Execute a harmless synthetic command repeatedly across a certificate boundary; show the public-key fingerprint remains unchanged and no second approval is requested.
- Switch authorized workers through the same harness handle, not by copying private keys between machines or giving them CA/admin credentials.
- Mark the objective COMPLETE through the durable objective tool (or SDK lifecycle API). Verify the lease is COMPLETED and the local key/certificate directory is absent.
- Verify no renewal is possible. In an explicitly controlled replay check using synthetic copied test credentials, wait until certificate expiry and prove reconnect fails. Existing connections can survive expiry; the harness should have closed its own process.
- Cancel/revoke another synthetic objective, verify residual-expiry semantics, and remove synthetic metadata/records according to the agreed test retention. Keep or remove the test trust only under the original owner approval.

Success requires both temporary **new authentication** and target-enforced **exact command authority**. It is not a hard session kill, universal data/process sandbox or rollback of remote changes. No VM installation has been performed; the future VM 220 dns-admin [helper design](ssh-dns-admin-design.md) grants no authority today.
