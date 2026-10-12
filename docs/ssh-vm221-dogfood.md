# Approved VM 221 observe installation evidence

Owner approved the reviewed VM 221 observe install and separately approved creation/storage/loading of a real dedicated CA. VM 220/dns-admin and network changes remain excluded.

## Installed and verified

- Dedicated unprivileged `pins-agent`, primary group only, trusted root-owned dash login shell and root-owned empty HOME. Native sudo query explicitly denies all commands (this administrator query returns 0 even for denial; exit status alone is not the gate).
- Static Linux amd64 gate from reviewed source, root-owned policy/principals/public CA and account-scoped native Match appended to the complete configuration. Matching signed/principals/server force-command binds workspace/host/observe/user/exact rules digest.
- Native full candidate/live `sshd -t`, effective environment/forced-command checks, safe `ssh.service` reload and active service pass. Fresh full effective comparison preserves all 29 original account contexts.
- Real dedicated native-agent CA; public fingerprint `SHA256:l3vFklSv9OXYxSsZwuUKHZhVt89Nn5Qfo9fet0lxT0Y` matched target before trust activation. No CA private material or signer socket was sent to the VM.
- Actual fresh signed SSH operations `platform`, `status`, `identity` pass. Shell/chaining/extra argv/absolute executable/wrapper/SFTP/PTY/forwarding/wrong host/wrong role/conflicting force-command/expired-certificate/raw-key login fail. Exact approved lease, same-key renewal and COMPLETE issuance denial pass. Ephemeral management-client key/certificate directory is deleted.

## Original requester-location limitation — now resolved via approved bastion

Actual dogfood's native SSH client runs on the existing reachable management host and connects **directly** to VM 221; it is not a traffic proxy. Certificate/lease issuance remains on the local issuer, using the dedicated CA agent. This Mac cannot currently establish a direct connection to the VM address. Thus this evidence verifies target installation and real management-client-to-target authentication/commands/leases, **not** Mac CLI/Node-to-VM execution. No route, firewall, tunnel/proxy or public listener was added to hide that limitation. Owner subsequently authorized reuse of the existing management bastion. [Mac-native CLI execution is now verified](ssh-bastion.md) using an explicit issuer-bound native -W hop, with final credentials and signer local; no target exposure or network/trust changes. This paragraph records the original management-client checkpoint, not the current supported Mac bastion path.

## Custody and lifecycle

Owner-only local directory: `/Users/claw/Library/Application Support/21pins/ssh/` (0700). Private/config/reference files are 0600. `config.json` pins public CA and `ca-agent.sock` in production `agent` mode; the native signer receives no private-key reference. CA private storage is explicitly owner-approved and not requester/API metadata.

Agent process is volatile, not a new automatic daemon/global Pi extension. After agent restart/boot, owner-approved custody must reload the same CA into the dedicated socket before new signing works. Never use the general desktop agent as a convenience fallback, never pass the CA socket into requester processes, and never paste private files or tokens into chat. Missing signer fails closed.

Current role policy: only requester `pi`, explicit approval, one-hour lease ceiling, 15-minute certificates and three fixed operations. Completion prevents new issuance, not reuse of already-issued certificates or automatic established-session termination. The command gate remains active throughout residual access.

## Reproducible opt-in test

```sh
PINS21_VM221_DOGFOOD=1 go test ./internal/sshaccess \
  -run TestApprovedVM221Dogfood -count=1 -v -timeout 110s
```

Uses only the explicitly installed target and configured dedicated real issuer. Test secrets/connection metadata stay local; output is bounded derived evidence. Default Go CI skips it. New real negative certificates reserve unique serials in issuer metadata; no serial-reset shortcut. The test closes its synthetic lease and deletes its remote ephemeral client credentials on normal failure/success.

Original backups/candidate and install receipt: root-only `/root/21pins-bootstrap-backup/`, including `install-receipt.json`. Do not rerun prestaging over this backup. Rollback preserves original recovery policy and removes/restores only this installation's account/artifacts/trust/config; validate before safe reload and verify fresh recovery access. No arbitrary home/data cleanup.
