# VM205 Beryl-only WireGuard authority — approved and installed

**2026-10-13 update:** owner `y` approved this exact boundary; restricted trust/recovery/native certificate smoke is installed and verified. Historical review/preflight sections below preserve approval provenance, not a request to reinstall. See `ssh-vm205-beryl-dogfood.md`. Beryl is explicitly human-controlled; owner-run client/guest tests and fresh correlated evidence remain outstanding. Never reinstall this account/trust/backup.

## Bounded objective

Finish Beryl-origin private DNS end to end, with fresh client handshake, UDP/TCP DNS, actual Technitium filtering and guest/client packet evidence. VM220's completed trust installation is unchanged. This source-only milestone is not completion of the end-to-end objective.

## Narrowest role

Only two literal commands, no client-selected arguments:

| SSH literal | Exact root helper operation |
|---|---|
| `beryl enroll` | `peer-enroll` |
| `beryl inspect` | `peer-inspect` |

Both map to `/usr/bin/sudo -n /usr/local/bin/21pins wg-beryl OP MANIFEST_SHA256`. There is no generic WG/interface state, other-peer selector, deletion, shell, DNS administration, endpoint mutation, route/firewall change, interface restart, package operation or service administration.

Scope: workspace `local`, host `wg-gateway` (VM205), role `wg-beryl`, account `pins-wg-agent`, alias `pins-vm205`, existing jump `fipi`. Review-only factory never installs or registers authority. Pi-only explicit separate approval, no self approval; default lease15m, hard30m, certificates≤5m and renewal below effective TTL. SSH lease expiration stops admin issuance, not the intentionally persistent existing network peer. Never automatically remove Beryl on lease closure.

The owner-supplied Beryl public identity was recovered locally from its exact existing user turn, without dumping transcripts or values. It matches both the existing live and persistent `10.66.66.5/32` peer. All four existing peers' allowed-IP maps match live/persistent. This is an owner identity match, not independent device-side attestation or fresh packet proof. No router/client access pointer has been obtained from those records.

## Pins and custody

Owner public manifest: `~/Library/Application Support/21pins/ssh/wg-beryl-manifest.json` (private local directory/file). Review artifacts: `~/Library/Caches/21pins-vm205-review/` (public artifacts only; no private CA, WG server/client keys, API tokens or signing agent).

Manifest digest: `d31791b5dc95aae7467bfbbad0f305e6e2e19242c45a53451098f42d4f3cae68`.

Rules digest: `e35aabe0bcd5b7acf62ddf349dc1b83d52ff5b681f6216685b998cd06081cd58`.

Review Linux binary digest: `816ebdfd92f2d8efa13ed410c7668b60f00c749a2badaace1f8b512790937f41`.

The manifest fixes `local`, `wg-gateway`, `wg0`, the single owner public key, `/etc/wireguard/wg0.conf` and exactly `10.66.66.5/32`. Unknown/trailing JSON, wrong selectors, key encoding, modes, symlinks, lock contention and hash/argv/root drift deny. A client cannot supply key/IP/path via arguments, stdin or environment. Root digest validation precedes parsing/native calls.

## Engine and proof semantics

Reuse the existing private staged transaction routines in `internal/dnsadmin`; expose a separate `wg-beryl` entry point, separate strict manifest `/etc/21pins/wg-beryl.json` and state `/var/lib/21pins/wg-beryl`. DNS-only production dispatch/rules remain separate; there is no VM220 deploy or trust change.

Enrollment rejects overlapping addresses, target range drift, all-peer live/persistent allowed-IP drift, unsafe files and `SaveConfig` mutation risk. A correct existing peer is verified without modifying config or calling `wg set`. Otherwise append only that peer to original bytes, durably fsync private journal and disk config BEFORE fixed live set, verify unrelated peers and exact disk bytes; recover/rollback only the helper transaction. Private snapshots containing server configuration stay root-private on VM205, never copied off gateway.

Inspection verifies the fixed peer's persistent/live presence, then reads only its validated recent-handshake result. Output is status/count/boolean and bounded handshake timestamp; raw configuration, peer identities, endpoints and metrics never cross the root helper output boundary. A recent server timestamp is not fresh Beryl-origin proof. End-to-end verification must originate authenticated traffic from Beryl after a recorded baseline and observe a later handshake, then actual UDP/TCP DNS/filtering and client/guest ingress packet tests. Router-origin `dig` does not prove guest FORWARD isolation. Timeout alone does not prove filtering or isolation; successful controls and packet/path evidence are required.

## One-time trust-install boundary

No VM205 changes have been made; account, CA trust, installed helper, role paths and backup are absent. No real issuer `wg-gateway` registration or WG role lease exists. Read-only native candidate validation preserves all28 original SSH recovery contexts in memory, checks new account restrictions and does not write/reload SSH.

Approval would permit only:

- new locked-password, single-group unprivileged `pins-wg-agent`, trusted dash and root-owned empty home;
- static root-owned gate/public CA/only this role's command policy/principals;
- private pinned manifest, state and installed lock;
- TWO exact digest-bound sudo grants;
- account-only forced/restricted SSH Match and validated safe reload;
- original root-only SSH/config-include recovery backup, receipts and trusted target public host-key pin;
- local registration of only this reviewed host/role, preserving the existing issuer config backup and previous hosts.

No DNS, VM220, WG interface/private-key replacement, firewall/routing, other-peer, package or Beryl changes are part of trust installation. After approval, the already-requested Beryl enrollment runs through the new authority and should be a no-op because its existing key and /32 already match. A mismatch requires diagnosis, not an invented replacement peer.

Trust rollback: preserve original SSH and include tree; validate all original recovery contexts and candidate before live mutation. On failure restore only original SSH, validate/reload safely, delete only newly installed artifacts/account, preserve unrelated services/files and root-only evidence. Never overwrite an existing backup/account/trust. Network peer transaction rollback is separate and only relevant if later enrollment actually appends the absent reviewed peer.

## Verified before approval

- Go suite, race and vet.
- Actual isolated native OpenSSH certificate/principals/account force-command, allowed exact literals; shell/chaining/altered args/wrong scope/subsystem/PTY/forward/raw-key denials, renewal/close.
- Native root Linux chroot against explicit synthetic WG tools/keys/config, not real network evidence: two operations, idempotence, unrelated-peer preservation, hash/argv/modes/symlink/lock/nonroot/obsolete-operation negatives; actual SIGKILL after durable disk-before-live, reconstruction/rollback/retry; native sudoers syntax. Chroot removed.
- Existing DNS-only isolated helper regression: obsolete WG/AdGuard deny, missing proof honestly nonzero. VM220 unchanged.
- Independent neutral advisory review accepted narrow source-only staging with structural disk-before-live and root-side output filtering; no new owner authority inferred.

Runnable checks:

```
go test ./...
go test -race ./...
go vet ./...
python3 scripts/ssh-wg-beryl-isolated.py --run
PINS21_SSH_INTEGRATION=1 go test ./internal/sshaccess -run TestIsolatedWGBerylAuthority -count=1 -v -timeout 110s
```

## Remaining release gate

Owner trust-install approval → restricted VM205 installation and actual certificate smoke → idempotent enrollment → actual Beryl access/client-triggered fresh handshake → Beryl-origin UDP/TCP DNS/control + genuine filtering → fresh guest/client packet/query isolation. Existing VM220 missing selector/proof operations still honestly deny; do not broaden its trust to manufacture evidence. Use real client queries and actual reviewed filter behavior, not server configuration or gateway-origin substitutes. A genuine failing policy or missing owner-only device access is surfaced separately; no automatic firewall repair and no COMPLETE until all four evidence classes pass.
