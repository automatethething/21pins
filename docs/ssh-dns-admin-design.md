# dns-admin: pinned one-peer helper and VM 220 review

**Implemented and isolated-tested; NOT installed or registered on VM 220.** VM 220 trust, accounts, configuration, packages, services, peer state and network remain unchanged. No dns-admin certificates are issued by the real issuer.

## Critical read-only preflight finding

VM 220 / dns-primary has an active **Technitium (.NET) DNS service**, listening on UDP53, with the requested private address `10.77.0.53`. It has **no WireGuard link kind, wg tool or persistent WireGuard config**, and **no configured/running AdGuard service** in the inspected native service/process configuration. The existing management host also has no wg tool. This is not evidence about kernel module availability or an exhaustive disk inventory.

Therefore the requested WireGuard/AdGuard authority is not presently backed by resources on this target. Trust approval cannot create valid interface/peer/AdGuard/guest pins. Do not install packages, replace Technitium, create an interface, invent a Beryl identity, silently substitute Technitium for AdGuard, spread root authority to another host, or activate a synthetic fixture manifest. Resolve the intended service placement with the owner before preparing an installable real manifest. This is a genuine prerequisite ahead of the requested trust-only approval, not an outstanding implementation/test task.

## Immutable least-privilege role

Separate Unix account `pins-dns-agent`, only its primary group, no ordinary keys/passwords, root-owned empty HOME and trusted noninjectable login shell. Host `dns-primary`, role `dns-admin`, workspace `local`, dedicated principal, exact signed/principals/server force-command and command rules digest. Do not share observe's Unix user. Requester `pi`, explicit owner approval, review-only `sshaccess.DNSAdminHost` factory fixes default lease 15m/hard ceiling 30m/certificates ≤5m, no preapproval/PTY/forwarding/tunnels/subsystems. Existing approved `fipi` bastion is explicit host/lease policy, never an inherited arbitrary proxy; all CA/requester private keys/socket/API tokens stay on Mac.

| Literal operation | Fixed helper operation |
| --- | --- |
| `beryl enroll` | `peer-enroll` |
| `beryl verify` | `peer-verify` |
| `wireguard state` | `wg-state` |
| `wireguard handshake` | `wg-handshake` |
| `dns query` | `dns-query` |
| `dns test` | `dns-test` |
| `adguard status` | `adguard-status` |
| `adguard filtering` | `adguard-filtering` |
| `guest isolation` | `guest-isolation` |

Each maps to **exact** `/usr/bin/sudo -n /usr/local/bin/21pins dns-admin OP SHA256_MANIFEST`. No caller argument is interpolated or forwarded to tools. Root helper rejects nonroot, extra args, unknown operations, changed manifest bytes/digest, symlink/untrusted ownership/permissions/ancestors. Digest is included in every fixed Exec argv, so signed command rules and exact sudoers bind the manifest as well as the operation. Changing peer/interface/test domains/firewall evidence pins requires a new reviewed manifest, rules version, sudoers and approval; old certificates fail closed.

`sshaccess.DNSAdminHost` builds this exact non-fixture, explicit-approval policy without registration/install; unit tests reject >30m requests, unapproved signing, self-approval and altered jump scope. `internal/dnsadmin.Rules` and `Sudoers` produce the nine mappings and exact argument strings. Sudoers permits only these entries as root, NOPASSWD/NOSETENV, env_reset, !setenv, secure native path; no wildcards, generic sudo/wg/ip/dig/systemctl, shell, package manager, arbitrary paths, input config or environment preservation. Gate/user/host/role isolation remains the existing native OpenSSH enforcement, not purpose text.

## Root helper and manifest

Implemented in `internal/dnsadmin`, early `21pins dns-admin` dispatch before application/issuer store initialization. No unrelated provider state is created. Production has no fixture, tool-path or manifest-path overrides.

Fixed root-only manifest `/etc/21pins/dns-admin.json`, mode 0600, contains workspace `local`, host `dns-primary`, exact interface and `/etc/wireguard/INTERFACE.conf`, one existing Beryl **public** peer identity, fixed resolver `10.77.0.53`, distinct fixed control/blocked query domains and expected answers, exact `AdGuardHome.service`, reviewed stateless nft rules hash, guest prefix/ingress and `/var/lib/21pins/dns-admin/guest-proof.json` evidence path. Enrollment CIDR is hardcoded `10.66.66.5/32`; caller cannot choose other peers/ranges/endpoints/keepalive/keys.

Native wg/dig/systemctl/nft executable ownership/ancestors are validated root-nonwritable/nonsymlink. Each fixed absolute invocation has cwd `/`, explicit minimal environment, four-second timeout and capped one-MiB output. Tool/config output, peer keys/endpoints, private WireGuard data and raw stderr never enter reports. Output is fixed operation/status/booleans/counts only. Missing tools/services/expected outcomes deny, never become synthetic success.

Root-only `/var/lib/21pins/dns-admin` mode 0700 contains installed root0600 `lock`, transient rollback journal and independent guest proof. Exclusive nonblocking flock bounds concurrency; read operations neither create lock nor mutate state. Only enrollment creates/removes its own private transaction material and writes the one pinned persistence file. Non-writable root ancestors and nonsymlink regular files are required. Helpers cannot run directly as the SSH user.

## Bounded enrollment transaction and recovery

- Parse complete native persistent/live peer ranges locally. One interface section, no duplicate peer/range definitions, no SaveConfig=true races; missing/invalid native state fails closed. Reject overlap, other peer takeover, altered Beryl ranges and live/persistent disagreement.
- Correct live+persistent existing pinned /32 is idempotent. Otherwise append **only** the absent reviewed peer section; preserve all original bytes/private material/unrelated peers. No interface restart, global sync, key changes, endpoint/route/firewall/resolver changes.
- Under lock fsync root0600 journal with original persistent bytes and original live peer map plus manifest/patched hashes. Persist private temp with fsync/atomic rename/directory fsync, then native wg set one peer allowed-ips.
- Verify exact file hash, pinned peer/range and all unrelated live peers. On error restore only if current persistence is the expected original/patched version, restore/remove the pinned peer only, verify original disk plus entire prior live peer map. Never claim successful rollback if unrelated drift/restore failure exists.
- Crash leaves a root-private journal. Read-only verify denies pending recovery; next authorized enroll validates binding, restores/verifies the prior snapshot, then retries. Manifest changes or concurrent root drift fail closed, retaining recovery journal for the owner. Successful/verified rollback removes the journal. Own orphan private temp files are cleaned only by enrollment under the same lock, never by ordinary read operations.
- A missing/future/stale handshake is not enrollment success evidence: `wireguard handshake` independently requires exact peer plus fresh timestamp ≤3m. Configured peer and handshake are distinct facts.

## DNS, filtering and guest evidence

`dns query` tests only the fixed control domain/A answer on the fixed resolver. `dns test` additionally verifies the pinned blocked domain's exact NXDOMAIN or unspecified IPv4 outcome. No arbitrary domains/types/resolver/flags/traffic generator. AdGuard status requires its exact active native unit; filtering requires both service and control/blocked DNS outcomes. This deliberately refuses to label the current Technitium service as AdGuard.

`guest isolation` requires unchanged reviewed stateless firewall hash **and** fresh (≤2m), root-owned independently produced guest-origin evidence bound to the same firewall hash and exact guest prefix/ingress, with both TCP and UDP denied. Missing/stale/wrong-source/DNS-only evidence returns failure, even if policy matches. The helper does not manufacture guest traffic, change interfaces/namespaces/firewalls, use router credentials, or turn a localhost/DNS check into packet-isolation proof. Root evidence producer/actual guest source must be selected and tested once the real topology is known. Root is TCB; attestations are not permission to invent a packet test.

## Verification completed

- Go/race/vet and strict rules/manifest/dispatch/ownership/parser/conflict/idempotence/transaction/failure/rollback/crash-recovery/redacted-output tests.
- Native isolated OpenSSH dns-admin role dispatch for all nine operations, signed critical/principals/server gate, altered args/chaining/shell/substitution/generic sudo/wrapper/wrong host/role/user/SFTP/PTY/forward/raw-key/policy-drift negatives, renewal/complete. Dispatch fixture uses fixed printf only; production privilege boundaries tested separately.
- Real root Linux chroot runs production static helper with root manifest/config/lock and explicitly stateful fixture WG/DNS/service tools. All nine operations plus nonroot/argv/manifest/hash/permissions/symlink/lock denials and native visudo syntax pass. No production fixture switches. Entire chroot is deleted; no VM220/221 mutation.
- VM220 complete prospective SSH candidate validated **in memory through /dev/stdin**, no target file writes: native syntax passes, exact ForceCommand/AcceptEnv replacement/PermitUserEnvironment=no/DisableForwarding yes. 29 current accounts identified; actual recovery comparisons must be repeated after a real manifest/candidate is prepared and before installation.
- Existing Mac→VM221 bastion/CLI workflow regression remains required; no global CLI/Pi settings changed. Current repository binary is rebuilt/tested at the owner-selected path.

These prove isolated implementation, not real WG kernel enrollment/handshake, AdGuard filtering or guest traffic on VM220. Nothing is activated on that target.

```sh
go test ./...
go test -race ./...
go vet ./...
PINS21_SSH_INTEGRATION=1 go test ./internal/sshaccess \
  -run 'TestIsolatedDNSAdminAuthority|TestIsolatedCommandAuthority|TestIsolatedOpenSSH' -count=1 -v -timeout 110s
python3 scripts/ssh-dns-admin-isolated.py --self-test
python3 scripts/ssh-dns-admin-isolated.py --run
```

## Remaining owner boundary

Resolve the verified **target/service placement mismatch**; do not request a misleading trust-only approval. Recommended default: preserve working Technitium and locate the existing WireGuard/AdGuard authorities, then explicitly approve any necessary revised host/role scope. Public peer references only in local owner-managed pins; never paste private keys/tokens/passwords or public endpoints into chat.

Once actual reviewed pins/resources are available, the next installation approval must be exact: VM220 only, root-owned static binary/gate/policy/manifest/lock, new unprivileged account, nine exact sudo entries, selected existing public CA/principals and EOF Match; backup/recovery comparison/native validation/safe reload/fresh certificate smoke with rollback. No Beryl enrollment or service/network/package mutation is silently included in trust installation. Explicit separately approved pinned enroll then proves live/disk/handshake and real DNS/guest traffic. Existing CA custody remains on Mac; no new permanent trust on management host.
