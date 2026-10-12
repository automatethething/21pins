# Technitium-only VM220 dns-admin authority

Owner decision: **Use existing Technitium**. This supersedes the combined VM220 WG/AdGuard role assumptions. Pi reads local references itself and presents approvals directly in the conversation, not through manual file/dashboard retrieval.

## Actual authorities

- VM220 `dns-primary`: existing Technitium `dns.service`, private resolver `10.77.0.53`; no WG/AdGuard installation there.
- VM205 `wg-gateway`: existing WG authority, private LAN `10.77.0.13`, tunnel `10.66.66.1/24`; supplied Beryl address-associated peer `10.66.66.5/32` already live/persistent with recent handshake. No independent public-identity enrollment attestation is inferred.
- Existing management bastion supplies explicit immutable SSH transport only. Its TCP -W path is not WG UDP transport.
- Gateway→resolver ordinary UDP/TCP DNS queries currently time out; VM220's local private-resolver UDP/TCP localhost probes pass. These are different vantage points, not proof of Beryl DNS or guest isolation.

The previous name-filtered search omitted the `wg` abbreviation and cannot support an absent/unknown WG authority conclusion. Corrected minimized evidence: `flowstate/ops/reports/finland-private-dns-topology.md` (read by Pi; owned by the separate read-only ops investigator).

## Exact production role

Separate proposed `pins-dns-agent` account. Host `dns-primary`; role `dns-admin`; workspace `local`; proposed alias `pins-vm220`, existing jump `fipi`. Explicit pi approval, no self-approval, 15m default/30m maximum lease, ≤5m certificates. Renewal window is bounded below the effective role certificate TTL (default 1m40s when a global 5m window would otherwise equal the role TTL). No PTY, agent/TCP/stream-local forwarding, X11, tunnels, arbitrary commands/args or raw-key login.

| Literal command | Fixed root-helper operation | Evidence |
|---|---|---|
| `dns query` | `dns-query` | Exact control A response at fixed resolver over UDP |
| `dns test` | `dns-test` | Same pinned control response over **UDP and TCP** |
| `technitium status` | `technitium-status` | Exact root unit-file digest, no systemd drop-ins, exact named unit active |
| `technitium filtering` | `technitium-filtering` | Requires separately reviewed known blocked-domain pin plus control success and explicit sinkhole/NXDOMAIN; missing pin/native failure denies |
| `guest isolation` | `guest-isolation` | Requires separately reviewed firewall digest/guest selectors and fresh independently root-generated external guest-origin TCP+UDP denial proof; missing prerequisites deny before native calls |

Every rule invokes only `/usr/bin/sudo -n /usr/local/bin/21pins dns-admin OP SHA256_MANIFEST`. Exact sudoers and identical certificate/principals/account force-command bind the digest-aware gate. Generic sudo/shell/packages/network writes are not granted.

**WireGuard/Beryl operations are absent from production dispatch, signed rules and sudoers.** The production manifest rejects even dormant WG interface/peer/config fields. Private staged enrollment/rollback routines remain tested but are unreachable through this role; any VM205 capability requires a separate reviewed host/role/account/approval.

## Real reviewed manifest, not invented prerequisites

`ssh-technitium-manifest.json` pins the fresh actual unit configuration and confirmed `localhost → 127.0.0.1` control response. SHA256 `1ddc2d4175ad8435d36acb39138052a9506bb858558cbf94e71260e36686909a`.

Unit SHA256 `5f5c27393fb97cbcc579927f49570d4a6f6610462d5d20d558c4dfa00b9c67a4`; fixed `/etc/systemd/system/dns.service`; exact `dns.service`; drop-ins denied. Root service/native tools and root configuration remain the TCB: this is configuration-drift/status verification, not full executable/library/socket identity attestation.

Filter and guest selectors are deliberately absent: their commands return nonzero/unverified, not synthetic success. They cannot be filled with fake probe domains or local self-attestation. Changing the reviewed manifest requires new rules digest/approval; old argv/cert policy cannot silently operate new content.

Force-command rules digest: `c14d60af957ce2a432d6dab344d2f346081c03b1eacd958881d191f53f78d81c`.

## Root/helper protections

Exact root execution and argv/digest validation before parsing; strict JSON unknown/trailing fields rejected. Root-owned regular nonsymlink files/ancestors, private manifest/state/installed nonblocking lock. Fixed native tools, clean minimal environment, ≤4s native timeouts/bounded output. No read-only operation creates configuration, packages, proof or provider state. Service unit may be root-readable 0644 but not writable/non-root/symlink; manifest/lock/proof remain root-private.

Any denied/missing proof yields nonzero CLI/SSH exit and `verified:false`. Native root/helper and native SSH gate failure propagation are separately exercised; after explicit installation approval, actual target certificate→gate→sudo→root-helper baseline/negative checks also pass. Fixture tests are never labeled real guest/client packet proof.

## Validation and activation gate

Go/race/vet, manifest/ownership/digest/privilege tests; root Linux chroot production helper with explicit DNS/service/firewall/guest fixtures and native sudoers syntax; real isolated SSH literal/scope/escape/PTY/forward/old-WG/old-AdGuard negatives and proof-child nonzero propagation; real current-binary Mac→bastion→VM221 regression; seven Node/Pi lifecycle tests.

Read-only actual VM220 prospective SSH candidate validates from `/dev/stdin`, preserves **29** recovery contexts, disables forwarding/TTY/user environments and installs nothing. Real unit pin/no-dropins and local UDP+TCP loopback DNS checks pass; management private target SSH is reachable.

Owner **y** approved and completed only VM220 account/gate/public CA/principals/policy/manifest/lock/exact sudoers and safe SSH reload. Real local issuer DNS-only scope is registered; fresh actual Mac certificate baseline/negative/renewal/completion smoke passes, and all29 original recovery contexts remain unchanged. CA private/signing agent/requester keys/tokens stay on Mac. No DNS/service/package/network/peer changes, WG gateway access/enrollment, filtering reconfiguration or firewall repair. [Actual install/dogfood evidence](ssh-vm220-technitium-dogfood.md) · [Corrected prerequisites](ssh-dns-admin-prerequisites.md).
