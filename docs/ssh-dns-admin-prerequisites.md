# Technitium role — corrected prerequisites and trust boundary

Owner selected existing Technitium. No manual file-opening/dashboard retrieval is required: Pi reads context, decides what matters and presents exact approval in the conversation.

## Service placement, not new provisioning

WG already exists on VM205 `wg-gateway`, not VM220. The Beryl-address peer is live/persistent with a recent handshake. Do not install WG/AdGuard on VM220, replace Technitium, create a new public listener or grant gateway privilege under a DNS-only approval. Earlier absence conclusions from a name-only lookup are withdrawn.

VM220 local fixed-resolver UDP/TCP localhost probes pass. Gateway-LAN-source queries from `10.77.0.13` time out; read-only ACL diagnosis finds source-restricted hypervisor forwarding, with exact Beryl source `10.66.66.5` already allowed but gateway `.13` not permitted. Do not "repair" the policy with broad LAN allowance. Actual Beryl-origin DNS remains unproven; a gateway-origin probe is not equivalent. Detailed final facts remain owned by the minimized ops report.

## Technitium-only profile ready for trust-stage review

- Fixed private resolver and actual root unit-file SHA256; no service drop-ins permitted.
- Exact control pin `localhost A 127.0.0.1` proved over both UDP/TCP from VM220.
- Five signed literal commands: DNS query/test, Technitium status/filtering, guest isolation.
- **Three baseline checks usable.** Filtering lacks a reviewed blocked-domain pin; guest isolation lacks real independently generated origin evidence. Both deny with nonzero exit before native calls. No invented success/proof/config values.
- Production profile contains no WG interface/peer/config and rejects attempts to add them. Public dispatch/rules/sudoers grant no Beryl/WG operation. Existing stage-only enrollment code does not expose a production entry point.
- Root service/native binaries and configuration are TCB; unit pin/drop-in rejection is not executable/library/socket attestation.

## Exact next owner boundary

One-time VM220 **SSH capability trust installation only**: separate unprivileged `pins-dns-agent`, trusted dash/root-empty home/no generic sudo; existing public CA trust, static root gate, principals/policy, real DNS-only manifest, installed private lock/state and five exact digest-bound sudo entries. Preserve original SSH config/accounts as root-only recovery backup; native validate/recovery checks before safe SSH reload. Then actual Mac→existing bastion→VM220 certificate/command/lifecycle smoke and ephemeral cleanup.

This does not authorize DNS/filtering/service/package/network/firewall changes, WG205 access or peer enrollment. No gateway `.13` DNS allowance is requested. Real Beryl traffic/guest validation and future capability/pin changes retain their separate gates. No target trust/issuer host registration/certificate has been installed/issued yet.
