# VM220 prerequisites — planning only, no mutation approval

Pi reads local context and presents decisions here/in the conversation; the owner need not open files or retrieve safely accessible information.

Fresh reconciliation confirms VM220 has working Technitium DNS but no configured WireGuard or AdGuard. Known VM221/management-host checks and a filtered DNS/VPN VM/container lookup found no alternate authority. This bounded discovery does not exclude an unknown external/router service.

The original nine-command role remains implemented, isolated-tested and inactive. Do not install a role with fake manifest pins or rename Technitium as AdGuard.

## Safe default

Preserve existing Technitium and its working private resolver. Keep CA/requester keys and API tokens on Mac. Reuse the approved management bastion for certificate SSH only. Do not assume its TCP -W channel transports WireGuard UDP or proves Beryl endpoint reachability.

## Prerequisites if the original WireGuard/AdGuard semantics are retained

1. Select the actual service authority and existing Beryl public-identity reference. No generated replacement peer identity, private-key retrieval or credential copying.
2. Review Beryl-to-WireGuard private endpoint reachability separately. A Mac SSH bastion success does not authorize a public UDP listener, routing/firewall exposure or a new permanent trust path. No guessed endpoint/port/host.
3. Prepare separately reviewed operator provisioning for WG tools/interface/private config and any required routes/firewall restrictions. None of this belongs to the dns-admin role, which remains incapable of packages/generic network commands.
4. Select an AdGuard deployment or actual existing authority without silently replacing Technitium or changing the resolver pipeline. Any service/filtering integration is a separately reviewed production change; no presumed DNS listener takeover/upstream selection.
5. Obtain real control/blocked DNS test pins and independently verifiable guest-origin TCP/UDP evidence. Do not manufacture attestation files from a local DNS check.
6. Only then build the real digest-bound root manifest, exact sudoers/gate/account/trust candidate and repeat read-only native/recovery preflight. Present the exact one-time trust installation approval in Pi. Backend provisioning, Beryl enrollment and real packet tests retain their distinct approvals.

## Owner-only decision

The discrepancy changes the intended service/backend scope. Pi may safely prepare plans and tests without approval, but cannot choose a different privileged service/host or authorize production prerequisites itself.

Recommended direction: use existing Technitium for DNS-specific administration, with WireGuard enrollment explicitly unavailable until its separate prerequisites are approved. Alternatively retain the original AdGuard/WireGuard requirements and review the prerequisite deployment as an additional change, not a trust-only installation.

No live target, issuer registration, trust, service, package, network or peer changes were performed during reconciliation.
