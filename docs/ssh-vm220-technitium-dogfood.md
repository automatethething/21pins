# VM220 Technitium-only installation and actual Mac dogfood

Owner explicitly approved the preceding bounded trust-only installation with **y**. Completed through existing management/guest-agent transport; no private CA/requester key/API token copied to management or target. Dedicated CA agent remains on Mac. No DNS/filter/service/package/network/firewall/WG205/Beryl mutations.

## Installed scope

Unprivileged `pins-dns-agent`, trusted `/usr/bin/dash`, locked password, single unprivileged group, root-owned empty HOME. Root-owned static gate, public CA/principals/five-rule policy; root-private real DNS-only manifest/state/installed lock and exact five digest-bound sudo grants. EOF account-only force-command/strict environment/no-PTY/no-forward controls.

Manifest SHA256 `1ddc2d4175ad8435d36acb39138052a9506bb858558cbf94e71260e36686909a`; rules SHA256 `c14d60af957ce2a432d6dab344d2f346081c03b1eacd958881d191f53f78d81c`; deployed static Linux binary SHA256 `23241b1ae704a74ffd617e5f03b7d97847d8157c62a64ebe476c0e8087db5c67`.

The install does not grant any WG/Beryl/AdGuard operation. `technitium filtering` and `guest isolation` return nonzero/unverified because real pins/evidence are absent. Their inclusion is a fixed read-only proof interface, not a claim that either feature passes.

## Recovery and native privilege evidence

- Root-only `/root/21pins-bootstrap-backup/`: original SSH config/include snapshot, reviewed candidate and `install-receipt.json`. **Do not rerun installer/prestage over this backup/account/trust tree.**
- Synthetic installer tests exercise successful installation and rollback failures before and after live-config mutation; restoration verified without real host changes.
- Native target sudo executes three real helper baselines under the new unprivileged account. Missing proof, WG, altered hash and generic shell sudo deny.
- Native SSH config validates before safe `ssh.service` reload; SSH and unchanged `dns.service` remain healthy.
- Fresh post-install comparison preserves **all 29 original recovery account contexts**; every installed artifact's root ownership/exact permissions, empty HOME/single group/trusted shell, binary receipt digest and deleted temporary upload are verified.
- Rollback is limited to installation: restore original SSH file, validate before reload, remove only created account/helper/CA/principals/policy/manifest/state/lock/sudo entry and empty created directories, preserve backup. Never delete unrelated config/accounts or touch DNS/gateway/firewall. Guest-agent recovery remains available independently of SSH.

## Actual Mac certificate smoke

`TestApprovedVM220MacTechnitiumCLI` passed **53.78s** with the selected repository binary and temporary loopback API/scoped independent requester/approver tokens:

- Explicit approved lease, fixed host/role/user/jump and real local native-agent CA; final pinned target key/certificate authentication via existing `fipi` -W.
- `dns query`, `dns test` (UDP/TCP), `technitium status` return verified JSON.
- Filtering/guest missing-evidence, old WG/AdGuard, arbitrary shell/generic sudo/chaining/altered args, wrong Unix user and changed target host-key negatives deny.
- Real same-key API certificate renewal; completion prevents re-execution; local requester private key removed. Temporary API/token/runtime state removed; durable lease audit remains terminal.

Local issuer registration adds only `dns-primary`/`dns-admin` alias `pins-vm220`/jump `fipi`, with 15m default/30m hard ceiling/≤5m certificates and explicit pi approval. Existing host configuration backed up in private local `config.before-vm220-technitium.json`; target public host pin and `ssh_config_vm220` stay in existing private local custody. Normal execution can explicitly select repository binary and this config; global CLI/Pi settings were not changed.

Actual WG authority remains VM205; its address-associated Beryl peer is already live/persistent. Existing source-restricted ACLs stay intact; gateway `.13` diagnostic denial is not repaired or confused with real Beryl-origin DNS. Real client-origin filtering/guest isolation remains separate unproven evidence, not outstanding permission to mutate production.
