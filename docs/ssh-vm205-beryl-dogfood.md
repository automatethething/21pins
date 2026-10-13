# Approved VM205 Beryl-only trust — actual installation evidence

Owner replied `y` to the exact two-command trust boundary. Installed only `pins-wg-agent`, existing public CA, static gate/only WG role policy/principals, owner-pinned manifest, private state/lock, TWO exact sudo grants, root-owned empty home/trusted dash and account-only restricted SSH block. Native validate/safe SSH reload healthy. No server/client WG key, interface, route, firewall, DNS, package or other peer changes.

Source gate/design: `afa82f5`; target binary SHA256 `816ebdfd92f2d8efa13ed410c7668b60f00c749a2badaace1f8b512790937f41` (exact approved artifact). Manifest `d31791b5dc95aae7467bfbbad0f305e6e2e19242c45a53451098f42d4f3cae68`; rules `e35aabe0bcd5b7acf62ddf349dc1b83d52ff5b681f6216685b998cd06081cd58`.

## Fresh target verification

- All28 original SSH recovery contexts identical to root-only original backup, both installer and fresh post-install check.
- Single unprivileged account group, `/usr/bin/dash`, root-owned empty HOME; installed root file/state/lock/sudo modes and exact binary digest verified.
- Native sudo helper baseline and wrong digest/obsolete WG/DNS/generic shell negatives pass.
- Owner's existing public key and `/32` already match live/persistent peer; certified `beryl enroll` is verified idempotent. Allfour WG peers preserve existing allowed-IP mapping; trust installation proves original config bytes/live table unchanged.
- Root-only `/root/21pins-bootstrap-backup/` original SSH/include snapshot, candidate and receipt retained. No upload residue or pending peer transaction. Never rerun installer over existing account/trust/backup.
- Only reviewed `wg-gateway`/`wg-beryl` local issuer scope added, backed up to `config.before-vm205-beryl.json`; existing DNS/observe scopes preserved. Target public host key pinned via existing strict management transport and same management subnet. No private host key/WAN address collected.

## Actual Mac execution

Fresh real API-only Mac→existing `fipi` native bastion→pinned VM205 certificate smoke initially73.53s, final88.46s after exact resolved-host-key negative correction:

- independent API approval/real local dedicated-agent CA issuance;
- `beryl enroll` and `beryl inspect` execute through installed root gate/sudo; configured peer inspected, server recent-handshake flag true;
- cross-DNS/obsolete/general WG/shell/chaining/extra argv/generic sudo/wrong Unix user/changed exact target host-key denials;
- same-key renewal, terminal complete/reexecution deny and local requester-key cleanup;
- no remote CA/private client/API material, no WG/other-peer/network changes.

THIS IS NOT FRESH BERYL-ORIGIN E2E PROOF. A recent server handshake is not a client-triggered handshake after a recorded test baseline, and no actual Beryl/client/guest queries were made by Pi.

Fresh installed VM220 authority regression53.69s verifies DNS UDP/TCP and Technitium service, immutable scope/negative/renewal/completion cleanup; its trust/helper/manifest are unchanged. Read-only SERVER-LOCAL DNS behavior: `example.com` NOERROR/answers on UDP/TCP; `ad.doubleclick.net` NXDOMAIN with explicit RFC8914 EDE15/17 Blocked/Filtered on both transports. This is real server-local filter behavior, not merely timeout/NXDOMAIN, but NOT Beryl-origin proof. Missing pins/proof VM220 filtering/guest literals still deny honestly.

## Tests and custody

Whole uncached Go race suite/vet pass; target-specific trust installer synthetic success/pre-live/post-live rollback checks pass; owner-run parser self-test distinguishes timeout/NXDOMAIN from explicit filtering. Temporary API fixture/requester credentials cleaned, WG audit entries terminal; root upload removed. CA private/signing socket and requester/API credentials remain Mac-local. Existing website changes preserved.

## Exact owner-only boundary

Original exact owner record explicitly says Beryl remains human-controlled: no Pi SSH/admin/probes or MAC/public-IP requests; prepare manual guest-network procedure. That source restriction was rechecked locally, not inferred only from a peer summary. Current bounded objective requires client evidence but does not explicitly override human device control. No device login, credential request, or Beryl probe attempted.

Next: owner connects a test Mac to Beryl's normal trusted network and signals `Beryl client proof ready`. Pi records fresh server baseline and coordinates bounded, synthetic-only server correlation while OWNER runs `scripts/beryl-client-proof.py --network trusted`; then owner switches to guest and runs `--network guest` in a fresh coordinated phase. See `beryl-client-verification.md`. Require actual later handshake, source-bound query/packet correlation, UDP/TCP resolution/filter controls and guest isolation/default-DNS/failover checks. No COMPLETE until all are fresh. Manual client JSON alone and negative timeout alone are not passing packet evidence.
