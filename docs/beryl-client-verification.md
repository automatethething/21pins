# Owner-run Beryl client/guest verification — historical procedure

Current: trusted DNS E2E and guest isolation are VERIFIED for the protected IPv4 DNS/Beryl WireGuard scope. Real synchronized guest observations plus additional owner-supplied active LAN-only FI policy/confirmed marked routing/enabled guest leak blackhole establish attribution. Required positive protected baseline is verified private DNS/port53; TCP22/5380 are supplementary probes, not mandatory trusted positives. See `beryl-guest-verification.md` for accepted evidence and limits. No counter probe/configuration change was needed; do not rerun the historical commands below.

VM205 approved two-command trust/install/certificate smoke is verified. Existing intended Beryl peer is live/persistent; no peer rewrite needed. VM220 trust remains unchanged; server-side DNS/filter behavior is verified. Actual Beryl-origin fresh handshake/DNS/filter/guest isolation remains unverified.

## Respect device control

Beryl remains human-controlled. Pi does not SSH/admin/probe Beryl or request MAC/public-IP values. The owner operates the test Mac and existing normal/guest networks. No router setting/profile/key changes are requested here.

## First coordinate the trusted-client phase

1. On your test Mac, connect to Beryl's **normal trusted** Wi-Fi/LAN, with its existing intended WireGuard profile active. Avoid another VPN/interface carrying test traffic; do not send network identifiers or screenshots.
2. In Pi chat say **`Beryl client proof ready`**. Do not run the checks until Pi confirms a fresh server baseline and the bounded correlation window.
3. In macOS Terminal run exactly:

```
python3 /Users/claw/flowstate/repos/21pins/scripts/beryl-client-proof.py --network trusted
```

The script uses the existing source manifest DNS target, `example.com` allowed control, server-confirmed `ad.doubleclick.net` filtering control and a synthetic nonce `.invalid` challenge. It collects only derived JSON, not DNS answer addresses, network config, MACs, public IPs, credentials or cookies. Paste only that JSON. Expected client controls: private UDP/TCP NOERROR with allowed answers; blocked-domain NXDOMAIN with explicit Blocked/Filtered EDE, not timeout. Pi must correlate a later authenticated handshake/source-bound queries with test timing; recent old server state is not enough. Normal control DNS/HTTPS must work.

## Then coordinate a fresh guest phase

4. After Pi confirms trusted evidence, connect the same test Mac to Beryl's **guest** network and tell Pi **`Beryl guest proof ready`**. No router administration/settings changes.
5. Once Pi starts the new bounded window, run exactly:

```
python3 /Users/claw/flowstate/repos/21pins/scripts/beryl-client-proof.py --network guest
```

Expected: default public DNS/HTTPS work; private DNS UDP/TCP and private DNS/admin TCP ports are not reachable; no private target is advertised as client DNS/failover. Synthetic default/direct guest challenges must NOT reach private Technitium, including via hidden router DNS proxy/failover. `scutil` derived flags conservatively inspect client DNS but cannot prove upstream isolation alone. Pi needs fresh source/path-bound query/packet correlation and positive trusted/control evidence. A timeout/no TCP connect alone is NOT verified isolation. These checks cover the current Finland scope, not unreviewed other-site endpoints.

## Privacy and success signal

Do not paste private WG keys, profiles, router pages/screenshots, tokens, passwords, cookies, DNS raw output, packet dumps, MACs, public IPs or real personal query data. Paste only the script's status JSON. It deliberately reports `E2E_complete:false`; Pi only changes objective state after independent fresh handshake/DNS/filter/guest correlation passes. If network policy really fails, report it; do not broaden ACLs or change device settings merely to make the test pass.

## 2026-10-13 trusted-window reconciliation

Owner readiness was relayed through the linked session. Pi implemented a server-only ≤100s IPv4 observer (no Ethernet/MAC) with kernel filters for exact private source/destination/DNS port and synthetic `pins-<nonce>.invalid` label/prefix/suffix. Only validated synthetic nonce/counts leave root, no raw packets/personal queries/public endpoints. Pre-filter queued data is discarded with a bounded NULL-buffer syscall; readiness file is exclusive/no-follow and removed with closed sockets. Pure filter/parser/source/domain/truncation tests and native **server-SELF** UDP/TCP positive tests pass; SELF tests are not Beryl evidence.

Initial collector startup/cleanup bugs were fixed, exact prior owned process stopped and failed window discarded. A clean 95-second trusted window started with fresh baseline epoch1791893600/handshake1791893571; it exited0 with **zero** source-bound synthetic queries. No owner client status JSON was supplied to this operator. Later peer handshake advanced to1791894059, but without exact nonce/client timing this is NOT client-triggered DNS/filter/handshake proof. Zero capture is UNVERIFIED, not proof of successful isolation or a definite network fault. Window is closed; do not run stale unsynchronized checks.

Both neutral reviewers accept the bounded minimized mechanism and treating empty capture as unverified. Source-IP/nonce plus fresh WG state is operational correlation under the trusted-LAN/root TCB, not cryptographic identity attestation of a particular physical client; an adversarial private-LAN source spoofer remains a residual limitation. No MAC/public-IP collection is added to solve that.

Next owner action: if the trusted script ran, paste only its derived JSON; otherwise be at the trusted-client Terminal and reply `Beryl client proof ready` for a fresh window, then run immediately on RUN NOW. No fresh guest phase until trusted data is reconciled. VM205/VM220 installed trust and networking remain unchanged. No client tests have been run by Pi and E2E remains unverified.
