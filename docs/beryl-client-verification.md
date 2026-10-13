# Owner-run Beryl client/guest verification — not yet performed

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

This document is a ready manual procedure, not actual completed packet evidence. No client tests have been run by Pi.
