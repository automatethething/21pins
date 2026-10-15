# Controlled real-OpenWrt/fw4 validation — incomplete

**Outcome: UNVERIFIED. No compatibility claim.** The approved execution budget is exhausted. The product adapter remains unchanged at `214aad5`. A further guest run requires explicit owner approval; no Tailscale work starts.

## What was established

- Re-fetched the official checksum file and verified the complete pinned download before use.
- Image: `openwrt-24.10.4-x86-64-generic-ext4-combined.img.gz`.
- Compressed SHA256: `57f43d2a665646b0c45b909328704796db1777f85cc0c8ad51ec9b830d34ffc5`.
- Real guest: **OpenWrt24.10.4, x86/64, build r28959-29397011cc, kernel6.6.110**. This was the image's own booted kernel, not a rootfs on the runner kernel.
- QEMU TCG ran only inside the owned disposable runner. Every guest used explicit `-nic none`; the container used network `none`. No privileged container, host mount/shared directory into the guest, host forwarding, tap/bridge, KVM, SSH login, owner credential or trust-store change was used. The serial preflight issued stop/disable commands for the stock guest SSH service; their individual success was not separately attested. No SSH connection or trust enrollment occurred.
- The read-only payload disk contained the static Linux/amd64 test binary and official release-matched package data.
- All **three official indices passed signature checks** using the image's existing vendor keys. The six prerequisite payloads were then installed from the guest-local `file:` mirrors. No signature bypass/new key/direct unauthenticated installation was used.
- Full iproute JSON, nft JSON and dummy/veth prerequisites succeeded. Temporary default network feed files had to be moved aside inside the guest: opkg otherwise loaded them in addition to the temporary configuration. Their offline download failures were not ignored; the isolated mirror-only update was repeated and succeeded before installation.

### Actual native package versions

| Package | Version |
|---|---|
| firewall4 | `2024.12.18~18fc0ead-r1` |
| nftables-json | `1.1.1-r1` |
| ubus / ubusd | `2025.10.17~60e04048-r1` |
| uci | `2025.01.20~16ff0bad-r1` |
| kernel | `6.6.110~484466e2719a743506c36b4bb2103582-r1` |
| ip-full | `6.11.0-r1` |
| kmod-dummy / kmod-veth | `6.6.110-r1` |

[Sanitized evidence JSON](2026-10-15-openwrt-real-fw4-evidence.json) records the raw image, manifest, trailer, signed index, prerequisite package, validation binary/driver/controller digests, and selected native entry-file SHA256 values. Entry hashes were recovered read-only from the stopped owned guest filesystem; **they are not successful execution attestations or a semantic test result**.

## Interruption and limits

There were three guest boots, not an indefinite retry loop:

1. The first serial-control command exceeded its bound before adapter validation; the controller stopped that guest. A long encoded interactive command was replaced by short lines.
2. The second control channel returned completion but no genuine guest result frame. It was not accepted as evidence. The transport was replaced with acknowledged, short, native-printf chunks; no adapter/native reader tool was replaced.
3. The final guest passed the genuine serial frame, firmware and signed-package gates. The semantic validation invocation was then interrupted: the execution tool reported **exit137**, without a retained semantic result. The controller subsequently exited normally and the guest stopped. **The definitive interruption cause is unconfirmed; OOM is not established.**

Each operation/checkpoint was configured at no more than120 seconds. The failed helper had an execution-budget mismatch: the serial wait was80 seconds while the Go context/test deadlines were90/95 seconds. This is a harness defect, not a proven explanation of exit137 or an adapter verdict. Actual semantic acquisition start/end times were not retained. The interrupted monolithic invocation did not provide recoverable per-gate progress: its final result was guest-tmpfs/memory-only. No extra boot was attempted after the three-checkpoint budget. Offline read-only recovery found the synthetic network/firewall setup in the owned overlay, but that proves neither reader assertions nor negative-control outcomes.

## Required matrix — not certified

| Gate | Retained outcome |
|---|---|
| Real logical/device/address binding and native rebind rejection | **NOT ESTABLISHED** |
| Foreign namespace/device-name mirror must not reuse system ubus binding proof | **NOT ESTABLISHED** |
| Stored UCI flag versus active runtime guard | **NOT ESTABLISHED** |
| Exact scalar membership and member-removal negative | **NOT ESTABLISHED** |
| Native RPDB/mask/priority selection and earlier override | **NOT ESTABLISHED** |
| Independent finite synthetic forwarding/guard traffic | **NOT ESTABLISHED** |
| Unsupported expression, uncalled chain, unknown/unread override controls | **NOT ESTABLISHED** |
| Collection leaves kernel/UCI state unchanged | **NOT ESTABLISHED** |

No supported real-fw4 semantic assertion is reported as passed. No required negative is reported as successfully remaining UNVERIFIED: those outcomes are missing, not inferred. Runtime global-override/client-origin/path and firmware partial flags remain untouched. Stored configuration, prospective FIB selection, candidate forwarding/guard and observed traffic remain separate.

**Generic-contract defect: none confirmed.** The interruption does not clear the context/binding/unknown-handling gates or rule out a defect. No adapter repair, vendor exception, expected-result relaxation or alternate-platform substitution was made.

## Compatibility wording

> The pinned OpenWrt24.10.4 x86/64 image booted with the recorded native tools and authenticated prerequisites. Adapter214aad5's real-firmware/subset compatibility remains UNVERIFIED because the semantic/negative gates did not produce retained results. No firmware support claim is published.

This establishes no GL.iNet/Beryl, stock-policy, other-version/architecture, fw3/iptables, encrypted-VPN, production isolation or Tailscale support. No product/runtime capability is promoted.

## Current regressions

`go test ./...` and `go vet ./...` PASS after the failed helper rollback. Dashboard Key Drafts list, draft-viewer and exact-path validator PASS (8 entries). These are regression/link checks, not firmware semantic passes. The final production source tree matches214aad5.

## Teardown and follow-up

The guest/controller were stopped. The owned lab container and recovery snapshot/image were removed; the owned Colima VM was deleted **with its data**, and its Docker context was removed without changing the active owner context. Sanitized recovery used no guest boot or networking. Final cleanup checks in the evidence JSON attest VM/data/context and both VM-directory naming forms absent, container count zero before VM deletion, lab/recovery images removed with the destroyed runtime data, local firmware/package/payload/binary staging and temporary helper files removed, host QEMU still absent, and the owner context preserved. Zero owned lab runtime resources remain.

Post-run inspection also found that the failed helper lacked the planned native logical-rebind, set-member-removal and collection-state-nonmutation assertions. It could not have certified the full approved matrix even with a nominal success. These are **test-harness omissions, not confirmed generic-contract defects**.

The exact as-run driver/controller were hash-checked and archived locally in **`e6af55d`** for audit, then explicitly removed from the final tree. The failed monolithic harness is **not an accepted reusable validation gate**. Before any approved retry it needs checkpointed durable sanitized outcomes, a measured per-stage execution/resource budget, and complete rebind/member-removal/state-nonmutation assertions. Do not rerun the old helper or infer success from its exit alone. Independent result review must verify this failure report and cleanup, not grant compatibility.

**Owner action to authorize a separately bounded retry:** `Approve one checkpointed fw4 validation retry`. This does not authorize adapter changes, new firmware versions, private router access, new trust/credentials, fw3 or Tailscale.
