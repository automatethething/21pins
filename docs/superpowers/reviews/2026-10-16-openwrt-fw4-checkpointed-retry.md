# Controlled real-fw4 checkpointed retry — generic-contract contradiction

**Result: stopped at `negative_context`; firmware/subset acceptance remains UNVERIFIED. No compatibility statement is published.**

Exactly **one additional OpenWrt guest boot** was consumed. Product source is unchanged from `214aad5`; no adapter/vendor exception, outcome relaxation, private-device access, SSH/login, trust expansion, fw3 or Tailscale work occurred. The required stop rule was obeyed; no semantic gate followed the contradiction and no further boot is authorized.

## Durable checkpoint outcome

Last completed semantic checkpoint: **`forwarding_guard`**.

Exact failed stage: **`negative_context`**, status **CONTRADICTION**, reason `system_ubus_not_foreign_binding_proof`.

| Host-completed checkpoint | Result | Host commit UTC |
|---|---|---|
| environment/provenance | PASS | 2026-10-16T14:51:25.598541Z |
| logical/runtime binding; finite gateway profile | PASS | 14:51:35.190435Z |
| native logical rebind: reject old binding | PASS | 14:51:46.226024Z |
| collection leaves test kernel/UCI unchanged | PASS | 14:51:53.360753Z |
| stored flag versus runtime guard, both directions | PASS | 14:52:03.442944Z |
| exact scalar membership and member removal | PASS | 14:52:08.607482Z |
| constant mark/RPDB mask/priority/prospective path | PASS | 14:52:14.557112Z |
| forwarding/guard plus independent synthetic allow/drop/allow controls | PASS | 14:52:21.095813Z |
| foreign-namespace/device-name mirror | **CONTRADICTION** | 14:52:26.370621Z |
| cleanup | PASS | 14:52:27.598137Z |

Unsupported ct-mark, uncalled-chain, unread/unknown-override and aggregate negative-controls gates were **NOT RUN after the stop**. They are not represented as passing, failing, or successfully remaining UNVERIFIED. Earlier positive checkpoints explicitly retained the absence of complete `source.binding`, observed `path.selection`, `forwarding.permission` and `enforcement.guard` proof. The forwarding observation is finite synthetic guest-only traffic, not encrypted VPN or production isolation proof.

The immutable host records include native gate start and host result-commit times, assertion booleans, integrity digests and source commit. They survived guest/controller/VM deletion. See [checkpoint summary](2026-10-16-fw4-oneboot-checkpoints/summary.json) and the individual numbered files in that directory.

## Generic-contract defect: namespace provenance

The negative gate established independently with real native tools that:

- The mirrored gateway context was a distinct network namespace.
- Its same-named native device had a different synthetic identity from the registered gateway binding.
- Real ubus/UCI/native readers and existing admission/immutable question logic were used; no PATH/native-command stub or fake VPN was involved.
- The required condition, **no positive `gateway.interface_binding` AND overall UNVERIFIED**, evaluated false.

This is a failure of the required context/binding safety invariant, not an unsupported-expression workaround opportunity. A system ubus response must not become binding proof for another namespace merely because a device name matches. Source inspection points to the provenance boundary: executing the ubus client in a network namespace does not itself establish that the filesystem-connected system daemon serves that namespace. This requires generic contract/provenance review, not an OpenWrt vendor exception.

**Evidence precision limit:** the as-run reporter retained the composite condition and independent native witnesses, not the two component values separately. Consequently this report does **not** assert the exact emitted assessment was VERIFIED, nor independently quote an unretained interface-binding boolean. The retained contradiction is the failed composite safety requirement. No post-stop collection was performed to embellish it.

No product repair was attempted. The untouched source remains `214aad5`.

## Exact environment and provenance

- Image: `openwrt-24.10.4-x86-64-generic-ext4-combined.img.gz`.
- Official compressed SHA256 rechecked: `57f43d2a665646b0c45b909328704796db1777f85cc0c8ad51ec9b830d34ffc5`.
- Raw image SHA256: `1ccfec0626acad4ad94e1b3eb90975e3e7464b146b5030666e01ab962bb1d637`.
- Real OpenWrt **24.10.4 x86/64**, build **r28959-29397011cc**, kernel **6.6.110**.
- Kernel package: `6.6.110~484466e2719a743506c36b4bb2103582-r1`.
- firewall4 `2024.12.18~18fc0ead-r1`; nftables-json `1.1.1-r1`; ubus/ubusd `2025.10.17~60e04048-r1`; UCI `2025.01.20~16ff0bad-r1`; ip-full `6.11.0-r1`; dummy/veth modules `6.6.110-r1`.
- The image, manifest, all three feed indices/signatures and all six prerequisite payloads matched the previous authenticated pinned tuple. The guest then verified **three signatures** with its existing vendor keys before package installation. Temporary same-release `file:` mirrors only; no new signing authority or signature bypass.
- The live environment checkpoint contains exact native fw4/nft/ip/ubus/ubusd/UCI entry hashes. [Artifact provenance](2026-10-16-fw4-oneboot-checkpoints/artifact-provenance.json) records the new binary/driver and image hashes; [review record](2026-10-16-fw4-oneboot-checkpoints/preboot-review.json) binds all five reviewed files.

QEMU TCG was installed only in the disposable runner; guest `-nic none`, runner network none, read-only payload block disk, no guest shared directory, forwarding, tap, bridge, KVM or guest-agent/network management endpoint. Local runner-only IPC coordinated serial writes; it was not guest agent transport or a network endpoint. Resource controls were cache64MiB/one emulated CPU/guest768MiB, Go GOMAXPROCS1/GOMEMLIMIT128MiB. They are not a retroactive diagnosis of the old137.

## Previous137 diagnosis and harness repair

Retained transcript timing narrows the previous interruption to **2.299s** (23:21:05.153–23:21:07.452Z on October15), not the80/115s deadlines. No lower-level kill detail, matching narrow owned crash report or retained VM/kernel OOM evidence establishes its cause. **OOM remains unconfirmed.** The new run did not reproduce137; eight retained guest resource samples each show zero guest kernel OOM events. That does not rule out the previous host/exec/guest failure.

Confirmed old defects were repaired: deadline nesting70/75/90/100/105s, one named gate per invocation, durable immutable host started/result commits outside Colima, guest/controller secondary safe checkpoints, no advancement until host fsync, complete missing native assertions, exact source/module/build-input pinning and review hashes, one-use canonical boot budget, and independent serialized cleanup-only guard. Nineteen offline tests cover actual SIGKILL, exit137, timeout/controller failure, immutability, metadata collision, closed-run behavior, cross-parent budget reservation and privacy.

Preboot reviews1/2 blocked and caused fixes; review3 approved. A guard-only prelaunch then caught a metadata filename collision **before runner creation/any guest boot** and cleaned everything. That closed zero-boot journal is retained separately, not overwritten. The collision and canonical cross-parent budget fix were re-reviewed; final [round5 review](2026-10-16-fw4-retry-preboot-round5.md) APPROVED the exact five-file hashes before the sole actual launch. The original and resumed prelaunch journals cannot mint a second authorized guest boot.

## Teardown and assurance boundary

The independent guard stopped validation, recovered27 allowlisted safe frames/replies, removed the guest/controller/container and the entire owned VM/runtime data (including images/overlay/payload), removed its Docker context and local download/package/binary/staging/config/lease directory, preserved the original owner context, and wrote a stopped receipt. Temporary standalone compiler output was also deleted. Fresh exact-name absence checks confirm no owned runtime/context/staging; no host QEMU was installed. No raw console/config/ruleset/packet dump or network/hardware identifier is retained.

The owner-wide consumed boot token is retained as audit metadata, not a residual running resource. All earlier gate files remain immutable. No schedule, monitor or extra boot remains active. Current regression tests and final result review are recorded alongside this report; they do not convert the contradiction into compatibility.

**Compatibility wording:** native prerequisites and the recorded positive subset were exercised on this exact tuple, but required generic context safety failed. **Overall real-fw4 acceptance remains UNVERIFIED.** No GL.iNet/Beryl/stock-policy/all-version support, encrypted VPN or production isolation certification follows. No Tailscale work starts.
