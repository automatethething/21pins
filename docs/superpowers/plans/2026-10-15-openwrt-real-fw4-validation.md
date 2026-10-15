# Controlled Real-OpenWrt/fw4 Validation Plan

> **Execution:** one writer, @superpowers:executing-plans after owner approval. Validation harness/docs only; product source remains `214aad5`. **Planning only now: no image/package download, VM boot or live collection.**

**Goal:** Establish a version-bound compatibility claim for the implemented fw4 subset using real OpenWrt kernel, netifd/ubus, UCI, fw4, nft and iproute—not the previous ubus/UCI stubs.

**Architecture:** One offline disposable OpenWrt guest, owned entirely by the test coordinator, nested inside an owned disposable Linux/container runner. Serial console only; synthetic traffic remains inside that guest. Validate the existing adapter unchanged, record a limited compatibility matrix, then destroy every temporary resource.

**Tech stack:** Existing Colima/Docker; QEMU TCG installed only inside the disposable test runner (not on the Mac), official OpenWrt x86/64 image, current Go Linux/amd64 test binary. No host KVM/device passthrough, privileged container, host-network bridge, SSH, credential or trust-store change.

**Status:** Independently APPROVED round2 — [review record](../reviews/2026-10-15-openwrt-real-fw4-plan-review.md). Owner execution approval PENDING. No fw3/iptables or Tailscale implementation.

## Exact environment and claim

Pin **OpenWrt24.10.4 x86/64**, `openwrt-24.10.4-x86-64-generic-ext4-combined.img.gz`:

- Official directory: https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/
- Published image SHA256: `57f43d2a665646b0c45b909328704796db1777f85cc0c8ad51ec9b830d34ffc5` (recheck against the official checksum file at execution; mismatch => stop).
- Record the actual guest build/kernel and only the required native package versions. Real `firewall4`, `ubus/ubusd`, `uci`, JSON-capable nft and full iproute must be present. If required, preload release-matched **official signed package indices/signatures and matching payloads** (`ip-full`, relevant dummy/veth modules and dependencies) on the read-only payload disk. Use a temporary **guest-only `file:` mirror of those same pinned official feeds**, with a separate temporary opkg configuration and signature checking enforced using the image's existing vendor keys. Authenticate the signed index first, then package hashes; direct unauthenticated local `.ipk` installation is not sufficient. No new keys, third-party feed authority, host trust/config change or disabled signature check. Remove the temporary mirror configuration at teardown. Unverifiable/unavailable dependencies => stop/environment UNVERIFIED; no silent version substitution, snapshots or fallback repositories.
- Keep the base download immutable; write only an owned disposable overlay. Record image, package manifest, adapter binary/source and harness digests. This claim includes those package prerequisites—not an unqualified stock-image claim.

Permitted success wording:

> Adapter214aad5's registered IPv4 scalar-set/full-constant-mark fw4 subset was tested on OpenWrt24.10.4 x86/64 with the recorded kernel/tool versions. Logical/state/set/RPDB and native candidate evidence matched controlled observations. This does not certify default fw4 policy coverage, GL.iNet firmware, any private router, VPN encryption, other versions or production network isolation.

**Two separate axes:** real-firmware reader compatibility versus synthetic network-proof assurance. Test resources/identities remain synthetic even when native tools/firmware are real. Existing evaluator/verdict/profile contracts do not change. The runtime capability currently conservatively lists `live_firmware_compatibility`, global coverage and client-origin gaps; do not clear or override those flags to obtain a pass. A successful version-bound compatibility statement belongs in the sanitized validation record/docs, not a new runtime authority. If making the requested claim requires a generic capability-contract change, surface it for owner decision rather than add a platform exception.

## Gate 1 — Boot the real, isolated environment

**Potential harness files only:** `scripts/validate-openwrt-fw4.py` and `internal/netpolicy/openwrt_firmware_integration_test.go` (test-only build tag). No production Go edits. Use the existing reader, evaluator, synthetic actor/grant and private test-coordinator seams without adding any public bypass or credential.

- [ ] Build a static Go Linux/amd64 validation test binary from214aad5; no ubus/UCI/ip/nft replacement or PATH stub. Stage only the binary, synthetic fixture definition and authenticated package payload on an owned **read-only payload disk**, not a host directory/share.
- [ ] Run QEMU TCG inside the disposable runner. Explicitly use **`-nic none`** (omitting network arguments is not sufficient), no `hostfwd`, tap, bridge, shared folders, agent socket or network management endpoint. Use default offline serial-console access; do not create passwords/SSH keys or enroll trust. Retain no raw serial/boot log in reports.
- [ ] Verify inside the guest that OpenWrt's own kernel is running (not an OpenWrt rootfs on the runner's kernel), package provenance matches, fw4/nft backend and required JSON/namespace forms are available, and native command resolution points to real guest packages. Missing prerequisites => environment UNVERIFIED, not an adapter repair opportunity.
- [ ] Checkpoint each operation≤120s; at most three bounded boot checkpoints, no perpetual restart/retry. Every exit/timeout has a `finally` teardown; no resources may remain while returning a result.

## Gate 2 — One supported micrograph plus negative controls

Use generic synthetic names and documentation/benchmark addresses only. Fixture setup may change only this disposable guest's test UCI sections, links/namespaces and dedicated registered nft table/chains/set/RPDB entries. Keep real netifd/ubus/UCI/fw4 in use. Do not replace the complete default firewall just to obtain global closure, and do not call hand-authored test rules “stock fw4 policy support.”

Keep the adapter in the **actual router/default namespace** served by real netifd/ubus. Source and destination test namespaces/veth paths live wholly within the guest. No WAN/NIC/client traffic or private deployment names. No fake VPN identity for a dummy/veth device: route/path validation is not encrypted-VPN validation.

- [ ] Run the unchanged reader with existing exact admission and immutable binding/revision rules, real native commands, bounded before/after sampling and synthetic test identities/grants only. No real ConsentKeys login or new grant semantics. Confirm collection leaves test kernel/UCI state unchanged.
- [ ] Compare real ubus logical→device/address state to the registered binding. Change the owned test logical binding once: stale/rebound identity must not be accepted. **Negative context gate:** a foreign namespace/device-name mirror must not let the router's system ubus response become native binding proof for another namespace. This is a test requirement, not a presumption that it currently passes.
- [ ] Stored versus runtime: record the selected named UCI forwarding flag, install the supported runtime guard independently, then reverse one side. Assert they stay separate; a stored flag is never active enforcement.
- [ ] Destination set: positive exact live scalar membership, then remove that one synthetic member. Missing/ambiguous negative result remains unknown, never inferred membership or a supported fallback claim.
- [ ] RPDB/path: supported exact source/ingress/destination classifier and full constant mark, actual native mask/priority interpretation and source-bound FIB lookup. Inject one earlier matching route-policy override and verify selected path changes despite the main/desired route. Independently exercise finite synthetic traffic through the guest-only veth path; keep those test measurements separate from the adapter's **prospective** `routing.policy_selection` and absent observed `path.selection` proof.
- [ ] Forwarding/guard: record native forwarding candidate independently of selected path; enable/remove a supported source/destination/ingress-scoped drop guard and verify actual synthetic allow/block behavior. The adapter may emit candidate evidence while global coverage is unknown: do not demand or fabricate complete production `forwarding.permission`/`enforcement.guard` or access-isolation VERIFIED. Independent test observations validate the native candidate's interpretation, not a new runtime seal.
- [ ] Negative controls: at least one masked/ct-mark expression or unmodeled jump, an uncalled regular chain, and an unread/unknown override path. Requirements depending on those facts must remain UNVERIFIED/partial. A passing four-property gateway assessment must not imply any attached access policy, whole-network health or firmware-wide support.

**Stop rule:** If a real observation contradicts normalized semantics, immutable source/context binding, scope, unknown handling or the evaluator contract, stop validation and surface the generic-contract defect with minimal sanitized evidence. Do not change214aad5, add vendor branches, stub native tools, relax expected outcomes or reroute around failure. Platform/tool incompatibility is a recorded unsupported outcome, not permission to broaden the adapter. Clean up before returning any failure.

## Gate 3 — Publish only the bounded result, then remove the lab

- [ ] Save `docs/superpowers/reviews/2026-10-15-openwrt-real-fw4-validation.md`: version/digest tuple, supported test cases and outcomes, native-vs-test provenance, actual bounded windows, candidate-versus-complete facts and residual UNVERIFIED matrix. Allowlist fields before writing. No raw console/config/ruleset/packet payload, addresses, hardware IDs, credentials or private topology.
- [ ] Only if every applicable positive/negative gate passes, replace the blanket **documentation** firmware-untested statement with the exact environment/subset compatibility claim above. Leave runtime partial/unknown semantics and generic contracts untouched. Otherwise retain UNVERIFIED and report the concrete failed gate. No support claim for GL.iNet firmware, the owner's router, fw3/iptables, other versions/architectures or stock generated rules outside this subset.
- [ ] Verify214aad5 production source unchanged, focused/current regressions pass, and the evidence is sanitized. Independent read-only result review checks the narrow claim before acceptance; this is not public posting/deployment permission.
- [ ] Terminate guest/controller processes, delete overlay/payload/download/package/staging disks and console buffers, remove the disposable runner/container/VM and restore any selected tool context. Verify zero owned residual resources; no schedule/background monitor. Unresolved cleanup forbids success.

**Next implementation target after successful validation and owner acceptance:** Tailscale, solely as cross-model VPN validation in a separately scoped implementation plan. fw3/iptables remains a future compatibility slice; this lab establishes no support for any private router. No next adapter starts automatically.
