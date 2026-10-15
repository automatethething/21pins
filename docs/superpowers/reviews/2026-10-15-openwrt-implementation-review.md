# OpenWrt evidence implementation — validation and independent review

**Result:** four approved tasks implemented; fixture/kernel validated, **live firmware compatibility UNVERIFIED**. One writer, independent read-only reviewers. No private-device access, transport/trust/privilege/grant expansion, automatic repair, fw3/iptables or Tailscale implementation.

## Implementation

1. `ad3b236` — optional immutable native binding selectors; canonical deep copies, omitted-field compatibility, frozen request/read scope, revision/rename behavior and defensive mutation checks.
2. `2f26f0a` — finite source/set/mark/chain/RPDB normalization, active regular-chain reachability, separate stored/runtime digests, forwarding/path/guard distinctions and conservative unknown coverage.
3. `8edb87a` — admitted bounded local reader, fixed ubus/UCI/ip/nft forms, before/after semantic snapshots, operation/output/deadline limits, generic gateway dispatch and partial capabilities.
4. Final cross-model commit — real kernel gate, strict native scalar-element reply compatibility, VPN-context correlation, isolated-runner enforcement, docs and final regressions.

Adapters return normalized facts/capabilities only. Existing evaluator and exact gateway/VPN profiles remain unchanged. New prospective routing facts are not observed access-path proof. Logical association is not client-origin evidence. Unknown global coverage never becomes production enforcement/isolation proof; private synthetic closure is test-only.

## Independent implementation review

- Reader/admission review `71a51207-5b83-421b-8082-e912d2d39ad5`: **No issues found / merge OK**. Checked frozen scope, admission per read, namespace identity, 32-call/3s/64KiB bounds, semantic before/after consistency and sealing.
- Normalizer review `a615e959-9016-43b8-93b1-95a09a52b098`: **No issues found / merge OK**. Checked finite ordered graph, selectors/masks, route-table correlation, provenance and closure.
- Kernel-resolution review `b2170871-141d-4e56-bd20-b3e829e0b0d2`: strict native membership parsing accepted; **one valid test-isolation blocker** found: the test itself remounted `/proc/sys`. All executions had already been inside the owned disposable container mount namespace, not the owner host; nonetheless generic tests must not do that themselves.
- Fixed by removing remount calls from BOTH integration tests, requiring an explicit isolated-runner marker and supplying writable proc sys only during external disposable-container setup. Forwarding writes remain inside freshly created network namespaces. Also pinned related VPN resolution and same gateway/namespace/context correlation.
- Final review `11474965-9231-4f25-946f-a06736cf4b4e`: **No issues found / merge OK**; confirmed isolation correction and VPN identity boundaries.

Reviews were bounded seam inspections, not a claim to re-audit every existing repository surface. No reviewer wrote product files, ran live commands or received private operational context.

## Native cross-model gate — PASS, no SKIP

Inside the authorized disposable Linux container with private mount namespace and writable proc sys:

```sh
PINS21_ISOLATED_NETWORK_TEST=1 go test -race -tags=netpolicy_integration ./internal/netpolicy -count=1 -v -timeout=100s
```

The marker is a test-runner prerequisite, not a public CLI/grant/closure switch. Never use a live host/device as this runner.

- Existing real Linux/WireGuard/DNS allow/isolation/leak gate: **PASS9.44s**.
- New real kernel OpenWrt-contract gate: **PASS0.18s**.
- Whole package with race detector: **PASS10.778s**, no race report/SKIP.
- New fixture uses an owned fresh namespace, actual RPDB routes/marks, nft classifiers/sets/forwarding/guards and dummy devices. ubus/UCI are explicitly labeled synthetic stubs: this validates the generic adapter contracts, **not installed OpenWrt/GL.iNet firmware**.
- Read-only collector leaves known kernel state unchanged. A real earlier-priority route changes the selected path without conflating forwarding/guard facts. Real guard removal cannot be replaced by forwarding permission. Runtime changes between samples become stale; deleted/ambiguous set membership becomes unknown.
- No client-origin or observed-path claim is minted. Unknown production closure yields only partial candidates. Additional native evidence does not widen the four-property public gateway result.
- Sockets/keys/records in the existing gate and all new namespaces/stubs/temporary files are cleaned; no background collector/rearm.

The kernel gate exposed a genuine nft-version behavior: `-j get element` returned scalar native text, not JSON. Added a strict exact family/table/set/type/one-target grammar fallback, with wrong identity/type/extra/trailing-data negative tests. No generic success-code or substring membership inference.

## Regression gates — PASS

- `go test ./... -count=1`
- `go test -race ./... -count=1`
- `go vet ./...`
- Linux amd64 + arm64 CLI cross-build
- Existing Node/Pi SSH harness:7/7 PASS,0 SKIP (installed Pi loader)
- Existing and new namespace/kernel gates above
- `git diff --check`

Only the approved optional binding/reader/normalizer, narrow registry/question/collector seams, tests and documentation changed. LLM proxy, native SSH roles/certificates, existing execution-grant evaluation, provider/signing state and legacy receipts were not modified. Unrelated website changes are preserved.

## Unsupported / UNVERIFIED by design

Live OpenWrt/GL.iNet firmware compatibility; fw3/iptables; IPv6 native profile; dynamic/interval/concatenated sets and ambiguous negative membership; masked/ct-mark/dynamic classifier expressions; unmodeled NAT/offload/hooks/jumps/priorities or RPDB actions; global production override closure; remote/client probe vantage and observed access paths; other architectures outside existing Linux amd64/arm64 runtime; Tailscale and later vendors. Missing tools/rights, rebinding, stale/mixed state or exceeded bounds remain partial/UNVERIFIED, not a reason to add permissions, repair networking or contact a private device.
