# TODO — 21pins

## Build Phases

### Phase 1 (implemented)
- [x] Canonical grant schema + storage
- [x] Signed grant export (15m default TTL)
- [x] 7-pin evaluation output (pass/fail/requires_approval)
- [x] Execution receipts

### Phase 2 (implemented)
- [x] Grant CLI (`create/inspect/list/revoke/export`)
- [x] Evaluate CLI with clear pin-state output
- [x] Manual approval flow (`approvals list/get/approve/reject`)
- [x] Pin 7 enforcement gate (`--approval-id` required for threshold-crossing actions)

### Phase 3 (next)
- [ ] Delegation chain semantics (Pin 2 real enforcement)
- [ ] CK CLI identity handoff in grant issuance UX
- [ ] Gateway middleware policy checks on execution path
- [ ] Hosted control plane mode
- [ ] L402/payment integration for spend enforcement

## Security / Signing Roadmap

- [x] **Phase 1 signing approach:** Use a local 21pins Ed25519 keypair to sign portable grant exports.
- [ ] **Phase 3+ (planned):** Add **dual-signing** support:
  - 21pins signs operational grant exports (policy/authorization layer)
  - CK CLI co-signs identity attestation for stronger trust-chain interoperability
  - Verify both signatures in gateway/SDK validation paths when dual-sign mode is enabled
