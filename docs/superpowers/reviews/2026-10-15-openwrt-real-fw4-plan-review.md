# Controlled real-fw4 validation plan — independent review

**Final status: APPROVED round2. Execution approval: PENDING.**

Plan: [controlled real-OpenWrt/fw4 validation](../plans/2026-10-15-openwrt-real-fw4-validation.md). Accepted production source stays214aad5. Planning performed no image/package download, boot, private-device collection or implementation.

Parent sole writer; fresh read-only reviewers with no commands, edits, live access, private context or delegation:

- Round1 `c30c2d16-a2d6-4f00-8d68-145dc83ddfad`: one valid blocker. Offline guest plus prohibition on all feed configuration did not specify an authenticated installation path for absent package prerequisites. Direct local `.ipk` installation is not signed-index verification.
- Correction: a transient guest-only `file:` mirror of the same pinned official signed indices/signatures/payload, separate temporary opkg config, image's existing vendor keys, signature checking and package-hash verification. No new key/feed authority or host trust change; missing/unverifiable dependencies stop validation. Mirror/config removed at teardown.
- Round2 `7ac86013-ef37-48c4-9cd3-60022d5ae43c`: **No issues found / Approved**. Confirmed offline actual guest isolation, unchanged adapter, signed package provenance, candidate-versus-traffic assurance, partial/UNVERIFIED semantics and bounded cleanup.

The plan has three gates: boot one exact controlled real firmware; validate native supported and negative semantics; retain only sanitized version-bound compatibility evidence and destroy the lab. It does not promise stock policy coverage, real GL.iNet/private-router compatibility or clearance of runtime partial flags. Any observed generic-contract defect requires stop/report/cleanup, not a platform exception.

No execution has begun. Review in Dashboard → Key Drafts →21pins →Controlled real-OpenWrt fw4 validation plan. Reply **Approve controlled fw4 validation** to authorize this isolated test plan; no production/private router access, fw3 or Tailscale implementation is included. Tailscale is the next separately scoped VPN target only after successful validation and acceptance.
