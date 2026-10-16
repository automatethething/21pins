# FW4 checkpointed preboot review — round 5

## Review
- Correct: `BOOT_ANCHOR` is a fixed retained-review path, independent of `--journal` (`scripts/openwrt-fw4-lab.py:5`); boot mode exclusively calls `reserve_owner_boot` before container start (`:166`).
- Correct: Cross-parent journal regression patches only that canonical anchor and verifies a second reservation fails (`scripts/test_openwrt_checkpoint.py:10-17`).
- Correct: Declared-stage journal enumeration and guard metadata regression remain intact (`scripts/validate-openwrt-fw4.py:49-67`, `scripts/test_openwrt_checkpoint.py:18-21`).
- No issues found.
- Merge verdict: APPROVED