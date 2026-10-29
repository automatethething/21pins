# SSH controlled-beta runbook

## Release gate

1. Use a dedicated non-production target and a dedicated agent-CA profile.
2. Verify root-owned, non-symlink gate/policy/principal/CA artifacts, restrictive modes, and complete `sshd -t` / `sshd -T -C` output.
3. Confirm production mode rejects `--dev`, `--legacy-auth-only`, arbitrary commands, PTY, forwarding, raw-key login, and unreviewed roles.
4. Run fresh positive and negative native SSH tests, including wrong host/role, altered argv, shell/chaining, expired certificate, revoked lease, and policy-drift cases.
5. Preserve a tested root-only recovery path before any trust reload.
6. Require two-person review for production CA rotation, target trust changes, and role-policy changes; record the old/new CA fingerprints and rollback decision without storing private material.
7. Confirm CI has passed Go tests, `go vet`, focused race tests, and production guard tests before beta release.

## Incident response

- Stop new issuance and renewal.
- Revoke affected application credentials and leases.
- If CA private material or serial state may be compromised, rotate the CA; do not reset serial history under the same CA.
- Install new public trust/principals only after review, validate sshd, and retain rollback.
- Verify old-certificate denial using a fresh connection. Do not claim existing sessions were terminated.
- Record the certificate and established-session residual window; use target-side session/process controls for immediate containment.
- Notify affected operators through the approved private channel; do not put keys, tokens, certificates, SSH output, host addresses, or customer data in issue trackers or chat.
- After recovery, run fresh positive/negative authentication checks and confirm the issuer cannot sign with the retired CA.

## Beta evidence

Store only minimized derived results: pass/fail, scope identifiers, certificate validity windows, fingerprints, and cleanup status. Never store private keys, CA sockets, credentials, raw SSH output, customer data, or terminal content.

## Explicit non-goals

No public target exposure, real-user enrollment, target/root infrastructure mutation, generic process sandbox claim, or instantaneous revocation guarantee. This runbook is an operator gate, not evidence that any target has passed until the checks are run and recorded.
