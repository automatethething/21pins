# Independent SSH security review (repository-local)

## Scope

Reviewed the lease lifecycle, native certificate validation/signing, production command authority, SSH transport restrictions, CA fingerprint pinning, serial reservation, recovery guidance, and CI gates. No target access, credentials, private keys, or public exposure were used.

## Findings

- **P1 — operational, not code:** revocation and certificate expiry do not terminate established sessions or detached work. This is documented and remains a beta launch condition requiring target-side containment procedures.
- **P1 — operational, not code:** CA rotation requires coordinated issuer state, public trust/principal updates, sshd validation, rollback, and fresh old-certificate denial. The runbook now requires two-person review and records this as a gate.
- **P2 — CI:** native target dogfood is not run on every CI build because it requires an approved non-production target. The workflow covers deterministic tests, vet, race, and production guard tests; native dogfood remains an explicit beta evidence step.
- **P2 — scope:** trusted target root, sshd configuration, fixed helper executables, and account startup environment remain part of the security boundary. Documentation explicitly avoids claiming a universal process sandbox.

## Positive controls verified in source/tests

- Production agent mode requires command authority and rejects development fixture authority.
- Dedicated non-root role accounts, exact principals, ForceCommand, no PTY, no forwarding, no raw-key/password path, and restricted environment are generated/validated.
- Host/role/user/rules-digest scope is immutable and revalidated before signing and delivery.
- CA public fingerprint changes fail closed; serials are reserved monotonically under transaction/locking and are not reused after signing failure.
- Native certificate signature, principal, serial, validity, CA, critical options, and extension allowlist are verified.
- Existing tests cover command injection/bypass forms, wrong host/role, policy drift, expiry, revocation, concurrent serials, and cleanup behavior.

## Verdict

**Controlled beta: conditionally ready after the non-production CA rotation/recovery drill and owner sign-off. Public launch: not approved.**
