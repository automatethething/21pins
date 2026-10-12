# SSH command authority implementation plan

Owner authorizes implementation and isolated OpenSSH tests; no VM 220/221 or production changes. Existing authentication leases remain intact. Security advisors receive abstract descriptions only; controller is sole writer.

Design choices: certificate-only force-command cannot defend against a mistakenly broad cert; server-only generic ForceCommand cannot infer authenticated role from untrusted requested command. Use identical signed force-command, root-owned per-principal command option, and per-account server ForceCommand. Different enforceable roles use separate Unix accounts. A strict literal argv parser selects exact allowlisted operation → fixed executable argv; no shell evaluator, variable interpolation, argument passthrough or privileged general shell.

- [x] Independent Claude and agy abstract architecture/security review; final APPROVE/CMUX_TASK_DONE, with pre-gate shell/PAM checks retained.
- [x] Failing-first literal/allowlist/scope tests; strict parser, signed user/rule digest, root-owned paths/ancestors, bounded JSON, sanitized direct exec.
- [x] Failing-first signed force-command and production-gate tests; exact critical encoding/signature/options verification and live lease policy retained.
- [x] Root-installable public per-role command/principals/Match bundle plus verified consistent VM 221 review templates; no install/reload.
- [x] Production agent CA requires gate; explicit dev legacy CLI fixture preserved, new observe registration defaults three fixed operations.
- [x] Actual static-gate/native sshd tests: allowed literal operation, escape/scope/feature/force/rule-drift denials; effective AcceptEnv narrows unsafe globals. Renew/close and V1 user/expiry/lifecycle retained; Go/race/vet and seven Node tests pass.
- [x] Canonical command boundary/prerequisites and VM 220/Beryl exact-helper/sudo/rollback design; no privilege/network implementation.
- [x] Revised dogfood approval ID/title/artifact, portfolio/manifest synchronized; controller performs final verification and scoped commit before completion.

All subprocess/tool waits ≤120 seconds. Fixture-only ownership exception uses explicit dev CA and nonprivileged loopback server; never appears in production artifacts. Production policy, gate/executable ancestors and principal files must be root-owned and not user-writable. Native sshd still starts the fixed gate through the account's trusted login shell; no user-controlled environment/startup execution is allowed. Actual allowed executables remain part of the reviewed trusted computing base, not a universal process sandbox.
