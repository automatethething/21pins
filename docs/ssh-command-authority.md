# Native SSH command authority

This supersedes the authentication-only `observe` proposal. Implemented locally and exercised against isolated native OpenSSH; **no VM 220/221 changes are authorized or performed**.

## Two independent boundaries

- **Authentication lease:** who may get short-lived credentials, which workspace/host/Unix account/role, objective, approval and immutable hard deadline. Completion/revocation stops issuance, not already-established connections.
- **Command gate:** the trusted target permits only literal operation argv in a root-owned policy. Purpose remains approval/audit metadata; it is not a shell program, command-content filter or runtime policy input.

New `host add --role observe` defaults to exactly:

| Client operation argv | Fixed executed argv |
| --- | --- |
| `status` | `/usr/bin/uptime` |
| `platform` | `/usr/bin/uname -s` |
| `identity` | `/usr/bin/id -u` |

Not `uptime`, `uname`, arbitrary flags, service restart, file read/write, DNS/network mutation, shell or SFTP. This is a narrowly reviewed executable allowlist, **not a universal read-only OS/process sandbox**. These fixed trusted executables are part of the boundary. A future executable/helper requires security review, not a speculative passthrough.

`21pins ssh exec <id> -- platform` and harness `exec(handle, ['platform'])` send the same literal operation. Unknown/unparseable commands, altered argv, `sh -c`, chaining, redirects, substitutions, globbing, shell escapes and direct wrapper invocation have no matching rule and are denied. The parser supports safe bare tokens and literal single-quoted CLI arguments (including the literal apostrophe escape); it does not evaluate shell syntax. No attacker-derived arguments are appended to execution.

## Native three-layer enforcement

1. Sign a certificate **critical `force-command`** invoking the installed fixed gate with workspace/host/role/**Unix user/rules digest** and root policy path. Existing certificate validation checks exact nested critical-option wire encoding, signature, CA, principal/key/serial/time and extensions. Missing, changed or additional critical options are rejected by issuer delivery verification.
2. Target root-owned `AuthorizedPrincipalsFile` maps the exact principal using identical `command="...",restrict`. Native OpenSSH rejects a conflicting cert/principals forced command; a certificate accidentally omitting its gate still cannot bypass target enforcement.
3. The dedicated account's `Match User` sets the identical server **ForceCommand**, no PTY/forwarding/tunnels/user rc, and no ordinary key/password authentication. Do not derive a role from requested commands or certificate purpose. Different roles use **different Unix accounts**, never an ambiguous shared account.

The gate checks current OS username and policy workspace/host/role; signed SHA256 exact-rule version must match loaded policy. Changing root policy cannot silently broaden outstanding certificates; deploy the corresponding issuer/principals/server version as a coordinated, separately approved update. Drift fails closed.

It rejects root execution, insecure/symlink policy or binary paths, non-root owners and group/world-writable files/ancestors. It also verifies its own binary and fixed executable path, changes cwd to `/`, and uses direct `execve` with only `PATH=/usr/bin:/bin`, `LANG=C`, `LC_ALL=C`, `HOME=/`. Policy parsing is bounded and rejects unknown JSON fields/trailing documents. Root/admin is trusted; these checks are not protection against malicious root replacing trusted code. No command-content storage/session recording is added.

## Target prerequisites — mandatory before approval/install

- Root-owned dedicated account configuration, unprivileged account, no sudo/admin groups and no direct permanent login. Do not use a `nologin` shell: sshd must start the forced gate through a working, trusted login shell.
- Use a root-owned, non-user-configurable **`/bin/sh`** that has no user-controlled noninteractive startup. Shell and native loader run **before** the gate can clean its execution environment. Audit actual `AcceptEnv`, `PermitUserEnvironment`, `SetEnv`, PAM environment and startup paths; no client/user-controlled `BASH_ENV`, `ENV`, `LD_*`, `DYLD_*`, `PATH` or interpreter/startup variables may execute before the gate. Gate-side sanitization alone does not prove this. The generated per-account `AcceptEnv 21PINS_UNUSED` replaces broader global patterns; native fixture verifies this, including unsafe global startup-variable patterns. Recheck that exact effective setting on the target. Keep effective `PermitUserEnvironment no` and `PermitUserRC no`; inspect PAM independently. Prefer root-owned, empty account HOME so no user-writable startup files can run.
- Build target gate with **`CGO_ENABLED=0 go build -o 21pins ./cmd/21pins`**, verify artifact provenance and root-owned executable installation. The target gate needs no issuer state, CA private key, token, socket, daemon or API access. The fixed login shell's startup environment remains a separate check even with a static gate binary.
- Gate `/usr/local/bin/21pins` mode 0755; policy `/etc/ssh/21pins/commands.json` and public principal/CA files root-owned mode 0644; ancestor directories root-owned 0755, no user-writable/symlink path. Verify actual OS executable paths/ownership (do not rely on current-account fixture ownership).
- Use actual owner-reviewed public CA/principal files, current complete `sshd -t` and `sshd -T -C` contexts; preserve recovery policy and test native compatibility on the intended host **after separate approval**. The original VM preflight is stale with respect to new ForceCommand/command-option/gate/environment requirements.

Production `agent` CA mode rejects roles without command authority and every fixture exception. Non-observe registration requires explicit reviewed `--command-allowlist <private JSON rule-array file>`. New observe defaults may be customized only with that explicit owner policy. `--gate-binary`/`--gate-policy` set reviewed target paths. Existing V1 tests retain explicit **development-only legacy authentication**; `--legacy-auth-only` is refused for production agent CA mode. It is not command-authorized dogfood.

## Verification

```sh
go test ./...
go test -race ./...
go vet ./...
PINS21_SSH_INTEGRATION=1 go test ./internal/sshaccess \
  -run 'TestIsolatedCommandAuthority|TestIsolatedOpenSSH' -count=1 -v
```

The new unprivileged dev-CA fixture uses generated public bundle, actual signed critical force-command and real gate dispatch. Allowed literal operation succeeds; shell/chain/substitution/altered-argv/wrapper/subsystem/PTY/forward/raw-key/role/host/force-tamper/policy-drift fail. Same-key renewal and completion issuance denial remain intact. Existing V1 isolation/user/expiry/client/SDK closure tests still pass. Fixture ownership relaxation and disabled StrictModes/source penalties are explicit **local synthetic tests only**, never production prerequisites waived.

Short certificate expiry continues to bound new authentications only. A copied valid credential or established channel may still execute **allowlisted operations** during residual access; it cannot regain arbitrary commands through those windows. Allowed operations/helpers must independently limit their side effects and runtime; this implementation does not kill detached processes or undo changes.

Future privileged role: [fixed-peer dns-admin design](ssh-dns-admin-design.md). Bootstrap review: [host plan](ssh-host-bootstrap.md).
