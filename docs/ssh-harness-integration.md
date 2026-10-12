# SSH harness integration

## Objective ownership

A lease belongs to the objective/controller, not a single model call or worker. Keep one `SSHObjectiveHarness` instance per owning harness. Pi, agy and Claude can use its authorized lease handle while working for that objective; they do not get a CA/admin credential or a copied long-lived SSH key. Changing worker does not change the immutable agent-class/actor binding or create a new key.

Native authorization still checks the same authenticated app identity. Sharing a handle between workers on the same machine is delegation of work by the controlling harness, **not** multi-hop capability delegation or permission to copy private material to another machine. One objective writer is enforced for overlapping exec operations.

## Standard-library Node adapter

```js
import { SSHObjectiveHarness } from '../npm/lib/ssh-harness.mjs';

const harness = new SSHObjectiveHarness({
  binary: '/project/build/21pins',
  cwd: '/project',
  agentClass: 'pi',
});
const lease = await harness.ensureCapability({
  type: 'ssh',
  host: 'devbox',
  role: 'observe',
  objective: 'verify-service',
  purpose: 'verify synthetic development service',
  estimate: '45m',
});
await harness.exec(lease, ['printf', '%s\n', 'synthetic']);
await harness.onObjectiveStatus('verify-service', 'COMPLETE');
```

Use one separate lease per host. `ensureCapability` serializes creation, deduplicates objective/host/role handles and forbids changed purpose. Terminal objectives cannot silently reopen through the same adapter. A pending handle can become authorized through the separate administrator approval workflow; subsequent CLI exec re-checks current lease status and obtains its certificate with the same key.

`exec` invokes the native 21pins CLI using an argument array and direct SSH. stdout/stderr default to the harness terminal; the adapter returns exit status, not captured/recorded SSH content. A caller can provide its own stdio channels, but any content handling then belongs to that harness—not the 21pins authorization/credential server. Argument arrays are quoted for the remote shell without local shell interpolation; role/OS policy, not this quoting, limits remote command privilege.

Each agent exec defaults to a 120-second bounded invocation; set `timeoutMs` only within 1–120000 milliseconds. Split longer automated work into explicit checkpoints. Lease authorization can remain active for hours across many calls; no background renewal timer is spawned. CLI credential renewal occurs before a command when remaining validity is below the configured threshold. A long established session does not need renewal to stay connected; that is a documented limitation, not an authorization extension.

Supply only an agent `ssh:use` credential through a private token file referenced by `PINS21_SSH_TOKEN_FILE`. SDK environment is never persisted/returned. `PINS21_SSH_API_URL` selects the existing loopback issuer gateway, `PINS21_SSH_RUNTIME_DIR` selects the private client cache, and optional `PINS21_SSH_CONFIG_FILE` selects local aliases. `PINS21_SSH_DIR` belongs only to local issuer administration; requester operations never read it or the provider state file. Do not include a CA socket or administrator credential in worker environments.

## Terminal events and crashes

Mandatory owning-harness calls:
- COMPLETE → complete all that objective's leases.
- OWNER_BLOCKED → cancel leases; reauthorization is a later explicit objective action.
- CANCELLED/explicit stop → cancel leases.
- Graceful shutdown → `shutdown()` all handles.

Terminal processing marks the objective closed before queued work proceeds, terminates the owned local SSH process and attempts server-side lease closure. It unlinks that handle's key/certificate directory even if closure cannot be confirmed; errors are reported, never called successful. Unconfirmed closure retains metadata-only CLOSING handles and terminal intent for `retryClosures()`; restoration keeps those objectives closed to execution. Pi automatically retries them on session startup. Do not claim server-side closure while these retries remain unconfirmed; hard lease expiry is the fallback for renewal authorization, and certificate expiry bounds already-issued new logins. Node CLI calls have bounded timeouts. Dedicated standalone Node harnesses can use `installSignalHandlers()` for SIGTERM best-effort cleanup followed by normal signal termination. Applications with their own signal handling should call `shutdown()` instead.

The Go client forwards SIGTERM/interrupt to its owned SSH process group, closes that lease best effort and removes its local cache. SIGKILL/crash cannot run cleanup: there is no new renewal, issued certificates expire, and lease hard expiry rejects later issuance. Startup/status sweeps remove expired/terminal cache files; stale opening scratch directories are cleaned on later startup. No secure physical erase or crash-time key deletion guarantee is made.

Do **not** treat model-call completion, `agent_end`, a worker exit or a supervisor notification as objective completion. No lease is extended past its hard deadline; a new authorized lease is required afterward.

## Pi extension

Opt-in repository integration:

```sh
pi --extension ./examples/pi-ssh-leases.ts
```

The npm payload contains `lib/pi-ssh-extension.ts` and `lib/ssh-harness.mjs`. No global Pi settings/extensions were modified by this build. Load only in the exact owning project, using its bounded private configuration/agent credential environment.

The extension:
- Initializes the adapter on `session_start`, restores safe logical handle metadata from the current branch, retries any pending terminal closure, and persists no private keys/certificate bodies/SSH content.
- Exposes `ssh_ensure_capability` for purpose-bound requests; returns only logical lease metadata.
- Observes a successful durable `objective_control` terminal result: complete/block closes all leases owned by that session. Rejected completion checks do **not** close them. The current adapter matches the successful canonical result text; a different objective extension should wire the SDK to its structured terminal event.
- Provides `/ssh-stop` for explicit session cancellation and idempotent `session_shutdown` cleanup.
- Does not infer completion from prose or `agent_end`.

Use `21pins ssh exec <lease-id> -- ...` from the owning worker, or the SDK `exec` method. The model never needs to read the runtime key file. For agy/Claude controllers, wire their real objective status/cancellation signals to `onObjectiveStatus` and their shutdown to `shutdown`; there is no assumed universal CLI lifecycle event shared by those applications.

## Verification

```sh
go test ./...
node --test npm/test/*.test.js
PINS21_SSH_INTEGRATION=1 go test ./internal/sshaccess -run TestIsolatedOpenSSH -count=1 -v
```

`npm/test/pi-ssh-extension.test.js` additionally loads the actual TypeScript extension using installed Pi/jiti when `PINS21_PI_PACKAGE` points to the installed Pi package directory. This test uses a synthetic lifecycle CLI, verifies rejected terminal transitions leave leases open, accepted terminal transitions close them, and session shutdown is idempotent. The real SSH fixture separately executes the real CLI/Node SDK through renewal and verifies local key deletion on objective completion.
