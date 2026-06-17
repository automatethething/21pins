# Hosted CK Attestation + Control Plane Reliability Design

Date: 2026-06-14
Status: Draft for review

## Goal

Remove the current 21pins rollout blocker by adding a hosted-first ConsentKeys identity verification path while preserving 21pins' local-first reliability. New hosted-verified grants should carry a verifiable control-plane attestation, and existing local grants must keep working when hosted services are unavailable.

This is the smallest hosted-first slice. It does not build a full hosted dashboard, hosted approvals, multi-device sync, billing, or hosted policy evaluation.

## Current state

- `grant create --ck-whoami` resolves a `ck_sub` by parsing local `ck whoami` output.
- `policy.Grant` stores `Sub`, `Pins.Identity.Sub`, and authority chain only.
- `policy.Receipt` records the subject and grant decision, but no identity attestation reference.
- The local gateway can enforce grants without hosted dependencies.

## Non-goals

- No full hosted control-plane product.
- No hosted grant sync beyond the attestation exchange.
- No hosted approval workflow in this slice.
- No mandatory hosted dependency for existing local grants.
- No browser UI changes beyond docs/status text.

## User-facing behavior

### Hosted status

Add:

```bash
21pins hosted status [--json]
```

It reports:

- configured hosted URL
- reachable/degraded/offline
- last checked time
- whether hosted CK attestation is available

Default hosted URL should be configurable with `PINS21_HOSTED_URL`, falling back to the production 21pins control-plane URL once one exists. For local development/tests, allow `--hosted-url` flags on commands that call hosted.

### Hosted CK grant creation

Add:

```bash
21pins grant create --ck-hosted \
  --capabilities llm.chat \
  --data-classes public \
  --targets openrouter
```

Behavior:

1. CLI requests a hosted CK attestation from the configured 21pins control plane.
2. Hosted verifies ConsentKeys identity server-side.
3. Hosted returns a signed attestation artifact.
4. CLI verifies the hosted signature against a configured/trusted public key.
5. CLI creates a local grant whose `Sub` and `Pins.Identity.Sub` come from the verified attestation.
6. `grant inspect` shows the attestation metadata.

If hosted is unreachable, invalid, expired, or returns a subject that cannot be verified, `--ck-hosted` fails clearly and does not create a grant.

Existing `--sub` and `--ck-whoami` continue to work, but `--ck-hosted` is the preferred broad-rollout path.

## Attestation data model

Add to `policy`:

```go
type IdentityAttestation struct {
    ID        string    `json:"attestation_id"`
    Subject   string    `json:"subject"`
    Issuer    string    `json:"issuer"`
    Audience  string    `json:"audience"`
    Method    string    `json:"method"` // hosted_ck
    IssuedAt  time.Time `json:"issued_at"`
    ExpiresAt time.Time `json:"expires_at"`
    KeyID     string    `json:"key_id"`
    Signature string    `json:"signature"`
}
```

Add optional attestation to grants:

```go
type Grant struct {
    ...
    IdentityAttestation *IdentityAttestation `json:"identity_attestation,omitempty"`
}
```

Add receipt reference, not full artifact duplication:

```go
type Receipt struct {
    ...
    IdentityAttestationID string `json:"identity_attestation_id,omitempty"`
}
```

Receipt signing payload must include `IdentityAttestationID` when present, so exported receipts cannot silently swap identity references.

## Hosted API contract

The hosted service must determine the CK subject from a server-side ConsentKeys auth session. The CLI must never send a claimed `ck_sub` for signing.

Use a device/browser-style exchange so this works with today's CK CLI surface, which has `ck login`/`ck whoami` but no stable `ck token` command.

### 1. Start attestation session

```http
POST /v1/ck/attestation-sessions
Content-Type: application/json
```

Request:

```json
{
  "audience": "21pins",
  "purpose": "grant_create",
  "requested_ttl_minutes": 1440
}
```

Response:

```json
{
  "session_id": "cas_...",
  "verification_url": "https://21pins.com/ck/attest?session=cas_...",
  "user_code": "ABCD-EFGH",
  "expires_at": "2026-06-14T00:10:00Z",
  "poll_interval_seconds": 2
}
```

The CLI opens or prints `verification_url`. The hosted page requires the user to enter `user_code`, then authenticates the user with ConsentKeys OIDC and binds the verified CK subject to `session_id` server-side. The code check proves the browser session is approving the same terminal-created attestation session.

### 2. Poll attestation session

```http
GET /v1/ck/attestation-sessions/{session_id}
```

Pending response:

```json
{ "status": "pending" }
```

Approved response:

```json
{
  "status": "approved",
  "attestation": {
    "attestation_id": "att_...",
    "subject": "ck_sub_...",
    "issuer": "https://21pins.com",
    "audience": "21pins",
    "method": "hosted_ck",
    "issued_at": "2026-06-14T00:00:00Z",
    "expires_at": "2026-06-15T00:00:00Z",
    "key_id": "hosted-ed25519-v1",
    "signature": "base64url-ed25519-signature"
  }
}
```

Denied/expired responses return `status: "denied"` or `status: "expired"` with a human-readable error. The hosted service signs only subjects produced by its ConsentKeys OIDC callback for that session.

The signed payload is the JSON serialization of all attestation fields except `signature`, with stable field names. The CLI verifies:

- signature is valid for `key_id`
- `issuer` matches configured hosted URL/allowed issuer
- `audience == "21pins"`
- `method == "hosted_ck"`
- current time is within `[issued_at, expires_at]`
- `subject` matches `ck_sub_...`

## Hosted public key trust

The CLI rejects attestations with unknown `key_id`.

For this slice, support one boring trust path:

- `PINS21_HOSTED_PUBLIC_KEY_<KEY_ID>` env var, where non-alphanumeric key ID characters are converted to underscores and uppercased, e.g. `hosted-ed25519-v1` -> `PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1`.

Future work can add `21pins hosted trust-key`, hosted JWKS, and rotation UX. Do not auto-trust keys fetched from the same endpoint that is being verified.

## Local reliability rules

1. Existing local grants keep evaluating when hosted is offline.
2. Hosted is required only for creating new `--ck-hosted` grants or refreshing expired hosted attestations.
3. Gateway request evaluation never calls hosted in this slice.
4. If a grant has an expired attestation, local evaluation still allows it unless a future explicit policy flag requires fresh hosted identity. This avoids surprise production outages.
5. `21pins hosted status` must expose hosted failures without blocking local routing.

## Gateway behavior

No hosted network calls in `internal/gateway`.

When a request is allowed and a receipt is created from a grant with an attestation, `policy.NewReceipt` copies `grant.IdentityAttestation.ID` into `Receipt.IdentityAttestationID`.

## CLI behavior

- `grant inspect` prints attestation metadata when present.
- `grant list` can remain unchanged for this slice.
- `status` adds a simple local note if any hosted-attested grants exist.
- `hosted status` performs the network health/attestation capability check.

## Testing

Unit tests:

- attestation signature verification succeeds for valid hosted artifact
- verification fails for bad signature
- verification fails for wrong audience
- verification fails for expired attestation
- `grant create --ck-hosted` stores attestation and subject from attestation
- `grant create --ck-hosted` creates no grant when hosted fails
- receipt includes attestation ID and signature verification covers it
- gateway policy evaluation does not call hosted

Integration-ish tests with `httptest`:

- fake hosted endpoint returns signed attestation; CLI creates grant
- fake hosted endpoint unreachable; CLI exits with clear error
- `hosted status --json` reports reachable/offline
- attestation sessions never sign a CLI-supplied subject

Verification commands:

```bash
go test ./...
go build -o /tmp/21pins-hosted-ck ./cmd/21pins
```

Manual smoke with fake hosted endpoint is enough for this slice. Real hosted deployment can follow once endpoint ownership, OIDC callback URL, and hosted signing key are finalized.

## Future work

- `21pins hosted trust-key` command for pinned hosted public keys.
- Hosted JWKS with out-of-band pinning/rotation.
- Attestation refresh command and `hosted status` warnings for expired grant attestations.
- Optional policy flag requiring fresh hosted identity for specific high-risk grants.

## Dashboard update requirement

After implementation, update:

- `ideas/PORTFOLIO.md`
- `dashboard/project-status.json`

Only mark the blocker resolved when both hosted CK grant creation and offline local gateway fallback are verified.
