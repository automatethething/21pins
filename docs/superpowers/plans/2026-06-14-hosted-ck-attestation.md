# Hosted CK Attestation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add hosted-first ConsentKeys identity attestations for 21pins grants while preserving local gateway reliability when hosted is unavailable.

**Architecture:** Keep hosted interaction in the CLI layer only. Add signed `IdentityAttestation` metadata to grants, copy its ID into receipts, and verify hosted attestations with pinned Ed25519 public keys from env. The gateway must not call hosted; local grant evaluation stays offline.

**Tech Stack:** Go standard library HTTP/JSON/Ed25519/base64, existing `policy`, `store`, `gateway`, `identity`, and CLI packages, `httptest`, `go test ./...`.

---

## Dirty repo warning

This repo already has inherited uncommitted changes. Do **not** discard them. Do not commit during this plan unless the owner explicitly asks and the inherited changes are included intentionally. If you do commit, show `git status --short` first.

## File structure

- Modify `internal/policy/types.go`
  - Add `IdentityAttestation`.
  - Add optional `Grant.IdentityAttestation`.
  - Add optional `Receipt.IdentityAttestationID`.
- Create `internal/policy/attestation.go`
  - Signable payload shape.
  - Signature verification helper.
  - Env var key ID mapping helper can live here or in CLI; prefer CLI for env access.
- Create `internal/policy/attestation_test.go`
  - Valid/bad/wrong-audience/expired attestation verification tests.
- Modify `internal/policy/receipt.go`
  - Copy attestation ID in `NewReceipt`.
  - Include attestation ID in signable receipt payload.
- Modify `internal/policy/receipt_test.go`
  - Verify receipt signature covers attestation ID.
- Create `internal/hosted/client.go`
  - Small hosted client for status, session start, session polling, and public-key env lookup.
- Create `internal/hosted/client_test.go`
  - `httptest` coverage for reachable/offline status, successful attestation flow, hosted failure.
- Modify `cmd/21pins/main.go`
  - Add `hosted status [--json] [--hosted-url URL]`.
  - Add `grant create --ck-hosted [--hosted-url URL]`.
  - Keep `--sub` and `--ck-whoami` behavior unchanged.
  - Add local status note for hosted-attested grants.
- Modify `README.md`
  - Document hosted CK attestation usage and env vars.
- Update dashboard after implementation:
  - `ideas/PORTFOLIO.md`
  - `dashboard/project-status.json`

---

### Task 1: Add attestation model and verification

**Files:**
- Modify: `internal/policy/types.go`
- Create: `internal/policy/attestation.go`
- Create: `internal/policy/attestation_test.go`

- [ ] **Step 1: Write failing attestation verification tests**

Create `internal/policy/attestation_test.go`:

```go
package policy

import (
    "crypto/ed25519"
    "crypto/rand"
    "testing"
    "time"
)

func signedTestAttestation(t *testing.T, mutate func(*IdentityAttestation), now time.Time) (IdentityAttestation, ed25519.PublicKey) {
    t.Helper()
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    a := IdentityAttestation{
        ID: "att_123",
        Subject: "ck_sub_abc",
        Issuer: "https://21pins.com",
        Audience: "21pins",
        Method: "hosted_ck",
        IssuedAt: now.Add(-time.Minute),
        ExpiresAt: now.Add(time.Hour),
        KeyID: "hosted-ed25519-v1",
    }
    if mutate != nil { mutate(&a) }
    signed, err := SignIdentityAttestationForTest(a, priv)
    if err != nil { t.Fatal(err) }
    return signed, pub
}

func TestVerifyIdentityAttestationValid(t *testing.T) {
    now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
    a, pub := signedTestAttestation(t, nil, now)
    if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err != nil {
        t.Fatalf("expected valid attestation: %v", err)
    }
}

func TestVerifyIdentityAttestationRejectsBadSignature(t *testing.T) {
    now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
    a, pub := signedTestAttestation(t, nil, now)
    a.Subject = "ck_sub_evil"
    if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err == nil {
        t.Fatal("expected bad signature rejection")
    }
}

func TestVerifyIdentityAttestationRejectsWrongAudience(t *testing.T) {
    now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
    a, pub := signedTestAttestation(t, func(a *IdentityAttestation) { a.Audience = "other" }, now)
    if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err == nil {
        t.Fatal("expected wrong audience rejection")
    }
}

func TestVerifyIdentityAttestationRejectsExpired(t *testing.T) {
    now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
    a, pub := signedTestAttestation(t, func(a *IdentityAttestation) { a.ExpiresAt = now.Add(-time.Second) }, now)
    if err := VerifyIdentityAttestation(a, pub, "https://21pins.com", now); err == nil {
        t.Fatal("expected expired rejection")
    }
}
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./internal/policy -run IdentityAttestation -v
```

Expected: FAIL because `IdentityAttestation`, `VerifyIdentityAttestation`, and `SignIdentityAttestationForTest` do not exist.

- [ ] **Step 3: Add minimal types**

In `internal/policy/types.go` add:

```go
type IdentityAttestation struct {
    ID        string    `json:"attestation_id"`
    Subject   string    `json:"subject"`
    Issuer    string    `json:"issuer"`
    Audience  string    `json:"audience"`
    Method    string    `json:"method"`
    IssuedAt  time.Time `json:"issued_at"`
    ExpiresAt time.Time `json:"expires_at"`
    KeyID     string    `json:"key_id"`
    Signature string    `json:"signature"`
}
```

Add to `Grant`:

```go
IdentityAttestation *IdentityAttestation `json:"identity_attestation,omitempty"`
```

Add to `Receipt`:

```go
IdentityAttestationID string `json:"identity_attestation_id,omitempty"`
```

- [ ] **Step 4: Implement attestation verification**

Create `internal/policy/attestation.go`:

```go
package policy

import (
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "errors"
    "regexp"
    "strings"
    "time"
)

var ckSubPattern = regexp.MustCompile(`^ck_sub_[A-Za-z0-9_-]+$`)

type signableIdentityAttestation struct {
    ID        string    `json:"attestation_id"`
    Subject   string    `json:"subject"`
    Issuer    string    `json:"issuer"`
    Audience  string    `json:"audience"`
    Method    string    `json:"method"`
    IssuedAt  time.Time `json:"issued_at"`
    ExpiresAt time.Time `json:"expires_at"`
    KeyID     string    `json:"key_id"`
}

func VerifyIdentityAttestation(a IdentityAttestation, publicKey ed25519.PublicKey, expectedIssuer string, now time.Time) error {
    if strings.TrimSpace(a.ID) == "" { return errors.New("missing attestation id") }
    if !ckSubPattern.MatchString(a.Subject) { return errors.New("invalid attestation subject") }
    if a.Issuer != expectedIssuer { return errors.New("invalid attestation issuer") }
    if a.Audience != "21pins" { return errors.New("invalid attestation audience") }
    if a.Method != "hosted_ck" { return errors.New("invalid attestation method") }
    if now.Before(a.IssuedAt) || !now.Before(a.ExpiresAt) { return errors.New("attestation is not currently valid") }
    payload, err := identityAttestationPayloadBytes(a)
    if err != nil { return err }
    sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
    if err != nil { return err }
    if !ed25519.Verify(publicKey, payload, sig) { return errors.New("invalid attestation signature") }
    return nil
}

func identityAttestationPayloadBytes(a IdentityAttestation) ([]byte, error) {
    return json.Marshal(signableIdentityAttestation{
        ID: a.ID, Subject: a.Subject, Issuer: a.Issuer, Audience: a.Audience,
        Method: a.Method, IssuedAt: a.IssuedAt, ExpiresAt: a.ExpiresAt, KeyID: a.KeyID,
    })
}

func SignIdentityAttestationForTest(a IdentityAttestation, privateKey ed25519.PrivateKey) (IdentityAttestation, error) {
    payload, err := identityAttestationPayloadBytes(a)
    if err != nil { return IdentityAttestation{}, err }
    a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
    return a, nil
}
```

- [ ] **Step 5: Run policy tests**

Run:

```bash
go test ./internal/policy -v
```

Expected: PASS.

---

### Task 2: Include attestation reference in receipts

**Files:**
- Modify: `internal/policy/receipt.go`
- Modify: `internal/policy/receipt_test.go`

- [ ] **Step 1: Write failing receipt coverage test**

Add to `internal/policy/receipt_test.go`:

```go
func TestReceiptIncludesIdentityAttestationIDAndSignatureCoversIt(t *testing.T) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
    grant := Grant{
        ID: "grt_123",
        Sub: "ck_sub_abc",
        Pins: Pins{
            Identity: IdentityPin{Sub: "ck_sub_abc"},
            Authority: AuthorityPin{Chain: []string{"ck_sub_abc"}},
        },
        IdentityAttestation: &IdentityAttestation{ID: "att_123", Subject: "ck_sub_abc"},
    }
    req := ActionRequest{GrantID: grant.ID, Sub: "ck_sub_abc", Capability: "llm.chat", DataClass: "public", Target: "openrouter"}
    result := EvaluationResult{Decision: DecisionAllow, PinStates: map[string]PinStatus{"identity":"pass"}}
    receipt := NewReceipt(grant, req, result, now)
    if receipt.IdentityAttestationID != "att_123" { t.Fatalf("missing attestation id: %+v", receipt) }
    signed, err := SignReceipt(receipt, priv, "test-key")
    if err != nil { t.Fatal(err) }
    if err := VerifyReceipt(signed, pub); err != nil { t.Fatalf("verify failed: %v", err) }
    signed.IdentityAttestationID = "att_other"
    if err := VerifyReceipt(signed, pub); err == nil { t.Fatal("expected tampered attestation id to fail") }
}
```

Ensure imports include `crypto/ed25519`, `crypto/rand`, and `time` if absent.

- [ ] **Step 2: Run test and verify failure**

```bash
go test ./internal/policy -run ReceiptIncludesIdentityAttestationID -v
```

Expected: FAIL because `NewReceipt` does not copy ID and signable receipt omits it.

- [ ] **Step 3: Update receipt creation/signing**

In `internal/policy/receipt.go`:

- Build `r := Receipt{...}` in `NewReceipt`.
- If `grant.IdentityAttestation != nil`, set `r.IdentityAttestationID = grant.IdentityAttestation.ID`.
- Return `r`.
- Add `IdentityAttestationID string` to `signableReceipt`.
- Copy it in `receiptPayloadBytes`.

- [ ] **Step 4: Run policy tests**

```bash
go test ./internal/policy -v
```

Expected: PASS.

---

### Task 3: Add hosted client package

**Files:**
- Create: `internal/hosted/client.go`
- Create: `internal/hosted/client_test.go`

- [ ] **Step 1: Write failing hosted client tests**

Create `internal/hosted/client_test.go` with tests for:

```go
func TestPublicKeyEnvName(t *testing.T) {
    if got := PublicKeyEnvName("hosted-ed25519-v1"); got != "PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1" {
        t.Fatalf("unexpected env name: %s", got)
    }
}
```

Add an `httptest` successful session:

- server handles `POST /v1/ck/attestation-sessions`
- returns `cas_123`, URL, code, expiry, poll interval `0`
- server handles `GET /v1/ck/attestation-sessions/cas_123`
- returns `approved` plus signed attestation
- client verifies and returns attestation

Add offline status test:

- client points to `http://127.0.0.1:1`
- `Status` returns offline/degraded without panic.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/hosted -v
```

Expected: FAIL because package does not exist.

- [ ] **Step 3: Implement minimal hosted client**

Create `internal/hosted/client.go`:

Types:

```go
type Client struct { BaseURL string; HTTPClient *http.Client }
type Status struct { URL string `json:"url"`; State string `json:"state"`; CheckedAt time.Time `json:"checked_at"`; CKAttestationAvailable bool `json:"ck_attestation_available"`; Error string `json:"error,omitempty"` }
type SessionStart struct { SessionID, VerificationURL, UserCode string; ExpiresAt time.Time; PollIntervalSeconds int }
type PollResponse struct { Status string; Attestation *policy.IdentityAttestation; Error string }
```

Functions:

```go
func DefaultBaseURL() string
func PublicKeyEnvName(keyID string) string
func PublicKeyFromEnv(keyID string) (ed25519.PublicKey, error)
func (c Client) Status(ctx context.Context) Status
func (c Client) StartAttestationSession(ctx context.Context, ttlMinutes int) (SessionStart, error)
func (c Client) PollAttestation(ctx context.Context, sessionID string) (PollResponse, error)
func (c Client) CompleteHostedAttestation(ctx context.Context, ttlMinutes int, expectedIssuer string, now time.Time, out io.Writer) (policy.IdentityAttestation, error)
```

Keep it boring:

- `DefaultBaseURL()` returns `PINS21_HOSTED_URL` or `https://21pins.com`.
- `Status` can GET `/health`; if 2xx, mark reachable. If not, offline.
- `CompleteHostedAttestation` prints URL/code, polls until approved/denied/expired/context done, loads public key by `attestation.KeyID`, verifies, returns attestation.
- Base64 public key env value accepts standard or raw URL encoding; choose one if implementing both is not worth it. Prefer standard base64 because Go uses it elsewhere in this repo.

- [ ] **Step 4: Run hosted tests**

```bash
go test ./internal/hosted -v
```

Expected: PASS.

---

### Task 4: Wire CLI hosted status and ck-hosted grant creation

**Files:**
- Modify: `cmd/21pins/main.go`
- Add tests if practical: `cmd/21pins/hosted_test.go` or use package-level helper tests.

- [ ] **Step 1: Extract grant creation helper if needed**

If `handleGrant` becomes too large, add a small helper:

```go
type grantCreateOptions struct { ... }
func createGrantFromOptions(st *store.Store, opts grantCreateOptions) (policy.Grant, error)
```

Do not refactor unrelated CLI code.

- [ ] **Step 2: Add `hosted` command to CLI usage and switch**

In `main()` add:

```go
case "hosted":
    handleHosted(os.Args[2:])
```

In `usage()` add:

```text
hosted status [--json] [--hosted-url URL]
```

- [ ] **Step 3: Implement `handleHosted`**

`hosted status` flags:

- `--json`
- `--hosted-url`

Output plain text by default, JSON if requested.

- [ ] **Step 4: Add `--ck-hosted` to grant create**

Add flags:

```go
ckHosted := fs.Bool("ck-hosted", false, "verify ConsentKeys identity through hosted 21pins control plane")
hostedURL := fs.String("hosted-url", "", "hosted 21pins control plane URL")
```

Validation:

- Reject using `--ck-hosted` with `--sub` or `--ck-whoami`.
- For `--ck-hosted`, call hosted client and use `attestation.Subject` as `resolvedSub`.
- Store `IdentityAttestation: &attestation` in the grant.

- [ ] **Step 5: Add local status note**

In `handleStatus`, count grants with `IdentityAttestation != nil` and print:

```text
Hosted identity attestations: N
```

- [ ] **Step 6: Run CLI tests/build**

```bash
go test ./cmd/21pins -v
go build -o /tmp/21pins-hosted-ck ./cmd/21pins
/tmp/21pins-hosted-ck hosted status --json
```

Expected: tests pass, build passes, hosted status returns JSON even if offline/degraded.

---

### Task 5: End-to-end fake hosted smoke tests

**Files:**
- Prefer tests in `internal/hosted/client_test.go` and `cmd/21pins` helper tests.
- If CLI subprocess tests are too much, do not add brittle shell tests.

- [ ] **Step 1: Add fake hosted grant creation coverage**

Use `httptest` and helper functions rather than shelling out if possible:

- fake hosted returns signed attestation for `ck_sub_hosted`
- public key env is set via `t.Setenv(PublicKeyEnvName(keyID), base64Pub)`
- grant creation helper returns a grant
- assert `grant.Sub == "ck_sub_hosted"`
- assert `grant.IdentityAttestation.ID == "att_123"`

- [ ] **Step 2: Add hosted failure coverage**

Fake hosted returns 500 or offline. Assert no grant is created and error is clear.

- [ ] **Step 3: Run focused tests**

```bash
go test ./cmd/21pins ./internal/hosted ./internal/policy -v
```

Expected: PASS.

---

### Task 6: Docs and dashboard updates

**Files:**
- Modify: `README.md`
- Modify: `/Users/claw/flowstate/ideas/PORTFOLIO.md`
- Modify: `/Users/claw/flowstate/dashboard/project-status.json`

- [ ] **Step 1: README hosted CK docs**

Add concise docs:

```bash
export PINS21_HOSTED_URL=https://21pins.com
export PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1=<base64-public-key>
21pins hosted status
21pins grant create --ck-hosted --capabilities llm.chat --data-classes public --targets openrouter
```

Explain:

- hosted is only used for creating hosted-verified grants
- gateway request evaluation remains local/offline
- `--sub` and `--ck-whoami` remain available for local-only use

- [ ] **Step 2: Dashboard updates**

Update portfolio/dashboard only after tests pass:

- `ideas/PORTFOLIO.md`: mention hosted CK attestation path if implemented.
- `dashboard/project-status.json`: change blocker from CK identity attestations + hosted reliability to whatever remains. If only fake-hosted/local implementation exists, be honest: "hosted protocol implemented; production hosted deployment still pending".

- [ ] **Step 3: Validate docs/data**

```bash
cd /Users/claw/flowstate
python3 -m json.tool dashboard/project-status.json >/dev/null
node -c dashboard/manifest.js
```

Expected: no output/errors.

---

### Task 7: Final verification and review

**Files:** all touched files.

- [ ] **Step 1: Run full test suite**

```bash
cd /Users/claw/flowstate/repos/21pins
go test ./...
go build -o /tmp/21pins-hosted-ck ./cmd/21pins
```

Expected: PASS.

- [ ] **Step 2: Run static checks**

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 3: Manual local reliability check**

With hosted offline:

```bash
/tmp/21pins-hosted-ck hosted status --json
```

Expected: exits successfully with state `offline` or `degraded`; local gateway behavior is unaffected.

- [ ] **Step 4: Code review**

Ask reviewer to inspect the uncommitted diff against:

- `docs/superpowers/specs/2026-06-14-hosted-ck-attestation-design.md`
- this plan

Focus:

- no CLI-claimed `ck_sub` gets signed
- unknown hosted keys rejected
- attestation ID included in signed receipt payload
- gateway makes no hosted calls
- existing `--sub`/`--ck-whoami` remain compatible

- [ ] **Step 5: Final status**

Report:

- changed files
- tests run
- manual smoke results
- whether production hosted deployment remains pending
- dirty repo status
