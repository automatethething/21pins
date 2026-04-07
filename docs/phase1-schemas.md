# 21pins Phase 1 Schemas

## Grant (canonical)

```json
{
  "grant_id": "grt_...",
  "sub": "ck_sub_...",
  "status": "active|revoked|expired",
  "delegated_by": "ck_sub_...",
  "pins": {
    "identity": { "sub": "ck_sub_..." },
    "authority_chain": { "chain": ["ck_sub_root", "ck_sub_agent"] },
    "capabilities": { "allowed": ["llm.chat"] },
    "data_policy": { "allowed_classes": ["public", "internal"] },
    "spend_policy": {
      "limit_cents": 10000,
      "spent_cents": 500,
      "window_start": "...",
      "window_end": "..."
    },
    "execution_targets": { "allowed_targets": ["openrouter"] },
    "approval_policy": { "threshold_cents": 5000 }
  },
  "created_at": "...",
  "updated_at": "...",
  "revoked_at": null
}
```

## Signed Grant Export (operational)

- Format: `base64url(payload).base64url(signature)`
- Signature: Ed25519 (local 21pins keypair)
- Default TTL: 15 minutes

Payload:

```json
{
  "grant_id": "grt_...",
  "sub": "ck_sub_...",
  "pins_snapshot": { "...": "..." },
  "issued_at": "...",
  "expires_at": "...",
  "key_id": "local-ed25519-v1"
}
```

## Evaluation output

```json
{
  "decision": "allow|block|require_approval",
  "pin_states": {
    "identity": "pass|fail|requires_approval",
    "authority_chain": "pass|fail|requires_approval",
    "capabilities": "pass|fail|requires_approval",
    "data_policy": "pass|fail|requires_approval",
    "spend_policy": "pass|fail|requires_approval",
    "execution_targets": "pass|fail|requires_approval",
    "approval": "pass|fail|requires_approval"
  },
  "reasons": {
    "approval": "cost crosses approval threshold"
  }
}
```

## Approval request (Pin 7)

```json
{
  "approval_id": "apr_...",
  "grant_id": "grt_...",
  "receipt_id": "rcp_...",
  "sub": "ck_sub_...",
  "capability": "llm.chat",
  "data_class": "public",
  "target": "openrouter",
  "cost_cents": 250,
  "status": "pending|approved|rejected",
  "requested_at": "...",
  "resolved_at": "...",
  "approver_sub": "ck_sub_admin",
  "reason": "manual review result"
}
```

## Execution receipt (stored)

```json
{
  "receipt_id": "rcp_...",
  "grant_id": "grt_...",
  "sub": "ck_sub_...",
  "authority_chain": ["..."],
  "pin_states": { "...": "..." },
  "decision": "allow|block|require_approval",
  "capability": "llm.chat",
  "data_class": "public",
  "target": "openrouter",
  "cost_cents": 250,
  "approval_ref": "optional",
  "created_at": "...",
  "key_id": "local-ed25519-v1",
  "signature": "base64url-ed25519"
}
```

## Receipt artifact (CLI output/export)

```json
{
  "receipt_id": "rcp_...",
  "subject": "ck_sub_...",
  "capability": "data.lookup",
  "cost_cents": 250,
  "target": "api.vendor.com",
  "pin_results": { "...": "..." },
  "decision": "ALLOW|BLOCK|REQUIRE_APPROVAL",
  "approval_id": "apr_...",
  "signature": "...",
  "signature_key_id": "local-ed25519-v1",
  "signature_verified": true
}
```
