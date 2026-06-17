# App integration guide

This is the shortest path for an app to use 21pins with hosted identity attestations, attested approvals, policy receipts, and usage tracking.

## 1. Configure provider keys locally

```bash
./21pins init
./21pins key set openrouter --value "$OPENROUTER_API_KEY"
# optional
./21pins key set deepseek --value "$DEEPSEEK_API_KEY"
```

## 2. Create a hosted identity grant

```bash
export PINS21_HOSTED_PUBLIC_KEY_HOSTED_ED25519_V1='<hosted public key>'

./21pins grant create \
  --ck-hosted \
  --capabilities llm.chat \
  --data-classes public \
  --targets openrouter,deepseek \
  --approval-threshold-cents 100
```

Open the printed URL, enter the code, approve with ConsentKeys, then save the returned `grant_id` and `sub`.

## 3. Create an app token and start the gateway

```bash
TOKEN=$(./21pins token create my-app --scopes proxy:chat,usage:read | tail -1)
./21pins serve --port 8787
```

Use the token as the app's `Authorization: Bearer ...` value.

## 4. Send gated traffic

```bash
curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-21Pins-Grant-ID: <grant_id>" \
  -H "X-21Pins-Sub: <sub>" \
  -H "X-21Pins-Capability: llm.chat" \
  -H "X-21Pins-Data-Class: public" \
  -H "X-21Pins-Cost-Cents: 1" \
  -d '{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"pong"}]}'
```

21pins evaluates the grant locally before forwarding. Allowed requests record a signed receipt and usage event.

## 5. Handle approval-required responses

If a request crosses the grant's approval threshold, the evaluation returns an approval ID. Resolve it with a hosted approver attestation:

```bash
./21pins approvals list --grant <grant_id>
./21pins approvals approve <approval_id> --ck-hosted --reason "reviewed"
```

Then retry the gateway request with:

```bash
-H "X-21Pins-Approval-ID: <approval_id>"
```

The gateway only accepts approvals with a valid hosted approver attestation.

## 6. Export proof

```bash
./21pins receipts list --grant <grant_id>
./21pins receipts export <receipt_id> --out receipt.json
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8787/v1/usage
```

The proof bundle for a pilot is:

- hosted grant with `identity_attestation`
- gateway request headers
- signed receipt with `approval_ref` when approval was used
- usage row with provider, model, tokens, estimated cost, and receipt ID

## Pilot acceptance checklist

- Hosted grant creation succeeds.
- At least one OpenRouter or DeepSeek request is allowed through the gateway.
- Usage ledger records tokens/cost.
- Signed receipt verifies.
- Approval-threshold path requires `approvals approve --ck-hosted` and accepts `X-21Pins-Approval-ID` only after attested approval.
