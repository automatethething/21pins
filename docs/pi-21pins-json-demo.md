# Demo: Use 21pins with pi (`--mode json`)

This demo routes pi through your local 21pins gateway and shows JSON event output.

## 1) Start 21pins with provider keys

```bash
cd ~/flowstate/repos/21pins

./21pins key set openrouter --value "$OPENROUTER_API_KEY"
./21pins token create pi --scopes proxy:chat,usage:read
# copy the token output

./21pins serve --port 8787
```

Keep this running in a terminal.

## 2) Configure pi to use 21pins as a provider

Create `~/.pi/agent/models.json`:

```json
{
  "providers": {
    "pins21": {
      "baseUrl": "http://127.0.0.1:8787/v1",
      "api": "openai-completions",
      "apiKey": "$PINS21_TOKEN",
      "models": [
        {
          "id": "openrouter/openai/gpt-4o-mini",
          "name": "21pins · GPT-4o mini",
          "reasoning": true,
          "input": ["text", "image"],
          "contextWindow": 128000,
          "maxTokens": 16384,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

Set token env var in your shell:

```bash
export PINS21_TOKEN="<token-from-21pins-token-create>"
```

## 3) Run pi in JSON mode through 21pins

```bash
pi --mode json \
  --provider pins21 \
  --model openrouter/openai/gpt-4o-mini \
  "Explain in one sentence what 21pins does" \
  2>/dev/null | jq -c 'select(.type == "message_end")'
```

You can also inspect tool execution events:

```bash
pi --mode json --provider pins21 --model openrouter/openai/gpt-4o-mini \
  "List files in this directory" 2>/dev/null \
| jq -c 'select(.type|test("tool_execution_"))'
```

## 4) Inspect local usage/costs

```bash
curl -H "Authorization: Bearer $PINS21_TOKEN" http://127.0.0.1:8787/v1/usage | jq .
open http://127.0.0.1:8787/ui
```

Usage rows are recorded separately from policy receipts. The usage endpoint requires `usage:read`; both usage API and UI are loopback-only.

## 5) Optional: use 21pins model catalog to pick model strings

```bash
./21pins models sync --provider openrouter
./21pins models choose --provider openrouter --search gpt
# prints routing-ready model string, e.g. openrouter/openai/gpt-4o-mini
```

---

## Does this also work for OpenClaw and Hermes users?

Yes, if they support:
1. custom OpenAI-compatible `baseURL`
2. bearer token / API key override
3. passing `provider/model` in model IDs
4. optionally adding `X-21Pins-*` policy headers when you want gateway-enforced grants and receipts

If those are configurable, they can route through 21pins the same way.
