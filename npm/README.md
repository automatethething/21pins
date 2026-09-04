# 21pins

**Never accidentally share your LLM API keys again.**

21pins is a local-first CLI and localhost gateway for LLM apps, agents, and experiments. Store your provider keys once on your own machine, then give each app a scoped 21pins token instead of handing out real OpenAI, OpenRouter, Anthropic, DeepSeek, Venice, Hetzner, Maple, Gemini, or Ollama credentials.

It speaks the OpenAI-compatible `/v1/chat/completions` shape, so many tools can use it by changing only the base URL, API key, and model name.

## Why use it?

- **Stop pasting real provider keys into every prototype.** Use one local 21pins token per app or agent.
- **Never ship a real API key in a repo by mistake.** Apps talk to `127.0.0.1`; provider keys stay in your local 21pins state file.
- **Give agents narrower permissions.** A Pi token can have `proxy:chat,usage:read` without exposing your upstream OpenRouter key.
- **See surprise bills before they become surprise bills.** 21pins records local token usage and estimated API cost for routed chat calls.
- **Switch providers without rewriting every client.** Route models like `openrouter/openai/gpt-4o-mini`, `openai/gpt-4o-mini`, or `ollama/llama3.2` through one local gateway.
- **Tinker with less anxiety.** Build weird agent workflows, demos, and side projects without spraying secrets across shells, env files, and dashboards.

## Install

```bash
npm install -g 21pins
```

Then initialize local state:

```bash
21pins init
```

Your local state is separate from the npm package. Upgrading or reinstalling the npm package does not delete your stored keys, tokens, grants, receipts, or usage rows.

Default state paths:

```text
Linux:  ~/.config/21pins/state.json
macOS:  ~/Library/Application Support/21pins/state.json
```

Set `PINS21_STATE_PATH` if you want to store state somewhere else.

## Quickstart: Pi → 21pins → OpenRouter

Add your OpenRouter key once:

```bash
21pins key set openrouter --value "$OPENROUTER_API_KEY"
```

Create a scoped token for Pi or another local app:

```bash
21pins token create pi --scopes proxy:chat,usage:read
```

Start the local gateway:

```bash
21pins serve --port 8787
```

Configure your OpenAI-compatible client:

```text
Base URL: http://127.0.0.1:8787/v1
API key:  the 21pins token, not your OpenRouter key
Model:    openrouter/openai/gpt-4o-mini
```

21pins forwards the request with your stored OpenRouter key and records local usage/cost data when the upstream response includes usage.

## JavaScript example

```js
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.PINS21_TOKEN,
  baseURL: "http://127.0.0.1:8787/v1",
});

const response = await client.chat.completions.create({
  model: "openrouter/openai/gpt-4o-mini",
  messages: [{ role: "user", content: "Say pong." }],
});

console.log(response.choices[0].message.content);
```

## Usage and cost dashboard

Create your app token with `usage:read`, start the gateway, then open:

```text
http://127.0.0.1:8787/ui
```

Or fetch JSON:

```bash
curl -H "Authorization: Bearer $PINS21_TOKEN" \
  http://127.0.0.1:8787/v1/usage
```

`/ui` and `/v1/usage` are loopback-only. `/v1/usage` requires the `usage:read` scope.

## Providers

21pins currently wires:

- OpenAI
- OpenRouter
- Anthropic
- DeepSeek
- Venice
- Hetzner
- Maple / TryMaple
- Gemini
- Ollama

List providers:

```bash
21pins key providers
```

Sync model catalogs where supported:

```bash
21pins models sync
21pins models list --provider openrouter --search gpt
21pins models choose --provider openrouter --search gpt
```

## Security model

21pins is intentionally boring:

- provider keys live in a local state file, not in this npm package
- app tokens are shown once when created
- the default gateway binds to `127.0.0.1`
- usage endpoints are loopback-only
- npm install uses optional platform packages, not a remote-download postinstall script

Still treat every 21pins token like a bearer credential. If you paste it somewhere unsafe, rotate it.

## More docs

- Website: <https://21pins.com>
- GitHub: <https://github.com/automatethething/21pins>
- Packaging notes: <https://github.com/automatethething/21pins/blob/main/docs/packaging.md>

## License

MIT
