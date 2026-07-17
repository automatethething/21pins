package usage

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
)

type ParsedUsage struct {
	RequestID        string
	Model            string
	PromptTokens     int64
	CompletionTokens int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	TotalTokens      int64
	CostMicros       int64
	CostSource       string
	Warning          string
}

type CostEstimate struct {
	Micros   int64
	Source   string
	Currency string
}

type Price struct {
	PromptMicrosPerMillion     int64
	CompletionMicrosPerMillion int64
	Source                     string
}

type chatUsageEnvelope struct {
	ID     string         `json:"id"`
	Model  string         `json:"model"`
	Usage  map[string]any `json:"usage"`
	Cost   map[string]any `json:"cost"`
	Object string         `json:"object"`
}

func ParseChatUsage(body []byte) (ParsedUsage, bool) {
	var env chatUsageEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ParsedUsage{}, false
	}
	if strings.TrimSpace(env.ID) == "" && strings.TrimSpace(env.Model) == "" && env.Usage == nil {
		return ParsedUsage{}, false
	}
	parsed := ParsedUsage{RequestID: env.ID, Model: env.Model}
	if env.Usage == nil {
		parsed.Warning = "usage_missing"
		return parsed, true
	}
	parsed.PromptTokens = intFromMap(env.Usage, "prompt_tokens", "input_tokens")
	parsed.CompletionTokens = intFromMap(env.Usage, "completion_tokens", "output_tokens")
	parsed.TotalTokens = intFromMap(env.Usage, "total_tokens")
	if parsed.TotalTokens == 0 {
		parsed.TotalTokens = parsed.PromptTokens + parsed.CompletionTokens
	}
	parsed.CacheReadTokens = intFromMap(env.Usage, "cache_read_input_tokens")
	parsed.CacheWriteTokens = intFromMap(env.Usage, "cache_creation_input_tokens", "cache_write_input_tokens")
	if details, ok := env.Usage["prompt_tokens_details"].(map[string]any); ok {
		if cached := intFromMap(details, "cached_tokens"); cached > 0 {
			parsed.CacheReadTokens = cached
		}
	}
	if usd := floatFromMap(env.Cost, "usd"); usd > 0 {
		parsed.CostMicros = int64(math.Round(usd * 1_000_000))
		parsed.CostSource = "provider_response"
	}
	if parsed.PromptTokens == 0 && parsed.CompletionTokens == 0 && parsed.TotalTokens == 0 {
		parsed.Warning = "usage_tokens_missing"
	}
	return parsed, true
}

func ParseSSEUsage(body []byte) (ParsedUsage, bool) {
	frames := bytes.Split(body, []byte("\n\n"))
	var last ParsedUsage
	var found bool
	for _, frame := range frames {
		lines := bytes.Split(frame, []byte("\n"))
		var dataParts []string
		for _, line := range lines {
			line = bytes.TrimSpace(line)
			if bytes.HasPrefix(line, []byte("data:")) {
				part := strings.TrimSpace(string(bytes.TrimPrefix(line, []byte("data:"))))
				if part != "" && part != "[DONE]" {
					dataParts = append(dataParts, part)
				}
			}
		}
		if len(dataParts) == 0 {
			continue
		}
		parsed, ok := ParseChatUsage([]byte(strings.Join(dataParts, "\n")))
		if ok && (parsed.PromptTokens > 0 || parsed.CompletionTokens > 0 || parsed.TotalTokens > 0 || parsed.Warning != "") {
			last = parsed
			found = true
		}
	}
	return last, found
}

func EstimateOpenRouterCostMicros(model string, promptTokens, completionTokens int64, catalogPrice *Price) CostEstimate {
	price := Price{}
	if catalogPrice != nil && catalogPrice.PromptMicrosPerMillion > 0 && catalogPrice.CompletionMicrosPerMillion > 0 {
		price = *catalogPrice
		if strings.TrimSpace(price.Source) == "" {
			price.Source = "openrouter_catalog"
		}
	} else if model == "openai/gpt-4o-mini" {
		price = Price{PromptMicrosPerMillion: 150_000, CompletionMicrosPerMillion: 600_000, Source: "static"}
	} else {
		return CostEstimate{Micros: 0, Source: "unknown", Currency: "USD"}
	}
	micros := (promptTokens*price.PromptMicrosPerMillion + completionTokens*price.CompletionMicrosPerMillion) / 1_000_000
	return CostEstimate{Micros: micros, Source: price.Source, Currency: "USD"}
}

func MergeStreamOptionsIncludeUsage(payload map[string]any) {
	existing, ok := payload["stream_options"].(map[string]any)
	if !ok || existing == nil {
		existing = map[string]any{}
	}
	existing["include_usage"] = true
	payload["stream_options"] = existing
}

func floatFromMap(m map[string]any, keys ...string) float64 {
	if m == nil {
		return 0
	}
	for _, key := range keys {
		v, ok := m[key]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return n
		case int64:
			return float64(n)
		case int:
			return float64(n)
		case json.Number:
			out, _ := n.Float64()
			return out
		}
	}
	return 0
}

func intFromMap(m map[string]any, keys ...string) int64 {
	for _, key := range keys {
		v, ok := m[key]
		if !ok {
			continue
		}
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		case int:
			return int64(n)
		case json.Number:
			out, _ := n.Int64()
			return out
		}
	}
	return 0
}
