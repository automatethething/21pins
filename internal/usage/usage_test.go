package usage

import "testing"

func TestParseChatCompletionUsage(t *testing.T) {
	body := []byte(`{"id":"gen_123","model":"openai/gpt-4o-mini","usage":{"prompt_tokens":1000,"completion_tokens":200,"total_tokens":1200}}`)
	parsed, ok := ParseChatUsage(body)
	if !ok {
		t.Fatal("expected usage")
	}
	if parsed.RequestID != "gen_123" || parsed.Model != "openai/gpt-4o-mini" {
		t.Fatalf("bad parsed: %+v", parsed)
	}
	if parsed.PromptTokens != 1000 || parsed.CompletionTokens != 200 || parsed.TotalTokens != 1200 {
		t.Fatalf("bad tokens: %+v", parsed)
	}
}

func TestParseChatCompletionUsageMissingUsage(t *testing.T) {
	parsed, ok := ParseChatUsage([]byte(`{"id":"gen_123","model":"unknown/model"}`))
	if !ok {
		t.Fatal("expected visible zero-token usage")
	}
	if parsed.Warning == "" || parsed.TotalTokens != 0 {
		t.Fatalf("expected warning zero event: %+v", parsed)
	}
}

func TestParseChatCompletionUsageCacheTokenDetailVariants(t *testing.T) {
	body := []byte(`{"id":"gen_123","model":"openai/gpt-4o-mini","usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"prompt_tokens_details":{"cached_tokens":30},"cache_creation_input_tokens":7}}`)
	parsed, ok := ParseChatUsage(body)
	if !ok {
		t.Fatal("expected usage")
	}
	if parsed.CacheReadTokens != 30 || parsed.CacheWriteTokens != 7 {
		t.Fatalf("expected cache tokens, got %+v", parsed)
	}
}

func TestParseChatCompletionUsageCacheTokenTopLevelVariants(t *testing.T) {
	body := []byte(`{"id":"gen_456","model":"openai/gpt-4o-mini","usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,"cache_read_input_tokens":11,"cache_write_input_tokens":13}}`)
	parsed, ok := ParseChatUsage(body)
	if !ok {
		t.Fatal("expected usage")
	}
	if parsed.CacheReadTokens != 11 || parsed.CacheWriteTokens != 13 {
		t.Fatalf("expected top-level cache tokens, got %+v", parsed)
	}
}

func TestEstimateCostUsesStaticOpenRouterFallback(t *testing.T) {
	cost := EstimateOpenRouterCostMicros("openai/gpt-4o-mini", 1_000_000, 1_000_000, nil)
	if cost.Micros != 750_000 {
		t.Fatalf("expected 750000 micros, got %d", cost.Micros)
	}
	if cost.Source != "static" {
		t.Fatalf("expected static, got %s", cost.Source)
	}
}

func TestEstimateCostUnknownModel(t *testing.T) {
	cost := EstimateOpenRouterCostMicros("unknown/model", 100, 100, nil)
	if cost.Micros != 0 || cost.Source != "unknown" {
		t.Fatalf("unexpected cost: %+v", cost)
	}
}

func TestEstimateCostUsesCatalogPrice(t *testing.T) {
	price := Price{PromptMicrosPerMillion: 10, CompletionMicrosPerMillion: 20, Source: "openrouter_catalog"}
	cost := EstimateOpenRouterCostMicros("any/model", 1_000_000, 2_000_000, &price)
	if cost.Micros != 50 || cost.Source != "openrouter_catalog" {
		t.Fatalf("unexpected cost: %+v", cost)
	}
}

func TestParseSSEUsageFrames(t *testing.T) {
	stream := "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: {\"id\":\"gen_1\",\"model\":\"openai/gpt-4o-mini\",\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n" +
		"data: [DONE]\n\n"
	parsed, ok := ParseSSEUsage([]byte(stream))
	if !ok {
		t.Fatal("expected usage")
	}
	if parsed.TotalTokens != 6 {
		t.Fatalf("bad parsed: %+v", parsed)
	}
}

func TestMergeStreamOptionsIncludeUsagePreservesFields(t *testing.T) {
	payload := map[string]any{"stream_options": map[string]any{"foo": "bar"}}
	MergeStreamOptionsIncludeUsage(payload)
	opts := payload["stream_options"].(map[string]any)
	if opts["foo"] != "bar" || opts["include_usage"] != true {
		t.Fatalf("unexpected stream options: %#v", opts)
	}
}
