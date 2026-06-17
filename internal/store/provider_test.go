package store

import "testing"

func TestCanonicalProviderAlias(t *testing.T) {
	canonical, aliasUsed := CanonicalProvider("openrouter.ai")
	if canonical != "openrouter" {
		t.Fatalf("expected openrouter, got %s", canonical)
	}
	if !aliasUsed {
		t.Fatal("expected aliasUsed true")
	}
}

func TestCanonicalProviderDeepSeekAlias(t *testing.T) {
	canonical, aliasUsed := CanonicalProvider("deepseek.com")
	if canonical != "deepseek" {
		t.Fatalf("expected deepseek, got %s", canonical)
	}
	if !aliasUsed {
		t.Fatal("expected aliasUsed true")
	}
}

func TestCanonicalProviderUnknown(t *testing.T) {
	canonical, aliasUsed := CanonicalProvider("weird-provider")
	if canonical != "weird-provider" {
		t.Fatalf("expected weird-provider, got %s", canonical)
	}
	if aliasUsed {
		t.Fatal("expected aliasUsed false")
	}
}

func TestSupportedProvidersContainsCoreSet(t *testing.T) {
	got := SupportedProviders()
	required := []string{"openai", "openrouter", "anthropic", "deepseek", "gemini", "ollama"}
	for _, r := range required {
		found := false
		for _, p := range got {
			if p == r {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected supported providers to include %s", r)
		}
	}
}
