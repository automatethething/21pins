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

func TestCanonicalProviderNewAliases(t *testing.T) {
	cases := map[string]string{"hetzner.com": "hetzner", "inference.hetzner.com": "hetzner", "trymaple.ai": "trymaple", "maple": "trymaple"}
	for input, want := range cases {
		canonical, aliasUsed := CanonicalProvider(input)
		if canonical != want || !aliasUsed {
			t.Fatalf("%s: expected alias %s, got %s alias=%v", input, want, canonical, aliasUsed)
		}
	}
}

func TestSupportedProvidersContainsCoreSet(t *testing.T) {
	got := SupportedProviders()
	required := []string{"openai", "openrouter", "anthropic", "deepseek", "gemini", "ollama", "venice", "hetzner", "trymaple"}
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
