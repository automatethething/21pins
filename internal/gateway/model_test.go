package gateway

import "testing"

func TestSplitProviderModel(t *testing.T) {
	provider, model, err := splitProviderModel("openai/gpt-4o-mini")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider != "openai" || model != "gpt-4o-mini" {
		t.Fatalf("unexpected split result: %s %s", provider, model)
	}
}

func TestSplitProviderModelMissingProvider(t *testing.T) {
	_, _, err := splitProviderModel("gpt-4o-mini")
	if err == nil {
		t.Fatal("expected error for missing provider prefix")
	}
}
