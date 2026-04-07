package store

import (
	"path/filepath"
	"testing"
)

func TestModelCatalogRoundTrip(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	models := []ProviderModel{
		{ID: "openai/gpt-4o", Name: "GPT-4o", ContextWindow: 128000},
		{ID: "openai/gpt-4o-mini", Name: "GPT-4o mini", ContextWindow: 128000},
	}
	if err := s.SaveModelCatalog("openrouter", models); err != nil {
		t.Fatalf("SaveModelCatalog failed: %v", err)
	}

	catalog, ok := s.GetModelCatalog("openrouter")
	if !ok {
		t.Fatal("expected model catalog to exist")
	}
	if catalog.Provider != "openrouter" {
		t.Fatalf("expected provider openrouter, got %s", catalog.Provider)
	}
	if len(catalog.Models) != 2 {
		t.Fatalf("expected 2 models, got %d", len(catalog.Models))
	}

	all := s.ListModelCatalogs()
	if len(all) != 1 {
		t.Fatalf("expected 1 catalog, got %d", len(all))
	}
}
