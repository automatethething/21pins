package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/petrichor/21pins-cli/internal/store"
)

type discoveredModel struct {
	ID            string
	Name          string
	ContextWindow int
}

func handleModels(st *store.Store, args []string) {
	if len(args) == 0 {
		fatalf("models subcommand required: sync|list|choose")
	}
	switch args[0] {
	case "sync":
		handleModelsSync(st, args[1:])
	case "list":
		handleModelsList(st, args[1:])
	case "choose":
		handleModelsChoose(st, args[1:])
	default:
		fatalf("unknown models subcommand")
	}
}

func handleModelsSync(st *store.Store, args []string) {
	fs := flag.NewFlagSet("models sync", flag.ExitOnError)
	providerArg := fs.String("provider", "", "sync only one provider")
	_ = fs.Parse(args)

	providers := []string{}
	if strings.TrimSpace(*providerArg) != "" {
		p, _ := store.CanonicalProvider(*providerArg)
		if p == "" {
			fatalf("invalid provider")
		}
		providers = []string{p}
	} else {
		providers = st.ListProviders()
	}

	if len(providers) == 0 {
		fatalf("no providers configured; add keys first with: 21pins key set <provider> --value <key>")
	}

	var anySuccess bool
	for _, provider := range providers {
		models, err := syncProviderModels(st, provider)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sync failed for %s: %v\n", provider, err)
			continue
		}
		entries := make([]store.ProviderModel, 0, len(models))
		for _, m := range models {
			entries = append(entries, store.ProviderModel{ID: m.ID, Name: m.Name, ContextWindow: m.ContextWindow})
		}
		if err := st.SaveModelCatalog(provider, entries); err != nil {
			fmt.Fprintf(os.Stderr, "save catalog failed for %s: %v\n", provider, err)
			continue
		}
		anySuccess = true
		fmt.Printf("synced %d models for %s\n", len(entries), provider)
	}
	if !anySuccess {
		os.Exit(1)
	}
}

func handleModelsList(st *store.Store, args []string) {
	fs := flag.NewFlagSet("models list", flag.ExitOnError)
	providerArg := fs.String("provider", "", "filter by provider")
	search := fs.String("search", "", "filter model id/name")
	jsonOut := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	rows := collectModelRows(st, *providerArg, *search)
	if len(rows) == 0 {
		fmt.Println("No cached models. Run: 21pins models sync")
		return
	}

	if *jsonOut {
		printJSON(rows)
		return
	}

	for _, r := range rows {
		if r.ContextWindow > 0 {
			fmt.Printf("%s\t%s\t%s\tctx=%d\n", r.Provider, r.ModelID, r.RouteModel, r.ContextWindow)
		} else {
			fmt.Printf("%s\t%s\t%s\n", r.Provider, r.ModelID, r.RouteModel)
		}
	}
}

func handleModelsChoose(st *store.Store, args []string) {
	fs := flag.NewFlagSet("models choose", flag.ExitOnError)
	providerArg := fs.String("provider", "", "filter by provider")
	search := fs.String("search", "", "filter model id/name")
	index := fs.Int("index", 0, "1-based model index; if 0, interactive prompt")
	_ = fs.Parse(args)

	rows := collectModelRows(st, *providerArg, *search)
	if len(rows) == 0 {
		fatalf("no cached models. run: 21pins models sync")
	}

	if *index > 0 {
		if *index > len(rows) {
			fatalf("index out of range (1-%d)", len(rows))
		}
		fmt.Println(rows[*index-1].RouteModel)
		return
	}

	fmt.Println("Choose a model:")
	for i, r := range rows {
		label := r.ModelID
		if r.Name != "" && r.Name != r.ModelID {
			label = r.Name + " (" + r.ModelID + ")"
		}
		fmt.Printf("%2d) %-10s %s\n", i+1, r.Provider, label)
	}
	fmt.Print("Enter number: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(rows) {
		fatalf("invalid selection")
	}
	fmt.Println(rows[n-1].RouteModel)
}

type modelRow struct {
	Provider      string `json:"provider"`
	ModelID       string `json:"model_id"`
	Name          string `json:"name,omitempty"`
	ContextWindow int    `json:"context_window,omitempty"`
	RouteModel    string `json:"route_model"`
	SyncedAt      string `json:"synced_at"`
}

func collectModelRows(st *store.Store, providerArg, search string) []modelRow {
	providerArg = strings.TrimSpace(providerArg)
	search = strings.ToLower(strings.TrimSpace(search))
	catalogs := st.ListModelCatalogs()
	providers := make([]string, 0, len(catalogs))
	for p := range catalogs {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	rows := []modelRow{}
	for _, provider := range providers {
		if providerArg != "" {
			cp, _ := store.CanonicalProvider(providerArg)
			if provider != cp {
				continue
			}
		}
		c := catalogs[provider]
		for _, m := range c.Models {
			if search != "" {
				hay := strings.ToLower(m.ID + " " + m.Name)
				if !strings.Contains(hay, search) {
					continue
				}
			}
			rows = append(rows, modelRow{
				Provider:      provider,
				ModelID:       m.ID,
				Name:          m.Name,
				ContextWindow: m.ContextWindow,
				RouteModel:    routingModel(provider, m.ID),
				SyncedAt:      c.SyncedAt,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Provider == rows[j].Provider {
			return rows[i].ModelID < rows[j].ModelID
		}
		return rows[i].Provider < rows[j].Provider
	})
	return rows
}

func routingModel(provider, modelID string) string {
	return provider + "/" + modelID
}

func syncProviderModels(st *store.Store, provider string) ([]discoveredModel, error) {
	provider, _ = store.CanonicalProvider(provider)
	key := st.GetProviderKey(provider)

	switch provider {
	case "openai":
		if key == "" {
			return nil, errors.New("no key configured")
		}
		return fetchOpenAIModels(key)
	case "openrouter":
		if key == "" {
			return nil, errors.New("no key configured")
		}
		return fetchOpenRouterModels(key)
	case "anthropic":
		if key == "" {
			return nil, errors.New("no key configured")
		}
		return fetchAnthropicModels(key)
	case "gemini":
		if key == "" {
			return nil, errors.New("no key configured")
		}
		return fetchGeminiModels(key)
	case "ollama":
		return fetchOllamaModels()
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func fetchOpenAIModels(key string) ([]discoveredModel, error) {
	type item struct{ ID string `json:"id"` }
	var resp struct{ Data []item `json:"data"` }
	if err := getJSON("https://api.openai.com/v1/models", map[string]string{"Authorization": "Bearer " + key}, &resp); err != nil {
		return nil, err
	}
	out := make([]discoveredModel, 0, len(resp.Data))
	for _, m := range resp.Data {
		out = append(out, discoveredModel{ID: m.ID, Name: m.ID})
	}
	return out, nil
}

func fetchOpenRouterModels(key string) ([]discoveredModel, error) {
	type item struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		ContextLength int    `json:"context_length"`
	}
	var resp struct{ Data []item `json:"data"` }
	if err := getJSON("https://openrouter.ai/api/v1/models", map[string]string{"Authorization": "Bearer " + key}, &resp); err != nil {
		return nil, err
	}
	out := make([]discoveredModel, 0, len(resp.Data))
	for _, m := range resp.Data {
		out = append(out, discoveredModel{ID: m.ID, Name: m.Name, ContextWindow: m.ContextLength})
	}
	return out, nil
}

func fetchAnthropicModels(key string) ([]discoveredModel, error) {
	type item struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
	}
	var resp struct{ Data []item `json:"data"` }
	headers := map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}
	if err := getJSON("https://api.anthropic.com/v1/models", headers, &resp); err != nil {
		return nil, err
	}
	out := make([]discoveredModel, 0, len(resp.Data))
	for _, m := range resp.Data {
		name := m.DisplayName
		if strings.TrimSpace(name) == "" {
			name = m.ID
		}
		out = append(out, discoveredModel{ID: m.ID, Name: name})
	}
	return out, nil
}

func fetchGeminiModels(key string) ([]discoveredModel, error) {
	type item struct {
		Name            string `json:"name"`
		DisplayName     string `json:"displayName"`
		InputTokenLimit int    `json:"inputTokenLimit"`
	}
	var resp struct{ Models []item `json:"models"` }
	u := "https://generativelanguage.googleapis.com/v1beta/models?key=" + url.QueryEscape(key)
	if err := getJSON(u, nil, &resp); err != nil {
		return nil, err
	}
	out := make([]discoveredModel, 0, len(resp.Models))
	for _, m := range resp.Models {
		id := strings.TrimPrefix(m.Name, "models/")
		name := m.DisplayName
		if strings.TrimSpace(name) == "" {
			name = id
		}
		out = append(out, discoveredModel{ID: id, Name: name, ContextWindow: m.InputTokenLimit})
	}
	return out, nil
}

func fetchOllamaModels() ([]discoveredModel, error) {
	type item struct{ Name string `json:"name"` }
	var resp struct{ Models []item `json:"models"` }
	if err := getJSON("http://127.0.0.1:11434/api/tags", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]discoveredModel, 0, len(resp.Models))
	for _, m := range resp.Models {
		out = append(out, discoveredModel{ID: m.Name, Name: m.Name})
	}
	return out, nil
}

func getJSON(url string, headers map[string]string, out any) error {
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upstream returned %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return err
	}
	return nil
}
