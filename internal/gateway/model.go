package gateway

import (
	"errors"
	"strings"

	"github.com/petrichor/21pins-cli/internal/store"
)

func splitProviderModel(model string) (provider string, providerModel string, err error) {
	trimmed := strings.TrimSpace(model)
	if trimmed == "" {
		return "", "", errors.New("model is required")
	}
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", errors.New("model must be in provider/model format")
	}
	provider, _ = store.CanonicalProvider(parts[0])
	return provider, strings.TrimSpace(parts[1]), nil
}
