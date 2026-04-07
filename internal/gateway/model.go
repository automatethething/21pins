package gateway

import (
	"errors"
	"strings"
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
	return strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1]), nil
}
