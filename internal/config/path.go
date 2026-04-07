package config

import (
	"os"
	"path/filepath"
)

func StatePath() string {
	if v := os.Getenv("PINS21_STATE_PATH"); v != "" {
		return v
	}
	base, err := os.UserConfigDir()
	if err != nil {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".21pins", "state.json")
	}
	return filepath.Join(base, "21pins", "state.json")
}
