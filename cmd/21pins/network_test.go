package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestNetworkSubprocess(t *testing.T) {
	if os.Getenv("PINS_NETWORK_TEST_PROCESS") != "1" {
		return
	}
	os.Args = []string{"21pins", "discover"}
	main()
}
func TestNetworkEarlyDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNetworkSubprocess$")
	command.Env = append(os.Environ(), "PINS_NETWORK_TEST_PROCESS=1", "PINS21_STATE_PATH="+path)
	if output, e := command.CombinedOutput(); e != nil {
		t.Fatalf("metadata command failed: %v (%d output bytes)", e, len(output))
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("network command initialized legacy provider state")
	}
}
