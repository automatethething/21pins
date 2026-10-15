package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/petrichor/21pins-cli/internal/config"
	"github.com/petrichor/21pins-cli/internal/netpolicy"
)

func handleNetwork(args []string) int {
	state := config.StatePath()
	dir := filepath.Dir(state)
	return netpolicy.Run(context.Background(), args, netpolicy.CLIEnv{RegistryPath: filepath.Join(dir, "network-state.json"), StatePath: state, ReceiptDir: filepath.Join(dir, "network-receipts")}, os.Stdout, os.Stderr)
}
