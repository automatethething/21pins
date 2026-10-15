//go:build !linux

package netpolicy

import "context"

func startMonitor(context.Context, Binding, string, string, uint16, string) (monitor, error) {
	return nil, ErrUnsupported
}
