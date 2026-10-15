//go:build !linux

package netpolicy

import (
	"context"
	"syscall"
)

func bindSocketToInterface(string, syscall.RawConn) error { return ErrUnsupported }

func namespaceIdentity(string) (string, error)                     { return "", ErrUnsupported }
func withinNamespace(context.Context, Binding, func() error) error { return ErrUnsupported }
