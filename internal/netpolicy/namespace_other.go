//go:build !linux

package netpolicy

import "context"

func namespaceIdentity(string) (string, error)                     { return "", ErrUnsupported }
func withinNamespace(context.Context, Binding, func() error) error { return ErrUnsupported }
