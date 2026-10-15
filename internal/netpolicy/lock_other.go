//go:build !linux && !darwin

package netpolicy

func lockFile(string) (func(), error) { return nil, ErrUnsupported }
