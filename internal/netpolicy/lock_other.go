//go:build !linux && !darwin

package netpolicy

import "os"

func ownedFile(os.FileInfo) bool { return false }

func lockFile(string) (func(), error) { return nil, ErrUnsupported }
