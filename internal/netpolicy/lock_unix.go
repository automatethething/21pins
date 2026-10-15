//go:build linux || darwin

package netpolicy

import (
	"os"
	"syscall"
)

func lockFile(path string) (func(), error) {
	if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600) {
		return nil, ErrUnsafe
	} else if e != nil && !os.IsNotExist(e) {
		return nil, ErrUnsafe
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, ErrUnsafe
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, ErrConflict
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
