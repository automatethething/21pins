//go:build linux

package netpolicy

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

func bindSocketToInterface(name string, raw syscall.RawConn) error {
	if !nativePattern.MatchString(name) || len(name) > 15 {
		return ErrInvalid
	}
	var bindErr error
	if raw.Control(func(fd uintptr) {
		bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, name)
	}) != nil || bindErr != nil {
		return ErrUnsupported
	}
	return nil
}

func namespacePath(name string) (string, error) {
	if name == "" {
		return "/proc/thread-self/ns/net", nil
	}
	if !nativePattern.MatchString(name) {
		return "", ErrInvalid
	}
	return filepath.Join("/var/run/netns", name), nil
}
func namespaceIdentity(name string) (string, error) {
	path, e := namespacePath(name)
	if e != nil {
		return "", e
	}
	info, e := os.Stat(path)
	if e != nil {
		return "", ErrMissing
	}
	return namespaceInfoIdentity(info)
}
func namespaceInfoIdentity(info os.FileInfo) (string, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ErrUnsupported
	}
	return "ctx_" + hashJSON([]uint64{uint64(st.Dev), st.Ino}), nil
}
func setNamespace(fd uintptr) error {
	// syscall is frozen and omits SYS_SETNS on amd64. These are Linux ABI numbers.
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 308
	case "arm64":
		number = 268
	default:
		return ErrUnsupported
	}
	_, _, e := syscall.RawSyscall(number, fd, uintptr(syscall.CLONE_NEWNET), 0)
	if e != 0 {
		return ErrUnsupported
	}
	return nil
}

// A dedicated locked thread is destroyed if restore fails; it can never rejoin the pool in the wrong namespace.
func withinNamespace(ctx context.Context, b Binding, fn func() error) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		current, e := os.Open("/proc/self/task/" + strconv.Itoa(syscall.Gettid()) + "/ns/net")
		if e != nil {
			runtime.UnlockOSThread()
			result <- ErrUnsupported
			return
		}
		defer current.Close()
		path, e := namespacePath(b.Namespace)
		if e != nil {
			runtime.UnlockOSThread()
			result <- e
			return
		}
		target, e := os.Open(path)
		if e != nil {
			runtime.UnlockOSThread()
			result <- ErrMissing
			return
		}
		defer target.Close()
		targetInfo, e := target.Stat()
		id := ""
		if e == nil {
			id, e = namespaceInfoIdentity(targetInfo)
		}
		if e != nil || id != b.Context {
			runtime.UnlockOSThread()
			result <- ErrStale
			return
		}
		if e = setNamespace(target.Fd()); e != nil {
			runtime.UnlockOSThread()
			result <- e
			return
		}
		operationErr := fn()
		if setNamespace(current.Fd()) != nil {
			result <- ErrUnsafe
			return
		}
		runtime.UnlockOSThread()
		result <- operationErr
	}()
	// Never abandon a namespace worker. Its I/O must obey the same bounded context.
	return <-result
}
