//go:build darwin || linux

package ttytest

import (
	"os"
	"syscall"
	"testing"
)

// Open returns the terminal side of a new pseudo-terminal, closed when the
// test ends. It skips the test where the system cannot make one.
func Open(t testing.TB) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open /dev/ptmx: %v; no pseudo-terminal to test against", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	name, err := terminalName(master)
	if err != nil {
		t.Skipf("unlock the pseudo-terminal behind /dev/ptmx: %v", err)
	}
	term, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open pseudo-terminal %s: %v", name, err)
	}
	t.Cleanup(func() { _ = term.Close() })
	return term
}

// ioctl applies request to f with argument arg.
func ioctl(f *os.File, request, arg uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), request, arg); errno != 0 {
		return errno
	}
	return nil
}
