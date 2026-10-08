//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package tty

import (
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal reports whether f is a terminal: whether the kernel returns
// its terminal attributes, as isatty(3) asks. A character device that is
// not a terminal, such as /dev/null, refuses the request.
func IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	// SyscallConn, unlike Fd, leaves the descriptor's blocking mode alone.
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var errno syscall.Errno
	ctlErr := rc.Control(func(fd uintptr) {
		var t syscall.Termios
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlGetTermios,
			uintptr(unsafe.Pointer(&t))) //nolint:gosec // G103: the ioctl only fills t.
	})
	return ctlErr == nil && errno == 0
}

// enableVT reports whether f interprets escape sequences. Unix terminals do
// without any setup.
func enableVT(*os.File) bool { return true }
