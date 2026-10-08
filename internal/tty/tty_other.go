//go:build !windows && !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package tty

import "os"

// IsTerminal reports whether f is a character device. These platforms have
// no termios request in package syscall, so /dev/null counts as a terminal.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// enableVT reports whether f interprets escape sequences. Unix terminals do
// without any setup.
func enableVT(*os.File) bool { return true }
