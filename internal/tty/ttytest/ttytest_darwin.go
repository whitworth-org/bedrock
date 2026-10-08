package ttytest

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"
)

// terminalName grants and unlocks the terminal side of the pseudo-terminal
// whose master is m, as grantpt(3) and unlockpt(3) do, and returns its path.
func terminalName(m *os.File) (string, error) {
	var name [128]byte // TIOCPTYGNAME writes a NUL-terminated path of at most 128 bytes
	//nolint:gosec // G103: the ioctl fills name and keeps no pointer to it.
	if err := ioctl(m, syscall.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); err != nil {
		return "", err
	}
	if err := ioctl(m, syscall.TIOCPTYGRANT, 0); err != nil {
		return "", err
	}
	if err := ioctl(m, syscall.TIOCPTYUNLK, 0); err != nil {
		return "", err
	}
	n := bytes.IndexByte(name[:], 0)
	if n < 0 {
		n = len(name)
	}
	return string(name[:n]), nil
}
