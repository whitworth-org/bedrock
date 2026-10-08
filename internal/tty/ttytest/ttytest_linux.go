package ttytest

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// terminalName unlocks the terminal side of the pseudo-terminal whose master
// is m, as unlockpt(3) does, and returns its path.
func terminalName(m *os.File) (string, error) {
	var n uint32
	//nolint:gosec // G103: the ioctl fills n and keeps no pointer to it.
	if err := ioctl(m, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {
		return "", err
	}
	var locked int32
	//nolint:gosec // G103: the ioctl reads locked and keeps no pointer to it.
	if err := ioctl(m, syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&locked))); err != nil {
		return "", err
	}
	return "/dev/pts/" + strconv.FormatUint(uint64(n), 10), nil
}
