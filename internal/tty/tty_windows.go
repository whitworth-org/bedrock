//go:build windows

package tty

import (
	"os"
	"syscall"
)

const enableVirtualTerminalProcessing = 0x0004

// Package syscall registers kernel32.dll as a system DLL, so this loads only
// the System32 copy and never one planted beside the binary.
var procSetConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

// IsTerminal reports whether f is a console. NUL is a character device but
// not a console, so unlike /dev/null on Unix it is not a terminal.
func IsTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}

// enableVT switches f's console to interpret escape sequences, keeping its
// other mode bits, and reports whether that worked. A legacy console refuses
// and so gets no colour. The previous mode is not restored on exit.
func enableVT(f *os.File) bool {
	h := syscall.Handle(f.Fd())
	var mode uint32
	if syscall.GetConsoleMode(h, &mode) != nil {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	newMode := uintptr(mode | enableVirtualTerminalProcessing)
	ok, _, _ := procSetConsoleMode.Call(uintptr(h), newMode)
	return ok != 0
}
