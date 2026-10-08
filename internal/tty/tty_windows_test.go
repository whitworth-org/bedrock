//go:build windows

package tty

import (
	"os"
	"syscall"
	"testing"
)

// openTerminal opens the console the test process is attached to, and skips
// the test when there is none, as for a service.
func openTerminal(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("open CONOUT$: %v; this process has no console to test against", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// When the environment turns colour off, Color must not switch the console
// to escape processing: the mode outlives bedrock, in the user's shell.
func TestColorOffLeavesTheConsoleModeAlone(t *testing.T) {
	term := openTerminal(t)
	h := syscall.Handle(term.Fd())
	var original uint32
	if err := syscall.GetConsoleMode(h, &original); err != nil {
		t.Skipf("GetConsoleMode(%s): %v", term.Name(), err)
	}
	t.Cleanup(func() { setConsoleMode(h, original) })
	plain := original &^ enableVirtualTerminalProcessing
	if !setConsoleMode(h, plain) {
		t.Skipf("SetConsoleMode(%s) refused to turn escape processing off", term.Name())
	}
	for _, e := range []env{{"NO_COLOR": "1"}, {"TERM": "dumb"}} {
		if Color(term, e.getenv) {
			t.Errorf("Color(%s) with %v = true, want false", term.Name(), e)
		}
		var mode uint32
		if err := syscall.GetConsoleMode(h, &mode); err != nil || mode != plain {
			t.Errorf("Color(%s) with %v changed the console mode from %#x to %#x (error %v)",
				term.Name(), e, plain, mode, err)
		}
	}
}

func setConsoleMode(h syscall.Handle, mode uint32) bool {
	ok, _, _ := procSetConsoleMode.Call(uintptr(h), uintptr(mode))
	return ok != 0
}
