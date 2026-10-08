//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows

package tty

import (
	"os"
	"testing"
)

// The null device is a character device on Unix but not a terminal, so
// 'bedrock example.org > /dev/null' is treated like any other non-terminal
// stdout: no report, no colour and no progress.
func TestNullDeviceIsNotATerminal(t *testing.T) {
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = null.Close() })
	if IsTerminal(null) {
		t.Errorf("IsTerminal(%s) = true, want false", os.DevNull)
	}
	if IsRegular(null) {
		t.Errorf("IsRegular(%s) = true, want false", os.DevNull)
	}
	if Color(null, env{}.getenv) {
		t.Errorf("Color(%s) = true, want false", os.DevNull)
	}
}
