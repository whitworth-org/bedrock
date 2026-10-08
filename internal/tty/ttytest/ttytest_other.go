//go:build !darwin && !linux

package ttytest

import (
	"os"
	"testing"
)

// Open skips the test: this system has no pseudo-terminal that package
// syscall can unlock.
func Open(t testing.TB) *os.File {
	t.Helper()
	t.Skip("no pseudo-terminal support for tests on this system")
	return nil
}
