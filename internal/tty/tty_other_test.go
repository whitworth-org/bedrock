//go:build !windows

package tty

import (
	"os"
	"testing"

	"github.com/whitworth-org/bedrock/internal/tty/ttytest"
)

// openTerminal opens the terminal side of a new pseudo-terminal, and skips
// the test on systems without one.
func openTerminal(t *testing.T) *os.File {
	t.Helper()
	return ttytest.Open(t)
}

// Unix terminals show colour without any setup, so a terminal gets it unless
// the environment turns it off. An empty NO_COLOR does not (no-color.org).
func TestTerminalGetsColor(t *testing.T) {
	term := openTerminal(t)
	for _, e := range []env{nil, {"NO_COLOR": ""}, {"TERM": "xterm-256color"}} {
		if !Color(term, e.getenv) {
			t.Errorf("Color(%s) with %v = false, want true", term.Name(), e)
		}
	}
}
