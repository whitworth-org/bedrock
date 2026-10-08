//go:build unix

package main

import (
	"testing"

	"github.com/whitworth-org/bedrock/internal/tty/ttytest"
)

// TestOSSystemColorFollowsTheEnvironment checks the real process boundary on
// a terminal: the terminal side of a new pseudo-terminal. The terminal report
// is coloured unless NO_COLOR or TERM=dumb turns it off, and nothing forces
// colour back on.
func TestOSSystemColorFollowsTheEnvironment(t *testing.T) {
	term := ttytest.Open(t)
	sys := osSystem()
	if !sys.isTerminal(term) || sys.isRegular(term) {
		t.Fatal("a pseudo-terminal is not a terminal, or is a regular file")
	}
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"no environment", nil, true},
		{"empty NO_COLOR", map[string]string{"NO_COLOR": ""}, true},
		{"NO_COLOR", map[string]string{"NO_COLOR": "1"}, false},
		{"TERM=dumb", map[string]string{"TERM": "dumb"}, false},
		{"FORCE_COLOR under NO_COLOR",
			map[string]string{"NO_COLOR": "1", "FORCE_COLOR": "1"}, false},
		{"CLICOLOR_FORCE under TERM=dumb",
			map[string]string{"TERM": "dumb", "CLICOLOR_FORCE": "1"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getenv := func(key string) string { return tt.env[key] }
			if got := sys.color(term, getenv); got != tt.want {
				t.Errorf("color = %v, want %v", got, tt.want)
			}
		})
	}
}
