package tty

import (
	"os"
	"path/filepath"
	"testing"
)

// env is a fake environment, so no test depends on the real one.
type env map[string]string

func (e env) getenv(name string) string { return e[name] }

func newFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "report.json"))
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func newPipe(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	return r, w
}

// Files and pipes are never terminals, so they never get colour, even when
// FORCE_COLOR or CLICOLOR_FORCE asks for it.
func TestFilesAndPipesAreNotTerminals(t *testing.T) {
	r, w := newPipe(t)
	streams := map[string]*os.File{
		"regular file":   newFile(t),
		"pipe read end":  r,
		"pipe write end": w,
	}
	force := env{"FORCE_COLOR": "1", "CLICOLOR_FORCE": "1"}
	for name, f := range streams {
		if IsTerminal(f) {
			t.Errorf("IsTerminal(%s) = true, want false", name)
		}
		if Color(f, force.getenv) {
			t.Errorf("Color(%s) = true, want false", name)
		}
	}
}

func TestIsRegular(t *testing.T) {
	r, w := newPipe(t)
	cases := []struct {
		name string
		f    *os.File
		want bool
	}{
		{"regular file", newFile(t), true},
		{"pipe read end", r, false},
		{"pipe write end", w, false},
	}
	for _, tc := range cases {
		if got := IsRegular(tc.f); got != tc.want {
			t.Errorf("IsRegular(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A stream that cannot be inspected is neither a terminal nor a regular file.
// os.Stdout is nil on Windows when the process has no standard output.
func TestUninspectableStreams(t *testing.T) {
	closed := newFile(t)
	if err := closed.Close(); err != nil {
		t.Fatalf("close %s: %v", closed.Name(), err)
	}
	for name, f := range map[string]*os.File{"closed file": closed, "nil file": nil} {
		if IsTerminal(f) {
			t.Errorf("IsTerminal(%s) = true, want false", name)
		}
		if IsRegular(f) {
			t.Errorf("IsRegular(%s) = true, want false", name)
		}
	}
}

func TestColorAllowed(t *testing.T) {
	cases := []struct {
		name     string
		terminal bool
		vars     env
		want     bool
	}{
		{"terminal, nothing set", true, nil, true},
		{"not a terminal", false, nil, false},
		{"NO_COLOR=1", true, env{"NO_COLOR": "1"}, false},
		{"NO_COLOR=0 still turns colour off", true, env{"NO_COLOR": "0"}, false},
		{"empty NO_COLOR keeps colour", true, env{"NO_COLOR": ""}, true},
		{"TERM=dumb", true, env{"TERM": "dumb"}, false},
		{"TERM=xterm-256color", true, env{"TERM": "xterm-256color"}, true},
		{"FORCE_COLOR cannot override NO_COLOR", true,
			env{"NO_COLOR": "1", "FORCE_COLOR": "1", "CLICOLOR_FORCE": "1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := colorAllowed(tc.terminal, tc.vars.getenv); got != tc.want {
				t.Errorf("colorAllowed(%v, %v) = %v, want %v",
					tc.terminal, tc.vars, got, tc.want)
			}
		})
	}
}

// A real terminal is detected, and NO_COLOR or TERM=dumb still turns its
// colour off.
func TestTerminalIsDetected(t *testing.T) {
	term := openTerminal(t)
	if !IsTerminal(term) {
		t.Errorf("IsTerminal(%s) = false, want true", term.Name())
	}
	if IsRegular(term) {
		t.Errorf("IsRegular(%s) = true, want false", term.Name())
	}
	for _, e := range []env{{"NO_COLOR": "1"}, {"TERM": "dumb"}} {
		if Color(term, e.getenv) {
			t.Errorf("Color(%s) with %v = true, want false", term.Name(), e)
		}
	}
}
