// Package tty tells main what kind of stream an output is (a terminal, a
// regular file, or neither, such as a pipe) and whether a terminal should
// get colour.
package tty

import "os"

// IsRegular reports whether f is a regular file, as when stdout is
// redirected with '>'. Terminals, pipes and devices are not regular files.
func IsRegular(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode().IsRegular()
}

// Color reports whether f should get SGR colour codes: f is a terminal,
// NO_COLOR is unset or empty, and TERM is not "dumb". FORCE_COLOR and
// CLICOLOR_FORCE are ignored, so colour never reaches a file or a pipe. On
// Windows, Color also switches the console to virtual-terminal processing,
// and a legacy console that refuses gets no colour. getenv is normally
// os.Getenv.
func Color(f *os.File, getenv func(string) string) bool {
	// enableVT goes last: on Windows it changes the console mode, which must
	// stay untouched when colour is off.
	return colorAllowed(IsTerminal(f), getenv) && enableVT(f)
}

// colorAllowed is the platform-independent part of Color. As no-color.org
// specifies, an empty NO_COLOR does not turn colour off.
func colorAllowed(terminal bool, getenv func(string) string) bool {
	return terminal && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
}
