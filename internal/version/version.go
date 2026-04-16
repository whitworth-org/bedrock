// Package version exposes the build-time version, commit, and date.
//
// Values are baked in via -ldflags at release build time:
//
//	go build -ldflags "-X granite-scan/internal/version.Version=0.2.0 \
//	                   -X granite-scan/internal/version.Commit=$(git rev-parse --short HEAD) \
//	                   -X granite-scan/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
//
// When unset, the package falls back to runtime/debug.ReadBuildInfo so a
// `go install` build still reports a meaningful version (the module
// pseudo-version + the VCS revision the Go toolchain captured).
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var (
	Version = "0.1.0-dev"
	Commit  = ""
	Date    = ""
)

// String returns a human-readable version line suitable for `--version`.
func String() string {
	v := Version
	commit := Commit
	date := Date

	if commit == "" || date == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if commit == "" && s.Value != "" {
						commit = shortRev(s.Value)
					}
				case "vcs.time":
					if date == "" {
						date = s.Value
					}
				}
			}
		}
	}

	out := fmt.Sprintf("granite-scan %s", v)
	if commit != "" {
		out += " (" + commit
		if date != "" {
			out += " " + date
		}
		out += ")"
	}
	out += fmt.Sprintf(" %s/%s", runtime.GOOS, runtime.GOARCH)
	return out
}

func shortRev(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
