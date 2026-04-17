// Package version exposes the build-time version, commit, and date.
//
// Values are baked in via -ldflags at release build time (see Makefile
// and .goreleaser.yaml):
//
//	go build -ldflags "-X github.com/whitworth-org/bedrock/internal/version.Version=v1.2.3 \
//	                   -X github.com/whitworth-org/bedrock/internal/version.Commit=$(git rev-parse --short HEAD) \
//	                   -X github.com/whitworth-org/bedrock/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
//
// When unset, the package falls back to runtime/debug.ReadBuildInfo so a
// `go install github.com/whitworth-org/bedrock@v1.2.3` build reports the
// real module version, plus the VCS revision and commit time the Go
// toolchain captured.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String returns a human-readable version line suitable for `--version`.
func String() string {
	v := Version
	commit := Commit
	date := Date

	if info, ok := debug.ReadBuildInfo(); ok {
		// When Version wasn't baked in via ldflags, fall back to the Go
		// toolchain's record of the module version set by `go install
		// path@version`. Local `go build .` leaves this as "(devel)";
		// in that case we keep v as "dev".
		if v == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
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

	out := fmt.Sprintf("bedrock %s", v)
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
