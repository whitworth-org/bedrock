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

// readBuildInfo is a seam over debug.ReadBuildInfo so tests can drive the
// fallback deterministically. Production always uses debug.ReadBuildInfo;
// `go test` may or may not stamp vcs.* into the test binary, which would
// otherwise make the fallback's output depend on the build environment.
var readBuildInfo = debug.ReadBuildInfo

// resolve returns the effective version, commit, and date. Values baked in
// via ldflags win; otherwise it falls back to runtime/debug.ReadBuildInfo so
// a `go install path@version` build still reports the module version, VCS
// revision, and commit time the Go toolchain recorded. Local `go build .`
// leaves Main.Version as "(devel)", in which case the version stays "dev".
func resolve() (v, commit, date string) {
	v, commit, date = Version, Commit, Date
	if info, ok := readBuildInfo(); ok {
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
	return v, commit, date
}

// String returns a human-readable version line suitable for `--version`.
func String() string {
	v, commit, date := resolve()
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

// UserAgent returns the HTTP User-Agent string identifying bedrock and its
// build version to the third-party services and hosts it probes. The version
// segment is resolved exactly as String resolves it, so the User-Agent and
// `--version` never disagree (…/dev for local builds).
func UserAgent() string {
	v, _, _ := resolve()
	return "github.com/whitworth-org/bedrock/" + v + " (+https://example.invalid/)"
}

// shortRev returns s if len(s) <= 12, otherwise s[:12].
// The 12-byte cap matches GitHub-style short SHAs and bounds the 40-char
// vcs.revision from runtime/debug.ReadBuildInfo (the ldflags path uses
// `git rev-parse --short`, which is shorter).
func shortRev(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
