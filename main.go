// granite-scan: a Hardenize-inspired CLI that audits a domain's
// DNS, Email, WWW, and BIMI security posture against IETF and vendor
// requirements. See CLAUDE.md for the architecture and the approved plan.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"granite-scan/internal/probe"
	"granite-scan/internal/registry"
	"granite-scan/internal/report"

	// Side-effect imports register checks with the global registry.
	_ "granite-scan/internal/checks/bimi"
	_ "granite-scan/internal/checks/dns"
	_ "granite-scan/internal/checks/dnssec"
	_ "granite-scan/internal/checks/email"
	_ "granite-scan/internal/checks/web"
)

const usage = `granite-scan: audit DNS, Email, WWW, and BIMI security posture for a domain.

usage: granite-scan [flags] <domain>

flags:
`

func main() {
	var (
		jsonOut  = flag.Bool("json", false, "emit JSON report to stdout")
		mdOut    = flag.Bool("md", false, "emit Markdown report to stdout")
		noActive = flag.Bool("no-active", false, "skip active probes (SMTP STARTTLS, HTTPS GETs, VMC fetch)")
		resolver = flag.String("resolver", "", "DNS resolver address host:port (default: system resolver)")
		timeout  = flag.Duration("timeout", 5*time.Second, "per-operation timeout")
	)
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	target, err := normalizeTarget(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid target:", err)
		os.Exit(2)
	}

	if *jsonOut && *mdOut {
		fmt.Fprintln(os.Stderr, "choose only one of --json or --md")
		os.Exit(2)
	}

	env := probe.NewEnv(target, *timeout, !*noActive, *resolver)

	results := registry.Run(context.Background(), env)
	rep := report.Report{Target: target, Results: results}

	format := report.FormatText
	if *jsonOut {
		format = report.FormatJSON
	} else if *mdOut {
		format = report.FormatMarkdown
	}
	color := format == report.FormatText && isTTY(os.Stdout)
	if err := report.Render(os.Stdout, rep, format, color); err != nil {
		fmt.Fprintln(os.Stderr, "render error:", err)
		os.Exit(2)
	}

	if rep.HasFailures() {
		os.Exit(1)
	}
}

// normalizeTarget strips a trailing dot, lowercases, and Punycode-encodes IDNs.
func normalizeTarget(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", fmt.Errorf("empty domain")
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", err
	}
	return strings.ToLower(ascii), nil
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
