// bedrock: a Hardenize-inspired CLI that audits a domain's
// DNS, Email, and WWW security posture against IETF and vendor
// requirements. (BIMI checks live under the Email category in output.)
// See CLAUDE.md for the architecture and the approved plan.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/idna"

	"github.com/whitworth-org/bedrock/internal/baseline"
	"github.com/whitworth-org/bedrock/internal/cli"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
	"github.com/whitworth-org/bedrock/internal/version"

	// Side-effect imports register checks with the global registry.
	_ "github.com/whitworth-org/bedrock/internal/checks/bimi"
	_ "github.com/whitworth-org/bedrock/internal/checks/dns"
	_ "github.com/whitworth-org/bedrock/internal/checks/dnssec"
	_ "github.com/whitworth-org/bedrock/internal/checks/email"
	_ "github.com/whitworth-org/bedrock/internal/checks/web"
	_ "github.com/whitworth-org/bedrock/internal/discover"
)

const usage = `bedrock: audit DNS, Email, and WWW security posture for a domain.

usage: bedrock [flags] <domain>

flags:
`

func main() {
	var (
		jsonOut        = flag.Bool("json", false, "emit JSON report to stdout")
		mdOut          = flag.Bool("md", false, "emit Markdown report to stdout")
		noActive       = flag.Bool("no-active", false, "skip active probes (SMTP STARTTLS, HTTPS GETs, VMC fetch)")
		resolver       = flag.String("resolver", "", "DNS resolver: host:port, preset (cloudflare|google|quad9|opendns), or <preset>-dot/-doh, tls://host, https://url")
		resolversCSV   = flag.String("resolvers", "", "CSV of multiple resolvers for cross-resolver propagation check (e.g. cloudflare,google,quad9)")
		timeout        = flag.Duration("timeout", 5*time.Second, "per-operation timeout")
		configPath     = flag.String("config", "", "path to JSON config file (flag values override config values)")
		showVersion    = flag.Bool("version", false, "print version and exit")
		onlyCSV        = flag.String("only", "", "CSV of categories to include (e.g. Email,WWW)")
		excludeCSV     = flag.String("exclude", "", "CSV of categories to exclude")
		severity       = flag.String("severity", "", "minimum severity to include in output: info|pass|warn|fail")
		idsCSV         = flag.String("ids", "", "CSV of specific check IDs to include")
		subdomains     = flag.Bool("subdomains", false, "enumerate subdomains and run a subset of checks against each (uses passive sources; off by default)")
		enableRBL      = flag.Bool("enable-rbl", false, "enable optional DNSBL/RBL lookups (queries third-party services; off by default)")
		enableCT       = flag.Bool("enable-ct", false, "enable Certificate Transparency lookups via crt.sh (third-party; off by default)")
		baselinePath   = flag.String("baseline", "", "path to a previous JSON report; surface regressions vs that baseline")
		regressionOnly = flag.Bool("regression-only", false, "with --baseline: exit non-zero only on NEW failures vs baseline (pre-existing fails are ignored)")
	)
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	cfg, err := cli.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	mergeConfig(cfg, &mergeArgs{
		jsonOut: jsonOut, mdOut: mdOut, noActive: noActive,
		resolver: resolver, resolversCSV: resolversCSV, timeout: timeout,
		onlyCSV: onlyCSV, excludeCSV: excludeCSV, severity: severity, idsCSV: idsCSV,
		subdomains: subdomains, enableRBL: enableRBL, enableCT: enableCT,
		baselinePath: baselinePath, regressionOnly: regressionOnly,
	})

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

	resolvers := cli.SplitCSV(*resolversCSV)
	var env *probe.Env
	if len(resolvers) > 0 {
		env, err = probe.NewEnvMulti(target, *timeout, !*noActive, resolvers)
		if err != nil {
			fmt.Fprintln(os.Stderr, "resolver:", err)
			os.Exit(2)
		}
	} else {
		env = probe.NewEnv(target, *timeout, !*noActive, *resolver)
	}
	env.Subdomains = *subdomains
	env.EnableRBL = *enableRBL
	env.EnableCT = *enableCT

	// Propagate Ctrl-C / SIGTERM into the scan so in-flight lookups can bail
	// cleanly rather than leaking goroutines.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	results := registry.Run(ctx, env)

	minSeverity, severitySet, err := cli.ParseSeverity(*severity)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		stop()
		os.Exit(2) //nolint:gocritic // stop() called above; signal ctx cancelled before exit
	}
	filter := cli.Filter{
		Only:        cli.SplitCSV(*onlyCSV),
		Exclude:     cli.SplitCSV(*excludeCSV),
		MinSeverity: minSeverity,
		SeveritySet: severitySet,
		IDs:         cli.SplitCSV(*idsCSV),
	}
	results = filter.Apply(results)

	rep := report.Report{Target: target, Results: results}

	var regressions []report.Result
	if *baselinePath != "" {
		base, berr := baseline.Load(*baselinePath)
		if berr != nil {
			fmt.Fprintln(os.Stderr, "baseline:", berr)
			os.Exit(2)
		}
		regressions = baseline.Diff(base, rep)
	}

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
	if format == report.FormatText && len(regressions) > 0 {
		fmt.Fprintf(os.Stdout, "\n== Regressions vs baseline (%s) ==\n", *baselinePath)
		for _, r := range regressions {
			// Sanitise ID + Title: regression entries are echoed outside the
			// normal renderer, and the baseline file is attacker-influenceable
			// if it was produced by a previous scan of an untrusted domain.
			fmt.Fprintf(os.Stdout, "  [REGRESSION] %s — %s\n",
				report.SanitizeForTerminal(r.ID),
				report.SanitizeForTerminal(r.Title))
		}
		fmt.Fprintln(os.Stdout)
	}

	if *regressionOnly {
		if len(regressions) > 0 {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if rep.HasFailures() {
		os.Exit(1)
	}
}

type mergeArgs struct {
	jsonOut, mdOut, noActive              *bool
	resolver, resolversCSV                *string
	timeout                               *time.Duration
	onlyCSV, excludeCSV, severity, idsCSV *string
	subdomains, enableRBL, enableCT       *bool
	baselinePath                          *string
	regressionOnly                        *bool
}

// mergeConfig fills in unset flag values from the config. Flags explicitly
// set on the command line take precedence (we detect this with flag.Visit).
func mergeConfig(cfg *cli.Config, m *mergeArgs) {
	if cfg == nil {
		return
	}
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if !set["json"] && cfg.JSON {
		*m.jsonOut = true
	}
	if !set["md"] && cfg.Markdown {
		*m.mdOut = true
	}
	if !set["no-active"] && cfg.NoActive {
		*m.noActive = true
	}
	if !set["resolver"] && cfg.Resolver != "" {
		*m.resolver = cfg.Resolver
	}
	if !set["resolvers"] && len(cfg.Resolvers) > 0 {
		*m.resolversCSV = strings.Join(cfg.Resolvers, ",")
	}
	if !set["timeout"] {
		if d, err := cfg.Duration(*m.timeout); err == nil {
			*m.timeout = d
		}
	}
	if !set["only"] && len(cfg.Only) > 0 {
		*m.onlyCSV = strings.Join(cfg.Only, ",")
	}
	if !set["exclude"] && len(cfg.Exclude) > 0 {
		*m.excludeCSV = strings.Join(cfg.Exclude, ",")
	}
	if !set["severity"] && cfg.Severity != "" {
		*m.severity = cfg.Severity
	}
	if !set["ids"] && len(cfg.IDs) > 0 {
		*m.idsCSV = strings.Join(cfg.IDs, ",")
	}
	if !set["subdomains"] && cfg.Subdomains {
		*m.subdomains = true
	}
	if !set["enable-rbl"] && cfg.EnableRBL {
		*m.enableRBL = true
	}
	if !set["enable-ct"] && cfg.EnableCT {
		*m.enableCT = true
	}
	if !set["baseline"] && cfg.Baseline != "" {
		*m.baselinePath = cfg.Baseline
	}
	if !set["regression-only"] && cfg.RegressionOnly {
		*m.regressionOnly = true
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
