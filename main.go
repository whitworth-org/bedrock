// bedrock: a Hardenize-inspired CLI that audits a domain's DNS, DNSSEC,
// Email and WWW security posture against IETF and vendor requirements.
// (BIMI checks live under the Email category in output.)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/idna"

	"github.com/whitworth-org/bedrock/internal/baseline"
	"github.com/whitworth-org/bedrock/internal/cli"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/progress"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
	"github.com/whitworth-org/bedrock/internal/tty"
	"github.com/whitworth-org/bedrock/internal/version"

	// Side-effect imports register checks with the global registry.
	_ "github.com/whitworth-org/bedrock/internal/checks/bimi"
	_ "github.com/whitworth-org/bedrock/internal/checks/dns"
	_ "github.com/whitworth-org/bedrock/internal/checks/dnssec"
	_ "github.com/whitworth-org/bedrock/internal/checks/email"
	_ "github.com/whitworth-org/bedrock/internal/checks/web"
	_ "github.com/whitworth-org/bedrock/internal/discover"
)

const usage = `bedrock audits a domain's DNS, DNSSEC, Email (including BIMI) and WWW
(HTTPS, TLS, headers) security posture against RFCs and vendor requirements.
--subdomains adds passive subdomain discovery.

usage: bedrock [flags] <domain>

On a terminal, bedrock prints a report that ends with the fixes, a summary
per category and the verdict. A pipe, a file or --json gets the JSON report
instead. While it scans, bedrock prints progress lines on a terminal's
stderr, except under CI or when stdout is a pipe; when stdout is a file,
stderr also gets the verdict.

Exit codes:
  0  no FAIL (with --regression-only: no new FAIL since the baseline)
  1  at least one FAIL (with --regression-only: a new FAIL)
  2  usage error, invalid input or configuration, or a failed write

Examples:
  bedrock example.org                  # report on a terminal
  bedrock example.org > report.json    # JSON in a file, verdict on stderr
  bedrock --baseline report.json --regression-only example.org

Flags:
`

const resolversHelp = "CSV of resolvers: the first serves every lookup; the dnssec.sentinel\n" +
	"check tests each (e.g. cloudflare,google,quad9)"

const (
	// maxListed caps how many IDs a stderr list after the verdict names.
	maxListed = 10
	// listWidth bounds each line of such a list, prefix included.
	listWidth = 72
	// failingPrefix and unfinishedPrefix start the lists of failing IDs and
	// of unfinished checks; continuation lines are indented to their width.
	failingPrefix    = "bedrock: failing: "
	unfinishedPrefix = "bedrock: unfinished: "
)

// options is the parsed command line, with config-file values filled in for
// the flags the command line left unset.
type options struct {
	json, noColor, noActive         bool
	showVersion                     bool
	subdomains, enableRBL, enableCT bool
	regressionOnly                  bool
	timeout                         time.Duration
	configPath, domain              string
	resolver, resolversCSV          string
	onlyCSV, excludeCSV, idsCSV     string
	severity, baselinePath          string
}

// system is the process boundary run depends on, so tests can fake the
// environment, terminals and time without a pty.
type system struct {
	getenv     func(string) string
	isTerminal func(io.Writer) bool
	isRegular  func(io.Writer) bool
	// color reports whether the terminal w takes SGR colour under the
	// environment getenv reads. On Windows it also switches the console to
	// escape processing, so run calls it only for the terminal report.
	color func(w io.Writer, getenv func(string) string) bool
	clock progress.Clock
}

// scanPlan is an invocation whose inputs have all been validated.
type scanPlan struct {
	env    *probe.Env
	filter cli.Filter
	base   *report.Report
}

// destination says where each part of the output goes. It is decided once,
// before the scan, from the streams and the environment.
type destination struct {
	human    bool      // stdout gets the terminal report rather than JSON
	color    bool      // the terminal report is coloured
	progress io.Writer // stderr when it gets progress lines, otherwise nil
	verdict  bool      // stderr gets the verdict, because stdout is a file
}

// scanned is a finished scan: every result it gave, before --severity and
// --ids filter them, and how the scan went.
type scanned struct {
	results     []report.Result
	elapsed     time.Duration
	interrupted bool     // ctx was cancelled while checks were unfinished
	unfinished  []string // check IDs not done at that moment
}

// usageError is a mistake on the command line, or a flag value found
// invalid after parsing. Its message points at --help, which lists the
// valid forms.
type usageError struct{ error }

func main() {
	ctx, stop := signalContext()
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, osSystem())
	stop()
	os.Exit(code)
}

// signalContext returns a context that the first SIGINT or SIGTERM cancels,
// so in-flight lookups bail cleanly. Once ctx is done the signals revert to
// their previous handling, so on a terminal a second Ctrl-C ends the process
// at once even if a check ignores ctx.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop)
	return ctx, stop
}

// run is one bedrock invocation. It returns the process exit code: 0 when the
// report has no FAIL, 1 when it has one (with --regression-only, when there is
// a regression), and 2 for usage, setup and output errors. An interrupted scan
// keeps these codes; its report says INCOMPLETE.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, sys system) int {
	fs, o, err := parseFlags(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		printHelp(stdout, fs)
		return 0
	case err != nil:
		return fail(stderr, usageError{err})
	case o.showVersion:
		fmt.Fprintln(stdout, version.String())
		return 0
	}
	plan, err := prepare(fs, o, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	dest := chooseOutput(stdout, stderr, o, sys)
	s := scan(ctx, plan, dest.progress, sys.clock)
	if !s.interrupted {
		// After an interrupt, a check cut short can leave a valid ID unmatched.
		warnUnmatchedIDs(stderr, idsSource(fs), plan.filter.IDs, s.results)
	}
	rep, regressions := buildReport(plan, s.results)
	view := newView(o, s, dest, exitCode(rep, regressions, o.regressionOnly))
	if err := render(stdout, rep, view, dest.human); err != nil {
		return fail(stderr, err)
	}
	printVerdict(stderr, rep, view, dest)
	return view.Exit
}

// parseFlags parses args into options. It returns flag.ErrHelp for -h and
// --help, and an error describing any other command-line mistake.
func parseFlags(args []string) (*flag.FlagSet, *options, error) {
	o := &options{}
	fs := newFlagSet(o)
	if err := fs.Parse(args); err != nil {
		return fs, o, err
	}
	if o.showVersion {
		return fs, o, nil
	}
	if fs.NArg() != 1 {
		return fs, o, argsError(fs.Args())
	}
	o.domain = fs.Arg(0)
	return fs, o, nil
}

// newFlagSet binds bedrock's flags to o. The set prints nothing itself: run
// decides what reaches stdout and stderr.
func newFlagSet(o *options) *flag.FlagSet {
	fs := flag.NewFlagSet("bedrock", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.json, "json", false, "write the JSON report even when stdout is a terminal")
	fs.BoolVar(&o.noColor, "no-color", false,
		"no colour in the terminal report, as with a non-empty NO_COLOR\n"+
			"or TERM=dumb")
	fs.BoolVar(&o.noActive, "no-active", false,
		"skip active probes (SMTP STARTTLS, HTTPS GETs, VMC fetch)")
	fs.StringVar(&o.resolver, "resolver", "",
		"DNS resolver: host:port, preset (cloudflare|google|quad9|opendns),\n"+
			"or <preset>-dot/-doh, tls://host, https://url")
	fs.StringVar(&o.resolversCSV, "resolvers", "", resolversHelp)
	fs.DurationVar(&o.timeout, "timeout", 5*time.Second,
		"per-operation timeout, greater than zero")
	fs.StringVar(&o.configPath, "config", "",
		"path to JSON config file (flag values override config values)")
	fs.BoolVar(&o.showVersion, "version", false, "print version and exit")
	fs.StringVar(&o.onlyCSV, "only", "",
		"CSV of categories to include: DNS, DNSSEC, Email, WWW, Subdomain")
	fs.StringVar(&o.excludeCSV, "exclude", "", "CSV of categories to exclude")
	fs.StringVar(&o.severity, "severity", "",
		"minimum severity to include in output: info|pass|warn|fail")
	fs.StringVar(&o.idsCSV, "ids", "",
		"CSV of specific check IDs to include, plus the run-level\n"+
			"dns.resolver.unreachable and registry.panic.* results")
	fs.BoolVar(&o.subdomains, "subdomains", false,
		"enumerate subdomains and run a subset of checks against each\n"+
			"(uses passive sources; off by default)")
	fs.BoolVar(&o.enableRBL, "enable-rbl", false,
		"enable optional DNSBL/RBL lookups\n(queries third-party services; off by default)")
	fs.BoolVar(&o.enableCT, "enable-ct", false,
		"enable Certificate Transparency lookups via crt.sh\n(third-party; off by default)")
	fs.StringVar(&o.baselinePath, "baseline", "",
		"path to a previous JSON report; surface regressions vs that baseline")
	fs.BoolVar(&o.regressionOnly, "regression-only", false,
		"requires --baseline: exit non-zero only on NEW failures vs baseline\n"+
			"(pre-existing fails are ignored)")
	return fs
}

// argsError explains a wrong number of arguments. The flag package stops at
// the first argument that is not a flag, so a flag typed after the domain
// arrives here as an extra argument.
func argsError(args []string) error {
	if len(args) == 0 {
		return errors.New("missing domain")
	}
	err := fmt.Errorf("expected one domain, got %d: %q", len(args), args)
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			return fmt.Errorf("%w (flags go before the domain)", err)
		}
	}
	return err
}

// printHelp writes the usage text and every flag's default to w.
func printHelp(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, usage)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

// fail reports err on one stderr line, pointing at --help for a usage
// error, and returns the exit code for usage, setup and output errors.
func fail(stderr io.Writer, err error) int {
	hint := ""
	if errors.As(err, new(usageError)) {
		hint = "; run 'bedrock --help' for usage"
	}
	diagnose(stderr, err.Error()+hint)
	return 2
}

// diagnose writes msg to stderr as one "bedrock: " line. The text is made
// display-safe, so a flag value, file name or target can neither write
// escape sequences nor start a second line nor hide text.
func diagnose(stderr io.Writer, msg string) {
	fmt.Fprintf(stderr, "bedrock: %s\n", report.DisplaySafe(msg))
}

// prepare merges the config file into o and validates every input, so a typo
// fails in milliseconds rather than after a full scan. Once every input is
// valid, a config timeout that does not parse gets a warning, as bedrock
// scans on with the default.
func prepare(fs *flag.FlagSet, o *options, stderr io.Writer) (*scanPlan, error) {
	cfg, err := cli.LoadConfig(o.configPath)
	if err != nil {
		return nil, err
	}
	timeoutErr := mergeConfig(cfg, fs, o)
	target, err := normalizeTarget(o.domain)
	if err != nil {
		return nil, usageError{fmt.Errorf("invalid domain %q: %w", o.domain, err)}
	}
	filter, base, err := loadOptions(o)
	if err != nil {
		return nil, err
	}
	env, err := newEnv(target, o)
	if err != nil {
		return nil, err
	}
	if timeoutErr != nil {
		diagnose(stderr, fmt.Sprintf("%v; scanning with the default timeout %s",
			timeoutErr, o.timeout))
	}
	return &scanPlan{env: env, filter: filter, base: base}, nil
}

// mergeConfig fills in the options the command line left unset from cfg.
// Flags set on the command line win; fs.Visit reports exactly those. A
// timeout the config file gives but that does not parse is left at the
// default and returned as the error, as a warning: bedrock has always
// scanned on in that case. Every other option is merged regardless.
func mergeConfig(cfg *cli.Config, fs *flag.FlagSet, o *options) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	setBool := func(name string, dst *bool, v bool) {
		if v && !set[name] {
			*dst = true
		}
	}
	setString := func(name string, dst *string, v string) {
		if v != "" && !set[name] {
			*dst = v
		}
	}
	setBool("no-color", &o.noColor, cfg.NoColor)
	setBool("no-active", &o.noActive, cfg.NoActive)
	setBool("subdomains", &o.subdomains, cfg.Subdomains)
	setBool("enable-rbl", &o.enableRBL, cfg.EnableRBL)
	setBool("enable-ct", &o.enableCT, cfg.EnableCT)
	setBool("regression-only", &o.regressionOnly, cfg.RegressionOnly)
	mergeResolvers(cfg, set, o)
	setString("only", &o.onlyCSV, strings.Join(cfg.Only, ","))
	setString("exclude", &o.excludeCSV, strings.Join(cfg.Exclude, ","))
	setString("severity", &o.severity, cfg.Severity)
	setString("ids", &o.idsCSV, strings.Join(cfg.IDs, ","))
	setString("baseline", &o.baselinePath, cfg.Baseline)
	if set["timeout"] {
		return nil
	}
	timeout, err := cfg.Duration(o.timeout)
	if err != nil {
		return fmt.Errorf("config %s: %w", o.configPath, err)
	}
	o.timeout = timeout
	return nil
}

// mergeResolvers fills in the resolvers from cfg unless the command line
// sets either resolver flag. The two flags choose the resolvers together:
// either one on the command line overrides both config keys.
func mergeResolvers(cfg *cli.Config, set map[string]bool, o *options) {
	if set["resolver"] || set["resolvers"] {
		return
	}
	o.resolver = cfg.Resolver
	o.resolversCSV = strings.Join(cfg.Resolvers, ",")
}

// validateArgs reports, on one line, every flag value that rules out a
// useful scan, so run can exit 2 before sending a query. severityErr is the
// error from parsing --severity, which f cannot carry.
func validateArgs(f cli.Filter, severityErr error, timeout time.Duration,
	regressionOnly bool, baseline string) error {
	categories := registry.Categories()
	err := errors.Join(
		cli.ValidateCategories(f.Only, categories),
		cli.ValidateCategories(f.Exclude, categories),
		severityErr,
		cli.ValidateTimeout(timeout),
		cli.ValidateRegressionOnly(regressionOnly, baseline),
	)
	if err == nil {
		return nil
	}
	// errors.Join puts each error on a line of its own.
	return errors.New(strings.ReplaceAll(err.Error(), "\n", "; "))
}

// resolverSpecs lists the resolvers to use: --resolvers when it names any,
// else --resolver, else none, which selects the system resolvers.
func resolverSpecs(resolversCSV, resolver string) []string {
	if specs := cli.SplitCSV(resolversCSV); len(specs) > 0 {
		return specs
	}
	if resolver != "" {
		return []string{resolver}
	}
	return nil
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

// loadOptions parses --severity into the result filter, checks the flag
// values with validateArgs, and loads --baseline.
func loadOptions(o *options) (cli.Filter, *report.Report, error) {
	minSeverity, severitySet, severityErr := cli.ParseSeverity(o.severity)
	filter := cli.Filter{
		Only:        cli.SplitCSV(o.onlyCSV),
		Exclude:     cli.SplitCSV(o.excludeCSV),
		MinSeverity: minSeverity,
		SeveritySet: severitySet,
		IDs:         cli.SplitCSV(o.idsCSV),
	}
	err := validateArgs(filter, severityErr, o.timeout, o.regressionOnly, o.baselinePath)
	if err != nil {
		return cli.Filter{}, nil, usageError{err}
	}
	if o.baselinePath == "" {
		return filter, nil, nil
	}
	base, err := baseline.Load(o.baselinePath)
	if err != nil {
		return cli.Filter{}, nil, err
	}
	return filter, base, nil
}

// newEnv builds the probe environment. Every resolver spec is validated
// here, and without one the system must have a resolver.
func newEnv(target string, o *options) (*probe.Env, error) {
	env, err := probe.NewEnvMulti(target, o.timeout, !o.noActive,
		resolverSpecs(o.resolversCSV, o.resolver))
	if err != nil {
		return nil, resolverError(o, err)
	}
	env.Subdomains = o.subdomains
	env.EnableRBL = o.enableRBL
	env.EnableCT = o.enableCT
	return env, nil
}

// resolverError names the flag behind err, from NewEnvMulti, and for
// --resolvers the position of the first entry it rejects: err may not name
// the entry, and repeating it could show a DoH URL's password or token.
// Without either flag, err says there is no system resolver.
func resolverError(o *options, err error) error {
	entries := cli.SplitCSV(o.resolversCSV)
	for i, entry := range entries {
		if _, entryErr := probe.NewMultiDNS([]string{entry}, o.timeout); entryErr != nil {
			return fmt.Errorf("invalid --resolvers entry %d: %w", i+1, entryErr)
		}
	}
	if len(entries) == 0 && o.resolver != "" {
		return fmt.Errorf("invalid --resolver: %w", err)
	}
	return err
}

// chooseOutput applies the stdout rule: a terminal gets the report, while a
// pipe, a file or --json gets JSON. Progress lines and, for a file, the
// verdict go to stderr only when showProgress allows.
func chooseOutput(stdout, stderr io.Writer, o *options, sys system) destination {
	d := destination{human: sys.isTerminal(stdout) && !o.json}
	d.color = d.human && !o.noColor && sys.color(stdout, sys.getenv)
	if showProgress(stdout, stderr, sys) {
		d.progress = stderr
		d.verdict = sys.isRegular(stdout)
	}
	return d
}

// showProgress reports whether stderr may get progress lines: it is a
// terminal, CI is unset, and stdout is a terminal or a regular file. A pipe
// may feed a pager or jq that shares the screen, so it never gets them.
func showProgress(stdout, stderr io.Writer, sys system) bool {
	return sys.isTerminal(stderr) && sys.getenv("CI") == "" &&
		(sys.isTerminal(stdout) || sys.isRegular(stdout))
}

// scan runs the registered checks in the categories the filter keeps and
// reports progress on them to w (nil for none). If ctx is cancelled while
// checks are unfinished, the scan is marked interrupted, with the checks not
// done at that moment.
func scan(ctx context.Context, plan *scanPlan, w io.Writer, clock progress.Clock) scanned {
	keep := plan.filter.KeepCategory
	prog := progress.New(w, checkIDs(keep), clock)
	prog.Start(progress.Info{
		Target: plan.env.Target, Active: plan.env.Active, Timeout: plan.env.Timeout,
	})
	defer prog.Stop()
	interrupts := make(chan []string, 1)
	stopWatching := context.AfterFunc(ctx, func() { interrupts <- prog.Interrupt() })
	start := clock.Now()
	opts := registry.Options{Keep: keep, OnDone: func(c registry.Check) { prog.Done(c.ID()) }}
	results := registry.Run(ctx, plan.env, opts)
	s := scanned{results: results, elapsed: clock.Now().Sub(start)}
	if !stopWatching() {
		// ctx was cancelled first, so the callback has run or is running;
		// its send carries the checks unfinished at the interrupt. A cancel
		// after the last check finished cut nothing short.
		s.unfinished = <-interrupts
		s.interrupted = len(s.unfinished) > 0
	}
	return s
}

// checkIDs lists the ID of every registered check in a category keep
// accepts: the checks registry.Run runs.
func checkIDs(keep func(category string) bool) []string {
	var ids []string
	for _, c := range registry.All() {
		if keep(c.Category()) {
			ids = append(ids, c.ID())
		}
	}
	return ids
}

// idsSource names where the --ids entries came from: the flag when it was
// set on the command line, which then wins, otherwise the config file.
func idsSource(fs *flag.FlagSet) string {
	source := `config "ids"`
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "ids" {
			source = "--ids"
		}
	})
	return source
}

// warnUnmatchedIDs names, in one stderr line, each --ids entry that no
// result of the scan has, before --severity and --ids filter them: a
// mistyped ID, or one in a category --only or --exclude skips, otherwise
// just leaves the report without it. source says where the entries came
// from. Quoting keeps any control character in an entry inert.
func warnUnmatchedIDs(stderr io.Writer, source string, ids []string, results []report.Result) {
	found := make(map[string]bool, len(results))
	for _, r := range results {
		found[r.ID] = true
	}
	var missing []string
	for _, id := range ids {
		if !found[id] {
			found[id] = true // name a repeated entry once
			missing = append(missing, strconv.Quote(id))
		}
	}
	if len(missing) == 0 {
		return
	}
	noun, verb, pronoun := "entry", "matches", "it"
	if len(missing) > 1 {
		noun, verb, pronoun = "entries", "match", "them"
	}
	diagnose(stderr, fmt.Sprintf("%s %s %s %s no result; check %s against the IDs in a report "+
		"run without filters", source, noun, strings.Join(missing, ", "), verb, pronoun))
}

// buildReport filters the results for output and compares them with the
// baseline. The summary is computed after filtering, so its totals match the
// results the report shows.
func buildReport(plan *scanPlan, results []report.Result) (report.Report, []report.Result) {
	shown := plan.filter.Apply(results)
	rep := report.Report{
		Target:  plan.env.Target,
		Results: shown,
		Summary: report.Summarize(shown),
	}
	return rep, applyBaseline(&rep, plan.base)
}

// applyBaseline records in rep each FAIL that is new since base and returns
// those results; without a baseline it returns nil.
func applyBaseline(rep *report.Report, base *report.Report) []report.Result {
	regressions := baseline.Diff(base, *rep)
	for _, r := range regressions {
		rep.Regressions = append(rep.Regressions, report.ResultRef{ID: r.ID, Title: r.Title})
	}
	return regressions
}

// exitCode is the process exit code for a finished scan: 1 when the run
// fails, otherwise 0. Any FAIL fails the run; with regressionOnly only a
// regression against the baseline does.
func exitCode(rep report.Report, regressions []report.Result, regressionOnly bool) int {
	failed := rep.HasFailures()
	if regressionOnly {
		failed = len(regressions) > 0
	}
	if failed {
		return 1
	}
	return 0
}

// newView gathers what the terminal report and the verdict say beyond the
// report itself; exit is the process exit code, computed once.
func newView(o *options, s scanned, d destination, exit int) report.View {
	return report.View{
		Color:          d.color,
		Elapsed:        s.elapsed,
		Scanned:        len(s.results),
		Passive:        o.noActive,
		Resolvers:      resolverLabels(o),
		Baseline:       o.baselinePath,
		RegressionOnly: o.regressionOnly,
		Interrupted:    s.interrupted,
		Unfinished:     s.unfinished,
		Exit:           exit,
	}
}

// resolverLabels names the resolvers the scan used, the specs resolverSpecs
// picks for newEnv, as given but without credentials; the system resolvers
// get none.
func resolverLabels(o *options) []string {
	specs := resolverSpecs(o.resolversCSV, o.resolver)
	for i, spec := range specs {
		specs[i] = redactResolver(spec)
	}
	return specs
}

// redactResolver cuts a URL spec (tls://, https://) to its scheme and host,
// as the probe package labels DoH upstreams: a DoH endpoint may take a
// password, token or account identifier in its user information, path,
// query or fragment. Other specs, such as host:port or a preset name, have
// none and pass unchanged; a URL that does not parse is cut to its scheme,
// as it may hold one too.
func redactResolver(spec string) string {
	scheme, _, isURL := strings.Cut(spec, "://")
	if !isURL {
		return spec
	}
	u, err := url.Parse(spec)
	if err != nil {
		return scheme + "://..."
	}
	return u.Scheme + "://" + u.Host
}

// render writes rep to stdout: the terminal report when human, otherwise the
// JSON document, byte for byte what a pipe has always received.
func render(stdout io.Writer, rep report.Report, v report.View, human bool) error {
	if human {
		return report.RenderHuman(stdout, rep, v)
	}
	if err := report.RenderJSON(stdout, rep); err != nil {
		return fmt.Errorf("write JSON report for %s: %w", rep.Target, err)
	}
	return nil
}

// printVerdict writes the verdict to stderr when nothing else would show it
// there. When stdout is a file, so 'bedrock example.org > report.json'
// still shows the result, it adds the unfinished checks and the failing IDs.
// When progress is off, an interrupted run gets the verdict line alone,
// since the JSON has no field that marks a report partial.
func printVerdict(stderr io.Writer, rep report.Report, v report.View, d destination) {
	switch {
	case d.verdict:
		diagnose(stderr, rep.Target+": "+report.Verdict(rep, v))
		lines := listLines(unfinishedPrefix, v.Unfinished)
		lines = append(lines, listLines(failingPrefix, report.FailingIDs(rep, v))...)
		for _, line := range lines {
			fmt.Fprintln(stderr, line)
		}
	case v.Interrupted && d.progress == nil:
		diagnose(stderr, rep.Target+": "+report.Verdict(rep, v))
	}
}

// listLines lists at most maxListed of ids under prefix, then "and N more",
// wrapped between IDs at listWidth columns with continuation lines indented
// to the prefix. Each ID is made display-safe.
func listLines(prefix string, ids []string) []string {
	n := min(len(ids), maxListed)
	shown := make([]string, n, n+1)
	for i, id := range ids[:n] {
		shown[i] = report.DisplaySafe(id)
	}
	if len(ids) > n {
		shown = append(shown, fmt.Sprintf("and %d more", len(ids)-n))
	}
	lines := report.WrapIDs(shown, listWidth-len(prefix))
	for i := range lines {
		lead := prefix
		if i > 0 {
			lead = strings.Repeat(" ", len(prefix))
		}
		lines[i] = lead + lines[i]
	}
	return lines
}

// osSystem is the real process boundary.
func osSystem() system {
	return system{
		getenv:     os.Getenv,
		isTerminal: onFile(tty.IsTerminal),
		isRegular:  onFile(tty.IsRegular),
		color: func(w io.Writer, getenv func(string) string) bool {
			f, ok := w.(*os.File)
			return ok && tty.Color(f, getenv)
		},
		clock: progress.SystemClock(),
	}
}

// onFile adapts a test on an open file to any writer; a writer that is not an
// *os.File, such as a buffer, passes no such test.
func onFile(test func(*os.File) bool) func(io.Writer) bool {
	return func(w io.Writer) bool {
		f, ok := w.(*os.File)
		return ok && test(f)
	}
}
