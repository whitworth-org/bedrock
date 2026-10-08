package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/cli"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// startupChildEnv marks a child process that runs main() with the
// arguments after "--"; see startupRun.
const startupChildEnv = "BEDROCK_STARTUP_CHILD"

// startupAllowPrivate lets a child use the loopback resolver.
const startupAllowPrivate = "BEDROCK_ALLOW_PRIVATE_RESOLVER=1"

// TestStartupChild is the child side of startupRun, not a test of its own.
func TestStartupChild(t *testing.T) {
	if os.Getenv(startupChildEnv) == "" {
		return
	}
	i := slices.Index(os.Args, "--")
	if i < 0 {
		t.Fatalf("startup child: no -- in %q", os.Args)
	}
	os.Args = append([]string{"bedrock"}, os.Args[i+1:]...)
	flag.CommandLine = flag.NewFlagSet("bedrock", flag.ExitOnError)
	main()
	os.Exit(0) // main returned: exit before the test framework prints to stdout
}

// startupResult is how one bedrock run exited and what it printed.
type startupResult struct {
	code           int
	stdout, stderr string
}

// startupRun runs bedrock with args in a child process whose environment
// has env added and BEDROCK_ALLOW_PRIVATE_RESOLVER unset unless env sets it.
func startupRun(t *testing.T, env []string, args ...string) startupResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	childArgs := slices.Concat([]string{"-test.run=^TestStartupChild$", "--"}, args)
	//nolint:gosec // G204: re-executes this test binary, not external input.
	cmd := exec.CommandContext(ctx, os.Args[0], childArgs...)
	inherited := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "BEDROCK_ALLOW_PRIVATE_RESOLVER=")
	})
	cmd.Env = slices.Concat(inherited, []string{startupChildEnv + "=1"}, env)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	var exitErr *exec.ExitError
	if err := cmd.Run(); err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("run bedrock %q: %v", args, err)
	}
	return startupResult{
		code:   cmd.ProcessState.ExitCode(),
		stdout: stdout.String(),
		stderr: stderr.String(),
	}
}

// startupResolver answers every query with NXDOMAIN on a loopback UDP port
// until the test ends. It returns the address and the count of queries.
func startupResolver(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	return startupRcodeResolver(t, mdns.RcodeNameError)
}

// startupRcodeResolver is startupResolver replying with rcode.
func startupRcodeResolver(t *testing.T, rcode int) (string, *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	var queries atomic.Int64
	srv := &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(
		func(w mdns.ResponseWriter, req *mdns.Msg) {
			queries.Add(1)
			resp := new(mdns.Msg)
			resp.SetRcode(req, rcode)
			_ = w.WriteMsg(resp)
		})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		_ = pc.Close()
		t.Fatal("fake resolver did not start within 2s")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), &queries
}

// startupArgs returns the arguments for a passive scan of startup.test
// through resolver, with extra flags.
func startupArgs(resolver string, extra ...string) []string {
	return slices.Concat(
		[]string{"--no-active", "--resolver", resolver}, extra, []string{"startup.test"})
}

// startupConfig writes cfg as a config file and returns its path.
func startupConfig(t *testing.T, cfg cli.Config) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestStartupRejectsBadInput: each bad flag or config value exits 2 before
// the scan starts, with nothing on stdout, the problem named on stderr, and
// no query sent.
func TestStartupRejectsBadInput(t *testing.T) {
	resolver, queries := startupResolver(t)
	allow := []string{startupAllowPrivate}
	zeroTimeout := startupConfig(t, cli.Config{Timeout: "0s"})
	regressionOnly := startupConfig(t, cli.Config{RegressionOnly: true})
	cases := []struct {
		name   string
		env    []string
		args   []string
		stderr []string
	}{
		{"unknown --only category", allow, startupArgs(resolver, "--only", "Emial"),
			[]string{`unknown category "Emial"`, "want one of: DNS, DNSSEC, Email"}},
		{"unknown --exclude category", allow, startupArgs(resolver, "--exclude", "WWW,Wbe"),
			[]string{`unknown category "Wbe"`}},
		{"zero --timeout", allow, startupArgs(resolver, "--timeout", "0"),
			[]string{"invalid --timeout 0s"}},
		{"negative --timeout", allow, startupArgs(resolver, "--timeout", "-5s"),
			[]string{"invalid --timeout -5s"}},
		{"zero timeout in config", allow, startupArgs(resolver, "--config", zeroTimeout),
			[]string{"invalid --timeout 0s"}},
		{"--regression-only without --baseline", allow,
			startupArgs(resolver, "--regression-only"),
			[]string{"--regression-only requires --baseline"}},
		{"regression_only in config without baseline", allow,
			startupArgs(resolver, "--config", regressionOnly),
			[]string{"--regression-only requires --baseline"}},
		{"every problem at once", allow,
			startupArgs(resolver, "--only", "Emial", "--timeout", "0"),
			[]string{`unknown category "Emial"`, "invalid --timeout 0s"}},
		{"malformed --resolver", allow, startupArgs("dns.example:abc"),
			[]string{`invalid port "abc"`}},
		{"--resolver with a path", allow, startupArgs("tls://dns.example/dns-query"),
			[]string{"with no path"}},
		{"denylisted --resolver", nil, startupArgs(resolver), []string{"is loopback"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := startupRun(t, c.env, c.args...)

			if got.code != 2 || got.stdout != "" {
				t.Errorf("exit %d, stdout %q; want exit 2 and no output", got.code, got.stdout)
			}
			for _, want := range c.stderr {
				if !strings.Contains(got.stderr, want) {
					t.Errorf("stderr %q does not contain %q", got.stderr, want)
				}
			}
		})
	}
	if n := queries.Load(); n != 0 {
		t.Errorf("the resolver saw %d queries; want none before the scan", n)
	}
}

// TestStartupCategories: --only and --exclude accept the categories of the
// check packages main links in.
func TestStartupCategories(t *testing.T) {
	want := []string{"DNS", "DNSSEC", "Email", "Subdomain", "WWW"}
	if got := registry.Categories(); !slices.Equal(got, want) {
		t.Errorf("registry.Categories() = %q, want %q", got, want)
	}
}

// TestStartupScansWithValidInput: valid input reaches the scan, which asks
// the chosen resolver and, with no records to find, exits 1. A resolver
// flag on the command line overrides both config resolver keys, and
// --resolvers overrides --resolver.
func TestStartupScansWithValidInput(t *testing.T) {
	resolver, queries := startupResolver(t)
	overridden, overriddenQueries := startupResolver(t)
	malformedResolvers := startupConfig(t, cli.Config{Resolvers: []string{"foo://malformed"}})
	overriddenResolver := startupConfig(t, cli.Config{Resolver: overridden})
	configResolver := startupConfig(t, cli.Config{NoActive: true, Resolver: resolver})
	configResolvers := startupConfig(t, cli.Config{NoActive: true, Resolvers: []string{resolver}})
	cases := []struct {
		name string
		args []string
	}{
		{"category names in any case", startupArgs(resolver, "--only", "email,wWw")},
		{"CLI --resolver over malformed config resolvers",
			startupArgs(resolver, "--config", malformedResolvers)},
		{"CLI --resolvers over config resolver", []string{
			"--config", overriddenResolver, "--no-active", "--resolvers", resolver, "startup.test",
		}},
		{"--resolvers over --resolver", startupArgs(overridden, "--resolvers", resolver)},
		{"config resolver", []string{"--config", configResolver, "startup.test"}},
		{"config resolvers", []string{"--config", configResolvers, "startup.test"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := queries.Load()

			got := startupRun(t, []string{startupAllowPrivate}, c.args...)

			if got.code != 1 || !strings.HasPrefix(got.stdout, "{") {
				t.Errorf("exit %d, stdout %.80q, stderr %q; want exit 1 and a JSON report",
					got.code, got.stdout, got.stderr)
			}
			if queries.Load() == before {
				t.Error("the scan sent no query to the chosen resolver")
			}
		})
	}
	if n := overriddenQueries.Load(); n != 0 {
		t.Errorf("an overridden resolver saw %d queries, want 0", n)
	}
}

// TestStartupFailsWhenResolverAnswersNothing: a resolver that replies only
// SERVFAIL or REFUSED serves the scan no better than a dead one, so the run
// reports dns.resolver.unreachable and exits 1, even when --ids names
// another check.
func TestStartupFailsWhenResolverAnswersNothing(t *testing.T) {
	servfail, _ := startupRcodeResolver(t, mdns.RcodeServerFailure)
	refused, _ := startupRcodeResolver(t, mdns.RcodeRefused)
	cases := []struct {
		name string
		args []string
	}{
		{"SERVFAIL", startupArgs(servfail)},
		{"REFUSED", startupArgs(refused)},
		{"SERVFAIL with --ids", startupArgs(servfail, "--ids", "email.spf.record")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := startupRun(t, []string{startupAllowPrivate}, c.args...)

			var rep report.Report
			if err := json.Unmarshal([]byte(got.stdout), &rep); err != nil {
				t.Fatalf("parse report: %v (stdout %.80q, stderr %q)", err, got.stdout, got.stderr)
			}
			i := slices.IndexFunc(rep.Results, func(r report.Result) bool {
				return r.ID == "dns.resolver.unreachable"
			})
			if got.code != 1 || i < 0 || rep.Results[i].Status != report.Fail {
				t.Errorf("exit %d, dns.resolver.unreachable at %d; want exit 1 and the FAIL",
					got.code, i)
			}
		})
	}
}

// TestStartupOnlyRunsNamedCategories: --only DNSSEC runs and reports just
// the DNSSEC checks, so it sends fewer queries than a scan of every
// category.
func TestStartupOnlyRunsNamedCategories(t *testing.T) {
	resolver, queries := startupResolver(t)
	allow := []string{startupAllowPrivate}
	startupRun(t, allow, startupArgs(resolver)...)
	all := queries.Swap(0)

	got := startupRun(t, allow, startupArgs(resolver, "--only", "DNSSEC")...)
	var rep report.Report
	if err := json.Unmarshal([]byte(got.stdout), &rep); err != nil {
		t.Fatalf("parse report: %v (stdout %.80q, stderr %q)", err, got.stdout, got.stderr)
	}
	for _, r := range rep.Results {
		if r.Category != "DNSSEC" {
			t.Errorf("--only DNSSEC reported %s from category %s", r.ID, r.Category)
		}
	}
	if only := queries.Load(); only >= all {
		t.Errorf("--only DNSSEC sent %d queries and a full scan %d; want fewer", only, all)
	}
}
