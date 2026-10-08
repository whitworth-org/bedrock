package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/whitworth-org/bedrock/internal/cli"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
	"github.com/whitworth-org/bedrock/internal/version"
)

// stream is the kind of stream a test writer stands for.
type stream int

const (
	pipe stream = iota
	terminal
	regularFile
)

func (s stream) String() string {
	return [...]string{"pipe", "terminal", "file"}[s]
}

// fakeStream is an in-memory stream that the fake system takes for its kind.
type fakeStream struct {
	bytes.Buffer
	kind stream
}

func (s *fakeStream) streamKind() stream { return s.kind }

// streamKind returns the kind of stream w stands for; a writer that does not
// say, such as a plain buffer, is a pipe.
func streamKind(w io.Writer) stream {
	if k, ok := w.(interface{ streamKind() stream }); ok {
		return k.streamKind()
	}
	return pipe
}

// frozenClock is a progress clock that never moves and never fires, so a
// report shows no elapsed time and progress prints no heartbeat.
type frozenClock struct{}

func (frozenClock) Now() time.Time                       { return time.Unix(0, 0) }
func (frozenClock) After(time.Duration) <-chan time.Time { return nil }

// fakeSystem is a process boundary on which each writer is the kind of
// stream it says, getenv reads env, and time stands still.
func fakeSystem(env map[string]string) system {
	return system{
		getenv:     func(key string) string { return env[key] },
		isTerminal: func(w io.Writer) bool { return streamKind(w) == terminal },
		isRegular:  func(w io.Writer) bool { return streamKind(w) == regularFile },
		// A terminal that, as tty.Color does, honours NO_COLOR and TERM=dumb.
		color: func(w io.Writer, getenv func(string) string) bool {
			return streamKind(w) == terminal && getenv("NO_COLOR") == "" &&
				getenv("TERM") != "dumb"
		},
		clock: frozenClock{},
	}
}

// runOn runs bedrock in-process with stdout and stderr on the given kinds of
// stream and returns its exit code, stdout and stderr.
func runOn(t *testing.T, out, errOut stream, env map[string]string,
	args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stdout, stderr := &fakeStream{kind: out}, &fakeStream{kind: errOut}
	code := run(ctx, args, stdout, stderr, fakeSystem(env))
	return code, stdout.String(), stderr.String()
}

// startScanFixture starts the NXDOMAIN-only resolver for this test and
// returns its spec and query counter.
func startScanFixture(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	// The fake resolver listens on loopback, which bedrock otherwise rejects.
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	h := &fakeDNSHandler{}
	return serveDNS(t, h), &h.queries
}

// scanArgs returns a command line that scans test.invalid through the fake
// resolver at spec with active probes off; extra flags go before the domain.
func scanArgs(spec string, extra ...string) []string {
	args := []string{"--no-active", "--timeout", "2s", "--resolver", spec}
	args = append(args, extra...)
	return append(args, "test.invalid")
}

// startLine is the progress line a scan of the empty fixture starts with.
func startLine() string {
	return fmt.Sprintf("bedrock: scanning test.invalid: %d checks, passive only, timeout 2s\n",
		len(registry.All()))
}

// fixtureVerdict is what stderr ends with when the empty fixture's JSON goes
// to a file: the verdict, then its failing IDs wrapped under the first one.
const fixtureVerdict = `bedrock: test.invalid: FAIL. 8 FAIL (DNS 2, Email 6), 4 WARN. Exit code 1.
bedrock: failing: dns.ns.count, dns.zone.soa, bimi.txt,
                  email.dkim.selector.none, email.dmarc.record,
                  email.mtasts.txt, email.spf.record,
                  email.tlsrpt.record
`

// writeFile writes content to a new file in a temporary directory and
// returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// createFile creates an empty file that is closed when the test ends.
func createFile(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// assertOneLine checks that stderr is exactly one 'bedrock: ' line that
// mentions want.
func assertOneLine(t *testing.T, stderr, want string) {
	t.Helper()
	oneLine := strings.Count(stderr, "\n") == 1 && strings.HasSuffix(stderr, "\n")
	if !oneLine || !strings.HasPrefix(stderr, "bedrock: ") || !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want one 'bedrock: ' line mentioning %q", stderr, want)
	}
}

// assertGolden checks that out, with the fake resolver's port masked, is
// byte for byte testdata/golden/<name>.
func assertGolden(t *testing.T, out, spec, name string) {
	t.Helper()
	got, want := normalizeOutput(out, spec), readGolden(t, name)
	if got != want {
		t.Errorf("output differs from testdata/golden/%s at %s", name,
			firstDivergence(strings.Split(got, "\n"), strings.Split(want, "\n")))
	}
}

// TestRunWritesPlainJSONWhenStdoutIsAFile scans the empty fixture with
// stdout and stderr redirected to files, as 'bedrock x > out.json 2> err'
// does, through the real process boundary.
func TestRunWritesPlainJSONWhenStdoutIsAFile(t *testing.T) {
	spec, queries := startScanFixture(t)
	dir := t.TempDir()
	stdout := createFile(t, filepath.Join(dir, "stdout"))
	stderr := createFile(t, filepath.Join(dir, "stderr"))
	sys := osSystem()
	sys.getenv = func(string) string { return "" }

	code := run(context.Background(), scanArgs(spec), stdout, stderr, sys)

	if code != 1 {
		t.Errorf("exit code = %d, want 1 for a report with FAILs", code)
	}
	if queries.Load() == 0 {
		t.Error("the fake resolver answered no queries, so the scan never ran")
	}
	got, err := os.ReadFile(stdout.Name())
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	assertGolden(t, string(got), spec, "empty.json")
	if errOut, err := os.ReadFile(stderr.Name()); err != nil || len(errOut) != 0 {
		t.Errorf("stderr = %q (read error %v), want it empty", errOut, err)
	}
}

// noColor is the environment of a terminal that gets no colour, so its report
// compares as plain text.
var noColor = map[string]string{"NO_COLOR": "1"}

// TestRunStdoutRule checks what each kind of stdout gets: a terminal gets the
// report, and a pipe, a file or --json gets the JSON document, each byte for
// byte its golden.
func TestRunStdoutRule(t *testing.T) {
	spec, _ := startScanFixture(t)
	tests := []struct {
		name   string
		stdout stream
		flags  []string
		golden string
	}{
		{"terminal", terminal, nil, "empty.human.txt"},
		{"terminal with --json", terminal, []string{"--json"}, "empty.json"},
		{"pipe", pipe, nil, "empty.json"},
		{"pipe with --json", pipe, []string{"--json"}, "empty.json"},
		{"file", regularFile, nil, "empty.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, _ := runOn(t, tt.stdout, pipe, noColor, scanArgs(spec, tt.flags...)...)
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			assertGolden(t, stdout, spec, tt.golden)
		})
	}
}

// bedrockSGR matches the SGR sequences the terminal report may use: reset,
// bold, FAIL 1;31, WARN 33, PASS 32 and INFO 36.
var bedrockSGR = regexp.MustCompile(`\x1b\[(?:0|1|1;31|33|32|36)m`)

// TestRunColorsOnlyTheTerminalReport checks when the terminal report is
// coloured, and that removing bedrock's own SGR codes from a coloured report
// leaves exactly the plain golden, so no other escape sequence is written.
func TestRunColorsOnlyTheTerminalReport(t *testing.T) {
	spec, _ := startScanFixture(t)
	noColorConfig := writeFile(t, "config.json", `{"no_color": true}`)
	tests := []struct {
		name  string
		env   map[string]string
		flags []string
		want  bool
	}{
		{name: "colour terminal", want: true},
		{name: "empty NO_COLOR", env: map[string]string{"NO_COLOR": ""}, want: true},
		{name: "NO_COLOR", env: map[string]string{"NO_COLOR": "1"}},
		{name: "TERM=dumb", env: map[string]string{"TERM": "dumb"}},
		{name: "--no-color", flags: []string{"--no-color"}},
		{name: "no_color in the config", flags: []string{"--config", noColorConfig}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stdout, _ := runOn(t, terminal, pipe, tt.env, scanArgs(spec, tt.flags...)...)
			if got := strings.Contains(stdout, "\x1b"); got != tt.want {
				t.Errorf("report coloured = %v, want %v", got, tt.want)
			}
			assertGolden(t, bedrockSGR.ReplaceAllString(stdout, ""), spec, "empty.human.txt")
		})
	}
}

// TestRunAsksForColourOnlyForTheTerminalReport checks that run consults the
// system's colour test, which on Windows switches the console mode, only
// when stdout gets the terminal report and --no-color is not set.
func TestRunAsksForColourOnlyForTheTerminalReport(t *testing.T) {
	spec, _ := startScanFixture(t)
	tests := []struct {
		name   string
		stdout stream
		flags  []string
		want   bool
	}{
		{"terminal", terminal, nil, true},
		{"terminal with --no-color", terminal, []string{"--no-color"}, false},
		{"terminal with --json", terminal, []string{"--json"}, false},
		{"file", regularFile, nil, false},
		{"pipe", pipe, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sys := fakeSystem(nil)
			asked := false
			sys.color = func(io.Writer, func(string) string) bool {
				asked = true
				return false
			}
			stdout := &fakeStream{kind: tt.stdout}
			run(context.Background(), scanArgs(spec, tt.flags...), stdout, &bytes.Buffer{}, sys)
			if asked != tt.want {
				t.Errorf("colour asked = %v, want %v", asked, tt.want)
			}
		})
	}
}

// gateCase is one mix of streams and environment for the progress gate.
type gateCase struct {
	stdout, stderr stream
	env            map[string]string
}

func (c gateCase) String() string {
	return fmt.Sprintf("stdout %s, stderr %s, env %v", c.stdout, c.stderr, c.env)
}

// wantStderr is what stderr holds after a scan of the empty fixture: progress
// only when stderr is a terminal, CI is unset and stdout is a terminal or a
// file, and then the verdict as well for a file.
func (c gateCase) wantStderr() string {
	switch {
	case c.stderr != terminal || c.env["CI"] != "" || c.stdout == pipe:
		return ""
	case c.stdout == regularFile:
		return startLine() + fixtureVerdict
	}
	return startLine()
}

func gateCases() []gateCase {
	envs := []map[string]string{nil, {"CI": "true"}, {"CI": "1"}, {"TERM": "dumb"}}
	var cases []gateCase
	for _, out := range []stream{terminal, regularFile, pipe} {
		for _, errOut := range []stream{terminal, pipe} {
			for _, env := range envs {
				cases = append(cases, gateCase{stdout: out, stderr: errOut, env: env})
			}
		}
	}
	return cases
}

// TestRunProgressGate runs the empty fixture on every mix of stdout
// {terminal, file, pipe}, stderr {terminal, pipe} and environment {none,
// CI=true, CI=1, TERM=dumb}. Any non-empty CI turns progress off; TERM=dumb
// turns colour off but leaves progress on.
func TestRunProgressGate(t *testing.T) {
	spec, _ := startScanFixture(t)
	for _, gc := range gateCases() {
		t.Run(gc.String(), func(t *testing.T) {
			code, stdout, stderr := runOn(t, gc.stdout, gc.stderr, gc.env, scanArgs(spec)...)
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if want := gc.wantStderr(); stderr != want {
				t.Errorf("stderr:\n%s\nwant:\n%s", stderr, want)
			}
			human := strings.HasPrefix(stdout, "bedrock report for test.invalid (")
			if human != (gc.stdout == terminal) {
				t.Errorf("stdout got the terminal report = %v, want it only on a terminal", human)
			}
		})
	}
}

// lineStarting returns the first line of s that starts with prefix, without
// its newline, or "" when there is none.
func lineStarting(s, prefix string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

// lastLine returns the last line of s, without its newline.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// goldenReport decodes testdata/golden/empty.json, the report a scan of the
// empty fixture gives.
func goldenReport(t *testing.T) report.Report {
	t.Helper()
	var rep report.Report
	if err := json.Unmarshal([]byte(readGolden(t, "empty.json")), &rep); err != nil {
		t.Fatalf("decode golden empty.json: %v", err)
	}
	return rep
}

// writeBaseline writes the empty fixture's report with result id passing,
// so a scan of the fixture has one regression against it, and returns the
// file's path.
func writeBaseline(t *testing.T, id string) string {
	t.Helper()
	rep := goldenReport(t)
	for i := range rep.Results {
		if rep.Results[i].ID == id {
			rep.Results[i].Status = report.Pass
		}
	}
	var doc bytes.Buffer
	if err := report.RenderJSON(&doc, rep); err != nil {
		t.Fatalf("render baseline: %v", err)
	}
	return writeFile(t, "older.json", doc.String())
}

// TestRunVerdictNamesTheExitCode checks the verdict for each way a run can
// end, as the last line of the terminal report and, when stdout is a file,
// on stderr. Each names the exit code run returns.
func TestRunVerdictNamesTheExitCode(t *testing.T) {
	spec, _ := startScanFixture(t)
	same := writeFile(t, "same.json", readGolden(t, "empty.json"))
	older := writeBaseline(t, "email.spf.record")
	const fails = "8 FAIL (DNS 2, Email 6), 4 WARN."
	noneShown := fmt.Sprintf("PASS. 0 of %d results shown; check --severity and --ids.",
		len(goldenReport(t).Results))
	tests := []struct {
		name    string
		flags   []string
		verdict string
		code    int
	}{
		{"FAILs", nil, "FAIL. " + fails, 1},
		{"no FAIL shown", []string{"--ids", "dns.aaaa.apex"}, "PASS. 0 FAIL, 1 WARN.", 0},
		{"nothing shown", []string{"--ids", "dns.nope"}, noneShown, 0},
		{"regression-only, nothing new", []string{"--baseline", same, "--regression-only"},
			"PASS. 0 new FAIL since " + same + "; 8 FAIL in total.", 0},
		{"regression-only, one new FAIL", []string{"--baseline", older, "--regression-only"},
			"FAIL. 1 new FAIL since " + older + "; 8 FAIL in total.", 1},
		{"baseline without regression-only", []string{"--baseline", same}, "FAIL. " + fails, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := fmt.Sprintf("%s Exit code %d.", tt.verdict, tt.code)
			code, stdout, _ := runOn(t, terminal, pipe, noColor, scanArgs(spec, tt.flags...)...)
			if got := lastLine(stdout); code != tt.code || got != "Result: "+want {
				t.Errorf("terminal: exit code %d, last line %q\nwant %d and %q",
					code, got, tt.code, "Result: "+want)
			}
			code, _, stderr := runOn(t, regularFile, terminal, nil, scanArgs(spec, tt.flags...)...)
			const prefix = "bedrock: test.invalid: "
			if got := lineStarting(stderr, prefix); code != tt.code || got != prefix+want {
				t.Errorf("file: exit code %d, stderr verdict %q\nwant %d and %q",
					code, got, tt.code, prefix+want)
			}
		})
	}
}

// steppingClock moves on by step at every reading and never fires.
type steppingClock struct {
	step time.Duration
	now  atomic.Int64
}

func (c *steppingClock) Now() time.Time {
	return time.Unix(0, c.now.Add(int64(c.step)))
}

func (*steppingClock) After(time.Duration) <-chan time.Time { return nil }

// TestRunHeaderCountsTheScan checks what the terminal report's first line
// takes from the run: how many results --ids left of those the scan gave,
// which --only limits to the DNS checks, the time the scan took, passive
// mode and the resolver.
func TestRunHeaderCountsTheScan(t *testing.T) {
	spec, _ := startScanFixture(t)
	dns := 0
	for _, r := range goldenReport(t).Results {
		if r.Category == "DNS" {
			dns++
		}
	}
	sys := fakeSystem(noColor)
	// Without progress the scan reads the clock twice: at its start and end.
	sys.clock = &steppingClock{step: 1500 * time.Millisecond}
	stdout := &fakeStream{kind: terminal}
	args := scanArgs(spec, "--only", "DNS", "--ids", "dns.ns.count")
	code := run(context.Background(), args, stdout, &bytes.Buffer{}, sys)
	want := fmt.Sprintf("bedrock report for test.invalid "+
		"(1 of %d results, 1.5s, passive only, resolver %s)", dns, spec)
	if got := lineStarting(stdout.String(), "bedrock report for "); code != 1 || got != want {
		t.Errorf("exit code %d, header %q\nwant 1 and %q", code, got, want)
	}
}

func TestRunWarnsAboutUnmatchedIDs(t *testing.T) {
	spec, _ := startScanFixture(t)
	config := writeFile(t, "ids.json", `{"ids": ["dns.axfr", "dns.nope"]}`)
	const (
		one  = " no result; check it against the IDs in a report run without filters\n"
		many = " no result; check them against the IDs in a report run without filters\n"
	)
	tests := []struct {
		name  string
		flags []string
		want  string
	}{
		{"every entry matches", []string{"--ids", "dns.axfr,web.hsts"}, ""},
		{"each unknown entry named once", []string{"--ids", "dns.nope,dns.axfr,dns.nope,web.hsst"},
			`bedrock: --ids entries "dns.nope", "web.hsst" match` + many},
		{"an entry --severity hides still matches",
			[]string{"--severity", "fail", "--ids", "dns.aaaa.apex"}, ""},
		{"an entry in a category --only skips matches nothing",
			[]string{"--only", "DNS", "--ids", "web.hsts"},
			`bedrock: --ids entry "web.hsts" matches` + one},
		{"entries from the config file", []string{"--config", config},
			`bedrock: config "ids" entry "dns.nope" matches` + one},
		{"the flag wins over the config file", []string{"--config", config, "--ids", "web.hsst"},
			`bedrock: --ids entry "web.hsst" matches` + one},
		{"control bytes stay inert", []string{"--ids", "x\x1b[2J\u202e"},
			`bedrock: --ids entry "x\x1b[2J\u202e" matches` + one},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, stderr := runOn(t, pipe, pipe, nil, scanArgs(spec, tt.flags...)...)
			if stderr != tt.want {
				t.Errorf("stderr = %q\nwant     %q", stderr, tt.want)
			}
		})
	}
}

// interruptLine is the progress line the first cancellation prints, after a
// newline that moves past the ^C a terminal echoes. It captures how many
// checks were done, and of how many.
var interruptLine = regexp.MustCompile(
	`\n\nbedrock: interrupted at 0s: (\d+) of (\d+) checks done; the report is partial\n`)

// interruptedVerdict is how the verdict of a scan interrupted with unfinished
// checks still running begins.
func interruptedVerdict(unfinished int) string {
	switch {
	case unfinished == 1:
		return "INCOMPLETE. Scan interrupted; 1 check did not finish. "
	case unfinished > 1:
		return fmt.Sprintf("INCOMPLETE. Scan interrupted; %d checks did not finish. ", unfinished)
	}
	return "INCOMPLETE. Scan interrupted; results are partial. "
}

// interruptAtFirstQuery starts a fake resolver that cancels the returned
// context at its first query, as Ctrl-C does mid-scan, and returns that
// context and the resolver's spec.
func interruptAtFirstQuery(t *testing.T) (context.Context, string) {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx, serveDNS(t, &fakeDNSHandler{onQuery: cancel})
}

// unfinishedAtInterrupt reads the progress line an interrupt prints on
// stderr and returns how many checks it says were not done.
func unfinishedAtInterrupt(t *testing.T, stderr string) int {
	t.Helper()
	m := interruptLine.FindStringSubmatch(stderr)
	if m == nil {
		t.Fatalf("stderr lacks the interrupt line:\n%s", stderr)
	}
	done, errDone := strconv.Atoi(m[1])
	total, errTotal := strconv.Atoi(m[2])
	if err := errors.Join(errDone, errTotal); err != nil {
		t.Fatalf("parse the interrupt line: %v", err)
	}
	return total - done
}

// TestRunInterruptedScan cancels the scan at the resolver's first query, as
// Ctrl-C does mid-scan. stderr says when, and the verdict counts the checks
// that had not finished then; the exit code keeps its meaning: 1 when the
// partial report has a FAIL. With stdout a file, stderr also lists them.
func TestRunInterruptedScan(t *testing.T) {
	for _, out := range []stream{terminal, regularFile} {
		t.Run(out.String(), func(t *testing.T) {
			ctx, spec := interruptAtFirstQuery(t)
			stdout, stderr := &fakeStream{kind: out}, &fakeStream{kind: terminal}
			code := run(ctx, scanArgs(spec), stdout, stderr, fakeSystem(noColor))
			unfinished := unfinishedAtInterrupt(t, stderr.String())
			verdictOn, prefix := stdout.String(), "Result: "
			if out == regularFile {
				verdictOn, prefix = stderr.String(), "bedrock: test.invalid: "
				assertExitCodeOfJSON(t, stdout.Bytes(), code)
			}
			verdict, want := lineStarting(verdictOn, prefix), prefix+interruptedVerdict(unfinished)
			if !strings.HasPrefix(verdict, want) ||
				!strings.HasSuffix(verdict, fmt.Sprintf(" Exit code %d.", code)) {
				t.Errorf("verdict %q, exit code %d; want %q... naming that code",
					verdict, code, want)
			}
			listed := lineStarting(stderr.String(), unfinishedPrefix) != ""
			if want := out == regularFile && unfinished > 0; listed != want {
				t.Errorf("stderr lists the unfinished checks = %v, want %v:\n%s",
					listed, want, stderr.String())
			}
		})
	}
}

// TestRunInterruptedScanSaysSoWithoutProgress interrupts scans where stderr
// gets no progress, as under CI or with stdout a pipe. The JSON has no field
// for an interrupt and the exit code keeps its meaning, so stderr gets the
// INCOMPLETE verdict, as one line.
func TestRunInterruptedScanSaysSoWithoutProgress(t *testing.T) {
	tests := []gateCase{
		{stdout: pipe, stderr: terminal},
		{stdout: pipe, stderr: pipe},
		{stdout: regularFile, stderr: pipe},
		{stdout: regularFile, stderr: terminal, env: map[string]string{"CI": "1"}},
		{stdout: terminal, stderr: pipe},
	}
	for _, gc := range tests {
		t.Run(gc.String(), func(t *testing.T) {
			ctx, spec := interruptAtFirstQuery(t)
			stdout, stderr := &fakeStream{kind: gc.stdout}, &fakeStream{kind: gc.stderr}
			code := run(ctx, scanArgs(spec), stdout, stderr, fakeSystem(gc.env))
			const prefix = "bedrock: test.invalid: INCOMPLETE. Scan interrupted; "
			got := stderr.String()
			if strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, prefix) ||
				!strings.HasSuffix(got, fmt.Sprintf(" Exit code %d.\n", code)) {
				t.Errorf("stderr = %q\nwant one line %q... naming exit code %d", got, prefix, code)
			}
		})
	}
}

// TestRunInterruptedScanSkipsTheIDsWarning checks that an interrupted scan
// does not warn about --ids entries: a check cut short can leave even a
// valid ID without a result.
func TestRunInterruptedScanSkipsTheIDsWarning(t *testing.T) {
	ctx, spec := interruptAtFirstQuery(t)
	stderr := &fakeStream{kind: pipe}
	run(ctx, scanArgs(spec, "--ids", "dns.nope"), &fakeStream{kind: pipe}, stderr, fakeSystem(nil))
	got := stderr.String()
	if !strings.HasPrefix(got, "bedrock: test.invalid: INCOMPLETE.") ||
		strings.Contains(got, "no result") {
		t.Errorf("stderr = %q, want the INCOMPLETE verdict and no --ids warning", got)
	}
}

// unfinishedListed returns the check IDs a terminal report lists as not
// finished when interrupted.
func unfinishedListed(rep string) []string {
	_, section, ok := strings.Cut(rep, "\nChecks not finished when interrupted (")
	if !ok {
		return nil
	}
	var ids []string
	for _, line := range strings.Split(section, "\n")[1:] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Results from these checks") {
			break
		}
		for id := range strings.SplitSeq(line, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// TestRunTracksOnlyTheChecksItRuns interrupts a scan run with --only DNS,
// which runs only the DNS checks. Progress counts only those, and the report
// lists, and the verdict counts, every one of them that did not finish.
func TestRunTracksOnlyTheChecksItRuns(t *testing.T) {
	category := map[string]string{}
	dnsChecks := 0
	for _, c := range registry.All() {
		category[c.ID()] = c.Category()
		if c.Category() == "DNS" {
			dnsChecks++
		}
	}
	ctx, spec := interruptAtFirstQuery(t)
	stdout, stderr := &fakeStream{kind: terminal}, &fakeStream{kind: terminal}
	run(ctx, scanArgs(spec, "--only", "DNS"), stdout, stderr, fakeSystem(noColor))
	start := fmt.Sprintf("bedrock: scanning test.invalid: %d checks,", dnsChecks)
	if !strings.HasPrefix(stderr.String(), start) {
		t.Errorf("stderr does not start %q:\n%s", start, stderr.String())
	}
	unfinished := unfinishedAtInterrupt(t, stderr.String())
	listed := unfinishedListed(stdout.String())
	if len(listed) != unfinished {
		t.Errorf("listed %d of %d unfinished checks, want them all", len(listed), unfinished)
	}
	for _, id := range listed {
		if category[id] != "DNS" {
			t.Errorf("lists %s, a %q check, under --only DNS", id, category[id])
		}
	}
	want := "Result: " + interruptedVerdict(len(listed))
	if got := lineStarting(stdout.String(), "Result: "); !strings.HasPrefix(got, want) {
		t.Errorf("verdict %q, want %q...", got, want)
	}
}

// cancellingClock is a progress clock that stands still, never fires and
// calls cancel at its nth reading.
type cancellingClock struct {
	frozenClock
	n      int64
	reads  atomic.Int64
	cancel context.CancelFunc
}

func (c *cancellingClock) Now() time.Time {
	if c.reads.Add(1) == c.n {
		c.cancel()
	}
	return c.frozenClock.Now()
}

// TestRunCancelAfterTheLastCheckIsNoInterrupt cancels the scan after every
// check has finished but before the scan stops watching for a cancel. The
// report is complete, so neither it nor stderr may say otherwise.
func TestRunCancelAfterTheLastCheckIsNoInterrupt(t *testing.T) {
	spec, _ := startScanFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sys := fakeSystem(noColor)
	// Without progress the scan reads the clock twice: before the checks
	// start and after they have all returned.
	sys.clock = &cancellingClock{n: 2, cancel: cancel}
	stdout, stderr := &fakeStream{kind: terminal}, &fakeStream{kind: pipe}
	code := run(ctx, scanArgs(spec), stdout, stderr, sys)
	const want = "Result: FAIL. 8 FAIL (DNS 2, Email 6), 4 WARN. Exit code 1."
	if got := lastLine(stdout.String()); code != 1 || got != want || stderr.Len() != 0 {
		t.Errorf("exit code %d, last line %q, stderr %q\nwant 1, %q and nothing",
			code, got, stderr.String(), want)
	}
	if ctx.Err() == nil {
		t.Error("the clock never cancelled the scan")
	}
}

// timerClock is a progress clock that stands still and hands every timer it
// sets to the test, which fires it at will.
type timerClock struct {
	frozenClock
	timers chan chan time.Time
}

func (c timerClock) After(time.Duration) <-chan time.Time {
	timer := make(chan time.Time, 1)
	c.timers <- timer
	return timer
}

// lateWriter is a terminal stream that sends to late every write made after
// close.
type lateWriter struct {
	mu     sync.Mutex
	closed bool
	late   chan string
}

func (*lateWriter) streamKind() stream { return terminal }

func (w *lateWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		w.late <- string(p)
	}
	return len(p), nil
}

func (w *lateWriter) close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

// TestRunWritesNoProgressAfterItReturns checks that run ends the heartbeats
// before it returns: a heartbeat timer that fires afterwards writes nothing
// to stderr, where it would land in the middle of whatever comes next.
func TestRunWritesNoProgressAfterItReturns(t *testing.T) {
	spec, _ := startScanFixture(t)
	clock := timerClock{timers: make(chan chan time.Time, 16)}
	sys := fakeSystem(noColor)
	sys.clock = clock
	stderr := &lateWriter{late: make(chan string, 16)}
	run(context.Background(), scanArgs(spec), &fakeStream{kind: terminal}, stderr, sys)
	stderr.close()
	select {
	case timer := <-clock.timers:
		timer <- time.Unix(0, 0)
	case <-time.After(5 * time.Second):
		t.Fatal("no heartbeat timer was set, so progress never started")
	}
	select {
	case line := <-stderr.late:
		t.Errorf("stderr got %q after run returned", line)
	case <-time.After(100 * time.Millisecond):
	}
}

// assertExitCodeOfJSON checks that code is the exit code an uninterrupted
// run would give the JSON report out: 1 if it has a FAIL, otherwise 0.
func assertExitCodeOfJSON(t *testing.T, out []byte, code int) {
	t.Helper()
	var rep report.Report
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("stdout is not one JSON document: %v", err)
	}
	if want := exitCode(rep, nil, false); code != want {
		t.Errorf("exit code = %d, want %d for the partial report", code, want)
	}
}

func TestListLines(t *testing.T) {
	ids := func(n int) []string {
		var out []string
		for i := 1; i <= n; i++ {
			out = append(out, fmt.Sprintf("web.check%02d", i))
		}
		return out
	}
	const (
		first  = "bedrock: failing: web.check01, web.check02, web.check03, web.check04,"
		second = "                  web.check05, web.check06, web.check07, web.check08,"
	)
	tests := []struct {
		name   string
		prefix string
		ids    []string
		want   []string
	}{
		{"none", failingPrefix, nil, nil},
		{"one", failingPrefix, []string{"web.hsts"}, []string{"bedrock: failing: web.hsts"}},
		{"ten, wrapped under the first", failingPrefix, ids(10),
			[]string{first, second, "                  web.check09, web.check10"}},
		{"eleven: ten, then the count", failingPrefix, ids(11),
			[]string{first, second, "                  web.check09, web.check10, and 1 more"}},
		{"twenty-five", failingPrefix, ids(25),
			[]string{first, second, "                  web.check09, web.check10, and 15 more"}},
		{"indented to a longer prefix", unfinishedPrefix, ids(5), []string{
			"bedrock: unfinished: web.check01, web.check02, web.check03, web.check04,",
			"                     web.check05"}},
		{"display-safe", failingPrefix, []string{"x\x1b[2J\u202ey"},
			[]string{"bedrock: failing: x\uFFFD[2J\\u202Ey"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			given := slices.Clone(tt.ids)
			if got := listLines(tt.prefix, tt.ids); !slices.Equal(got, tt.want) {
				t.Errorf("listLines =\n%q\nwant\n%q", got, tt.want)
			}
			if !slices.Equal(tt.ids, given) {
				t.Errorf("listLines changed its argument to %q", tt.ids)
			}
		})
	}
}

func TestRunHelpGoesToStdout(t *testing.T) {
	for _, arg := range []string{"-h", "-help", "--help"} {
		t.Run(arg, func(t *testing.T) {
			code, stdout, stderr := runOn(t, pipe, pipe, nil, arg)
			if code != 0 || stderr != "" {
				t.Errorf("exit code = %d, stderr = %q; want 0 and nothing", code, stderr)
			}
			if !strings.HasPrefix(stdout, usage) || !strings.Contains(stdout, "-regression-only") {
				t.Errorf("stdout lacks the usage text and flag defaults:\n%s", stdout)
			}
		})
	}
}

// columns is the width of line on a terminal with a tab stop every eight
// columns, taking each rune as one column.
func columns(line string) int {
	n := 0
	for _, r := range line {
		if r == '\t' {
			n += 8 - n%8
		} else {
			n++
		}
	}
	return n
}

// TestHelpText checks that the help, flag defaults included, fits 80
// columns and covers what it must: every category, the stdout rule and the
// exit codes.
func TestHelpText(t *testing.T) {
	_, stdout, _ := runOn(t, pipe, pipe, nil, "--help")
	for i, line := range strings.Split(stdout, "\n") {
		if n := columns(line); n > 80 {
			t.Errorf("help line %d is %d columns, want at most 80: %q", i+1, n, line)
		}
	}
	for _, want := range []string{"DNS, DNSSEC, Email (including BIMI) and WWW", "--subdomains",
		"DNS, DNSSEC, Email, WWW, Subdomain", "A pipe, a file or --json gets the JSON report",
		"\n  0  ", "\n  1  ", "\n  2  "} {
		if !strings.Contains(stdout, want) {
			t.Errorf("help text lacks %q", want)
		}
	}
}

func TestRunVersionGoesToStdout(t *testing.T) {
	code, stdout, stderr := runOn(t, pipe, pipe, nil, "--version")
	if code != 0 || stderr != "" || stdout != version.String()+"\n" {
		t.Errorf("exit code = %d, stdout = %q, stderr = %q; want 0, the version line, nothing",
			code, stdout, stderr)
	}
}

// helpHint ends a usage error's line.
const helpHint = "; run 'bedrock --help' for usage\n"

func TestRunUsageErrorsPrintOneLine(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown flag", []string{"--bogus", "example.org"},
			"flag provided but not defined: -bogus"},
		{"bad flag value", []string{"--timeout", "soon", "example.org"},
			`invalid value "soon" for flag -timeout`},
		{"missing domain", nil, "bedrock: missing domain;"},
		{"two domains", []string{"a.example", "b.example"},
			`expected one domain, got 2: ["a.example" "b.example"];`},
		{"flag after domain", []string{"example.org", "--no-active"},
			`got 2: ["example.org" "--no-active"] (flags go before the domain)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runOn(t, pipe, pipe, nil, tt.args...)
			if code != 2 || stdout != "" {
				t.Errorf("exit code = %d, stdout = %q; want 2 and nothing", code, stdout)
			}
			assertOneLine(t, stderr, tt.want)
			if !strings.HasSuffix(stderr, helpHint) {
				t.Errorf("stderr = %q, want it to point at --help", stderr)
			}
		})
	}
}

// TestRunRejectsBadInputBeforeScanning checks that each input error exits 2
// with one line before any check runs: the fake resolver sees no query. An
// invalid flag value or domain is a usage error, so its line points at
// --help.
func TestRunRejectsBadInputBeforeScanning(t *testing.T) {
	spec, queries := startScanFixture(t)
	missing := filepath.Join(t.TempDir(), "missing.json")
	badSeverity := writeFile(t, "severity.json", `{"severity": "loud"}`)
	regressionOnly := writeFile(t, "regression.json", `{"regression_only": true}`)
	tests := []struct {
		name string
		args []string
		want string
		help bool
	}{
		{"bad severity", scanArgs(spec, "--severity", "sever"), `invalid severity "sever"`, true},
		{"missing baseline", scanArgs(spec, "--baseline", missing), "open baseline " + missing,
			false},
		{"missing config", scanArgs(spec, "--config", missing), "read config " + missing, false},
		{"bad config severity", scanArgs(spec, "--config", badSeverity), `invalid severity "loud"`,
			true},
		{"every invalid flag value", scanArgs(spec, "--only", "Emial", "--timeout", "0"),
			`unknown category "Emial" (want one of: DNS, DNSSEC, Email, Subdomain, WWW); ` +
				"invalid --timeout 0s", true},
		{"--regression-only without --baseline", scanArgs(spec, "--regression-only"),
			"--regression-only requires --baseline", true},
		{"regression_only in the config without a baseline",
			scanArgs(spec, "--config", regressionOnly), "--regression-only requires --baseline", true},
		{"invalid domain", []string{"--resolver", spec, "exa mple.org"},
			`invalid domain "exa mple.org": idna: disallowed rune U+0020`, true},
		{"domain with a control byte", []string{"--resolver", spec, "x\x1by.org"},
			`invalid domain "x\x1by.org": `, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runOn(t, terminal, terminal, nil, tt.args...)
			if code != 2 || stdout != "" {
				t.Errorf("exit code = %d, stdout = %q; want 2 and nothing", code, stdout)
			}
			assertOneLine(t, stderr, tt.want)
			if got := strings.HasSuffix(stderr, helpHint); got != tt.help {
				t.Errorf("stderr = %q points at --help: %v, want %v", stderr, got, tt.help)
			}
			if n := queries.Load(); n != 0 {
				t.Fatalf("the fake resolver answered %d queries: checks ran before the error", n)
			}
		})
	}
}

// TestRunRejectsPrivateResolversBeforeScanning checks that a rejected
// --resolvers entry stops bedrock before any check runs, with an error that
// leaves out the other entries: a DoH URL can hold a password or token.
func TestRunRejectsPrivateResolversBeforeScanning(t *testing.T) {
	spec, queries := startScanFixture(t)
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
	//nolint:gosec // G101: fake credentials, which stderr must not repeat.
	doh := "https://alice:s3cr3t@doh.example/dns-query?token=abc123"
	args := scanArgs(spec, "--resolvers", doh+","+spec)
	code, stdout, stderr := runOn(t, pipe, pipe, nil, args...)
	if code != 2 || stdout != "" {
		t.Errorf("exit code = %d, stdout = %q; want 2 and nothing", code, stdout)
	}
	assertOneLine(t, stderr, "resolver 127.0.0.1 is loopback")
	if strings.Contains(stderr, "s3cr3t") || strings.Contains(stderr, "abc123") {
		t.Errorf("stderr = %q repeats another entry's credentials", stderr)
	}
	if n := queries.Load(); n != 0 {
		t.Errorf("the fake resolver answered %d queries: checks ran before the error", n)
	}
}

// TestRunScansOnPastABadConfigTimeout checks that a config timeout that does
// not parse gets a warning and the default timeout, rather than a new exit
// code: bedrock has always scanned on in that case.
func TestRunScansOnPastABadConfigTimeout(t *testing.T) {
	spec, queries := startScanFixture(t)
	config := writeFile(t, "timeout.json", `{"timeout": "30"}`)
	args := []string{"--no-active", "--resolver", spec, "--config", config, "test.invalid"}
	code, stdout, stderr := runOn(t, pipe, pipe, nil, args...)
	want := "bedrock: config " + config + `: parse timeout "30": time: missing unit in ` +
		`duration "30"; scanning with the default timeout 5s` + "\n"
	if code != 1 || stderr != want {
		t.Errorf("exit code = %d, stderr = %q\nwant 1 and %q", code, stderr, want)
	}
	if queries.Load() == 0 || !json.Valid([]byte(stdout)) {
		t.Error("the scan did not run, or stdout is not the JSON report")
	}
}

// isControlOrInvisible reports whether r could move the cursor, end a line,
// or hide or reorder text on a terminal.
func isControlOrInvisible(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// TestRunErrorsAreDisplaySafe checks that an error quoting a flag or a file
// name reaches stderr as one line with no control, format or separator
// character: no escape sequence, and no forged second line.
func TestRunErrorsAreDisplaySafe(t *testing.T) {
	spec, _ := startScanFixture(t)
	tests := []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"-\x1b]0;pwned\x07\x1b[2Jx", "example.org"}},
		{"baseline path", scanArgs(spec, "--baseline", "/nonexistent/\x1b[2Jb\nZ.json")},
		{"config path", scanArgs(spec, "--config", "/nonexistent/\u202e\tc.json")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runOn(t, pipe, terminal, nil, tt.args...)
			line, ok := strings.CutSuffix(stderr, "\n")
			if code != 2 || !ok || strings.IndexFunc(line, isControlOrInvisible) >= 0 {
				t.Errorf("exit code %d, stderr %q; want 2 and one display-safe line", code, stderr)
			}
		})
	}
}

// TestRunJSONSummaryMatchesFilteredResults checks that the JSON summary
// counts the results the filters left, not the whole scan.
func TestRunJSONSummaryMatchesFilteredResults(t *testing.T) {
	spec, _ := startScanFixture(t)
	all := len(goldenReport(t).Results)
	for _, flags := range [][]string{{"--only", "DNS"}, {"--ids", "dns.axfr,web.hsts"}} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			_, stdout, _ := runOn(t, pipe, pipe, nil, scanArgs(spec, flags...)...)
			var rep report.Report
			if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
				t.Fatalf("decode stdout: %v", err)
			}
			if n := len(rep.Results); n == 0 || n == all {
				t.Fatalf("the filter kept %d of %d results, want some but not all", n, all)
			}
			if want := report.Summarize(rep.Results); !reflect.DeepEqual(rep.Summary, want) {
				t.Errorf("summary = %+v, want %+v", rep.Summary, want)
			}
		})
	}
}

// TestRunHeaderNamesTheResolvers checks that the terminal report's header
// names the resolvers the scan used: --resolvers, which the scan prefers,
// over --resolver.
func TestRunHeaderNamesTheResolvers(t *testing.T) {
	spec, _ := startScanFixture(t)
	tests := []struct {
		name  string
		flags []string
		want  string
	}{
		{"--resolver", nil, ", resolver " + spec + ")"},
		{"--resolvers", []string{"--resolvers", spec + "," + spec},
			", resolvers " + spec + "," + spec + ")"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stdout, _ := runOn(t, terminal, pipe, noColor, scanArgs(spec, tt.flags...)...)
			header := lineStarting(stdout, "bedrock report for ")
			if !strings.HasSuffix(header, tt.want) {
				t.Errorf("header %q, want it to end %q", header, tt.want)
			}
		})
	}
}

// TestResolverLabels checks that the report names the resolvers without the
// parts of a URL spec that can carry a password, token or account identifier.
func TestResolverLabels(t *testing.T) {
	tests := []struct {
		name      string
		resolver  string
		resolvers string
		want      []string
	}{
		{"system resolver", "", "", nil},
		{"preset", "cloudflare", "", []string{"cloudflare"}},
		{"host and port", "127.0.0.1:53", "", []string{"127.0.0.1:53"}},
		{"IPv6 host and port", "[::1]:53", "", []string{"[::1]:53"}},
		{"DoT with user information", "tls://user:pw@dot.example:853", "",
			[]string{"tls://dot.example:853"}},
		{"DoH with a password, path, token and fragment",
			"https://alice:s3cr3t@doh.example/dns-query?token=abc123#frag", "",
			[]string{"https://doh.example"}},
		{"URL that does not parse", "https://alice:s3cr3t%zz@doh.example/", "",
			[]string{"https://..."}},
		{"--resolvers wins, each entry redacted", "cloudflare",
			"127.0.0.1:53, https://u:p@doh.example/q?k=v",
			[]string{"127.0.0.1:53", "https://doh.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &options{resolver: tt.resolver, resolversCSV: tt.resolvers}
			if got := resolverLabels(o); !slices.Equal(got, tt.want) {
				t.Errorf("resolverLabels = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestRunFlagOverridesConfig checks that a flag set on the command line wins
// over the config file, even over a config value that would be an error.
func TestRunFlagOverridesConfig(t *testing.T) {
	spec, _ := startScanFixture(t)
	config := writeFile(t, "config.json", `{"severity": "loud"}`)
	args := scanArgs(spec, "--config", config, "--severity", "fail")
	code, stdout, stderr := runOn(t, pipe, pipe, nil, args...)
	if code != 1 || stderr != "" {
		t.Fatalf("exit code = %d, stderr = %q; want 1 and nothing", code, stderr)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decode stdout: %v", err)
	}
	for _, r := range rep.Results {
		if r.Status != report.Fail && r.Status != report.NotApplicable {
			t.Errorf("--severity fail kept %s %s", r.Status, r.ID)
		}
	}
}

// failingWriter is a stream of the given kind on which every write fails.
type failingWriter struct{ kind stream }

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }
func (w failingWriter) streamKind() stream      { return w.kind }

func TestRunReportsWriteErrors(t *testing.T) {
	spec, _ := startScanFixture(t)
	tests := []struct {
		stdout stream
		want   string
	}{
		{pipe, "bedrock: write JSON report for test.invalid: disk full"},
		{terminal, "bedrock: write terminal report for test.invalid: disk full"},
	}
	for _, tt := range tests {
		t.Run(tt.stdout.String(), func(t *testing.T) {
			var stderr bytes.Buffer
			code := run(context.Background(), scanArgs(spec), failingWriter{kind: tt.stdout},
				&stderr, fakeSystem(nil))
			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			assertOneLine(t, stderr.String(), tt.want)
		})
	}
}

func TestMergeConfig(t *testing.T) {
	full := &cli.Config{
		NoColor: true, NoActive: true, Resolver: "cfg-resolver", Resolvers: []string{"r1", "r2"},
		Timeout: "7s", Only: []string{"DNS", "WWW"}, Exclude: []string{"Email"},
		Severity: "warn", IDs: []string{"a", "b"}, Subdomains: true, EnableRBL: true,
		EnableCT: true, Baseline: "cfg.json", RegressionOnly: true,
	}
	fromConfig := options{
		noColor: true, noActive: true, resolver: "cfg-resolver", resolversCSV: "r1,r2",
		timeout: 7 * time.Second, onlyCSV: "DNS,WWW", excludeCSV: "Email", severity: "warn",
		idsCSV: "a,b", subdomains: true, enableRBL: true, enableCT: true,
		baselinePath: "cfg.json", regressionOnly: true, domain: "example.org",
	}
	allFlags := []string{
		"--no-color=false", "--no-active=false", "--resolver", "flag-resolver",
		"--resolvers", "f1", "--timeout", "3s", "--only", "Email", "--exclude", "DNS",
		"--severity", "fail", "--ids", "c", "--subdomains=false", "--enable-rbl=false",
		"--enable-ct=false", "--baseline", "flag.json", "--regression-only=false", "example.org",
	}
	oneResolverFlag := fromConfig
	oneResolverFlag.resolver, oneResolverFlag.resolversCSV = "", "f1"
	fromFlags := options{
		resolver: "flag-resolver", resolversCSV: "f1", timeout: 3 * time.Second,
		onlyCSV: "Email", excludeCSV: "DNS", severity: "fail", idsCSV: "c",
		baselinePath: "flag.json", domain: "example.org",
	}
	tests := []struct {
		name string
		cfg  *cli.Config
		args []string
		want options
	}{
		{"empty config keeps defaults", &cli.Config{}, []string{"example.org"},
			options{timeout: 5 * time.Second, domain: "example.org"}},
		{"config fills unset flags", full, []string{"example.org"}, fromConfig},
		{"one resolver flag overrides both config keys", full,
			[]string{"--resolvers", "f1", "example.org"}, oneResolverFlag},
		{"flags win over config", full, allFlags, fromFlags},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, o, err := parseFlags(tt.args)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.args, err)
			}
			if err := mergeConfig(tt.cfg, fs, o); err != nil {
				t.Fatalf("merge: %v", err)
			}
			if *o != tt.want {
				t.Errorf("options = %+v\nwant      %+v", *o, tt.want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	fail := report.Result{ID: "x.fail", Status: report.Fail}
	others := []report.Result{
		{ID: "x.pass", Status: report.Pass}, {ID: "x.warn", Status: report.Warn},
		{ID: "x.info", Status: report.Info}, {ID: "x.na", Status: report.NotApplicable},
	}
	failing := report.Report{Results: append([]report.Result{fail}, others...)}
	clean := report.Report{Results: others}
	tests := []struct {
		name           string
		rep            report.Report
		regressions    []report.Result
		regressionOnly bool
		want           int
	}{
		{"a FAIL fails the run", failing, nil, false, 1},
		{"WARN, INFO and N/A do not", clean, nil, false, 0},
		{"a regression is also a FAIL", failing, []report.Result{fail}, false, 1},
		{"regression-only ignores old FAILs", failing, nil, true, 0},
		{"regression-only fails on a regression", failing, []report.Result{fail}, true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.rep, tt.regressions, tt.regressionOnly); got != tt.want {
				t.Errorf("exitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestOSSystemTellsFilesFromTerminals checks the real process boundary on
// streams that are not terminals, so none gets colour either.
func TestOSSystemTellsFilesFromTerminals(t *testing.T) {
	dir := t.TempDir()
	file := createFile(t, filepath.Join(dir, "out"))
	closed := createFile(t, filepath.Join(dir, "closed"))
	if err := closed.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	tests := []struct {
		name    string
		w       io.Writer
		regular bool
	}{
		{name: "regular file", w: file, regular: true},
		{name: "pipe", w: w},
		{name: "closed file", w: closed},
		{name: "buffer", w: &bytes.Buffer{}},
	}
	sys := osSystem()
	noEnv := func(string) string { return "" }
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if sys.isTerminal(tt.w) || sys.color(tt.w, noEnv) {
				t.Error("isTerminal or color = true, want false")
			}
			if got := sys.isRegular(tt.w); got != tt.regular {
				t.Errorf("isRegular = %v, want %v", got, tt.regular)
			}
		})
	}
}
