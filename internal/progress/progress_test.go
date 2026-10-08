package progress

import (
	"bytes"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// testTimeout bounds every wait on the heartbeat goroutine, so a broken
// implementation fails instead of hanging; passing tests never reach it.
const testTimeout = 5 * time.Second

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// scanIDs is unsorted on purpose: heartbeats and Interrupt sort the IDs.
var scanIDs = []string{"web.hsts", "dns.soa", "email.spf", "dns.mx"}

var scanInfo = Info{Target: "example.org", Active: true, Timeout: 5 * time.Second}

const startLine = "bedrock: scanning example.org: 4 checks, active probes, timeout 5s\n"

// fakeClock is a manual Clock: After registers a timer that fires once
// advance moves the time to or past its deadline.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []fakeTimer
	arms   int           // After calls so far
	armed  chan struct{} // nudged, without blocking, by every After call

	// lastAfter is written after mu is released, on purpose: reading it
	// after Stop is free of data races only if Stop waited for the
	// heartbeat goroutine, so the race detector catches a goroutine that
	// outlives Stop.
	lastAfter time.Duration
}

type fakeTimer struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: t0, armed: make(chan struct{}, 1)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	ch := make(chan time.Time, 1)
	c.timers = append(c.timers, fakeTimer{at: c.now.Add(d), ch: ch})
	c.arms++
	select {
	case c.armed <- struct{}{}:
	default:
	}
	c.mu.Unlock()
	c.lastAfter = d
	return ch
}

// advance moves the time forward by d, fires every timer now due and
// reports how many fired.
func (c *fakeClock) advance(d time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	pending := c.timers[:0]
	for _, tm := range c.timers {
		if tm.at.After(c.now) {
			pending = append(pending, tm)
			continue
		}
		tm.ch <- c.now
	}
	fired := len(c.timers) - len(pending)
	c.timers = pending
	return fired
}

func (c *fakeClock) armCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.arms
}

// waitArms blocks until After has been called at least n times.
func (c *fakeClock) waitArms(t *testing.T, n int) {
	t.Helper()
	timeout := time.After(testTimeout)
	for c.armCount() < n {
		select {
		case <-c.armed:
		case <-timeout:
			t.Fatalf("heartbeat goroutine stuck: %d of %d After calls", c.armCount(), n)
		}
	}
}

// harness runs a Progress on a fake clock. Its output buffer is not
// synchronised: it is read only while the heartbeat goroutine is idle (after
// start or advanceTo) or gone (after Stop), and the race detector checks
// that the Progress makes those reads safe.
type harness struct {
	t     *testing.T
	clock *fakeClock
	out   bytes.Buffer
	p     *Progress
}

func newHarness(t *testing.T, checkIDs ...string) *harness {
	t.Helper()
	h := &harness{t: t, clock: newFakeClock()}
	h.p = New(&h.out, checkIDs, h.clock)
	t.Cleanup(h.p.Stop)
	return h
}

// start calls Start and waits until the heartbeat goroutine waits on the
// clock, so the first advanceTo cannot overtake it.
func (h *harness) start(info Info) {
	h.t.Helper()
	h.p.Start(info)
	h.clock.waitArms(h.t, 1)
}

// advanceTo moves the clock to at after Start. When that fires the
// heartbeat timer, it waits until the goroutine has handled it and waits on
// the clock again, so the output is settled when advanceTo returns.
func (h *harness) advanceTo(at time.Duration) {
	h.t.Helper()
	d := t0.Add(at).Sub(h.clock.Now())
	if d < 0 {
		h.t.Fatalf("advanceTo(%v): the clock is already past it", at)
	}
	arms := h.clock.armCount()
	if h.clock.advance(d) > 0 {
		h.clock.waitArms(h.t, arms+1)
	}
}

// take returns the output written since the previous take.
func (h *harness) take() string {
	s := h.out.String()
	h.out.Reset()
	return s
}

// progressGoroutines returns the stacks of goroutines that are inside, or
// were started by, a *Progress method.
func progressGoroutines() []string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var found []string
	for g := range strings.SplitSeq(string(buf), "\n\n") {
		if strings.Contains(g, "internal/progress.(*Progress).") {
			found = append(found, g)
		}
	}
	return found
}

// waitNoProgressGoroutines fails the test unless every heartbeat goroutine
// is gone. One that has just signalled its exit may still be unwinding, so
// the check yields and retries until testTimeout.
func waitNoProgressGoroutines(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		leaked := progressGoroutines()
		if len(leaked) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a goroutine outlived Stop:\n%s", strings.Join(leaked, "\n\n"))
		}
		runtime.Gosched()
	}
}

func TestStartPrintsScanLine(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		{name: "active probes", info: scanInfo, want: startLine},
		{
			name: "passive only",
			info: Info{Target: "ietf.org", Timeout: 1500 * time.Millisecond},
			want: "bedrock: scanning ietf.org: 4 checks, passive only, timeout 1.5s\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, scanIDs...)
			h.p.Start(tt.info)
			if got := h.take(); got != tt.want {
				t.Errorf("output right after Start = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHeartbeatsAt3sThenEvery10s(t *testing.T) {
	h := newHarness(t, scanIDs...)
	h.start(scanInfo)
	h.take()
	const beat = " 0 of 4 checks done; waiting on dns.mx, dns.soa and 2 more\n"
	steps := []struct {
		at   time.Duration // since Start
		want string        // written since the previous step
	}{
		{at: 2999 * time.Millisecond, want: ""},
		{at: 3 * time.Second, want: "bedrock: 3s:" + beat},
		{at: 12999 * time.Millisecond, want: ""},
		{at: 13 * time.Second, want: "bedrock: 13s:" + beat},
		{at: 23 * time.Second, want: "bedrock: 23s:" + beat},
		{at: 33 * time.Second, want: "bedrock: 33s:" + beat},
	}
	for _, s := range steps {
		h.advanceTo(s.at)
		if got := h.take(); got != s.want {
			t.Fatalf("at %v got %q, want %q", s.at, got, s.want)
		}
	}
}

func TestHeartbeatNamesAtMostTwoUnfinishedChecks(t *testing.T) {
	tests := []struct {
		name string
		done []string
		want string // the heartbeat after "bedrock: 3s: "
	}{
		{
			name: "four unfinished",
			want: "0 of 4 checks done; waiting on dns.mx, dns.soa and 2 more",
		},
		{
			name: "three unfinished",
			done: []string{"dns.mx"},
			want: "1 of 4 checks done; waiting on dns.soa, email.spf and 1 more",
		},
		{
			name: "two unfinished",
			done: []string{"dns.mx", "web.hsts"},
			want: "2 of 4 checks done; waiting on dns.soa, email.spf",
		},
		{
			name: "one unfinished",
			done: []string{"dns.mx", "dns.soa", "email.spf"},
			want: "3 of 4 checks done; waiting on web.hsts",
		},
		{
			name: "all done",
			done: scanIDs,
			want: "4 of 4 checks done",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, scanIDs...)
			h.start(scanInfo)
			h.take()
			for _, id := range tt.done {
				h.p.Done(id)
			}
			h.advanceTo(3 * time.Second)
			if got, want := h.take(), "bedrock: 3s: "+tt.want+"\n"; got != want {
				t.Errorf("heartbeat = %q, want %q", got, want)
			}
		})
	}
}

func TestInterruptPrintsOnceAndEndsHeartbeats(t *testing.T) {
	h := newHarness(t, scanIDs...)
	h.start(scanInfo)
	h.p.Done("dns.soa")
	h.advanceTo(8 * time.Second)
	h.take()

	got := h.p.Interrupt()
	if want := []string{"dns.mx", "email.spf", "web.hsts"}; !slices.Equal(got, want) {
		t.Errorf("first Interrupt returned %q, want %q", got, want)
	}
	want := "\nbedrock: interrupted at 8s: 1 of 4 checks done; the report is partial\n"
	if out := h.take(); out != want {
		t.Errorf("first Interrupt printed %q, want %q", out, want)
	}

	h.p.Done("email.spf")
	got = h.p.Interrupt()
	if want := []string{"dns.mx", "web.hsts"}; !slices.Equal(got, want) {
		t.Errorf("second Interrupt returned %q, want %q", got, want)
	}
	h.advanceTo(13 * time.Second)
	h.advanceTo(23 * time.Second)
	if out := h.take(); out != "" {
		t.Errorf("printed %q after the first interrupt line, want nothing", out)
	}
}

// An interrupt that arrives after every check finished cut nothing short:
// it prints nothing, though it still ends the heartbeats.
func TestInterruptAfterEveryCheckFinishedPrintsNothing(t *testing.T) {
	h := newHarness(t, scanIDs...)
	h.start(scanInfo)
	h.take()
	for _, id := range scanIDs {
		h.p.Done(id)
	}
	if got := h.p.Interrupt(); len(got) != 0 {
		t.Errorf("Interrupt returned %q, want no unfinished checks", got)
	}
	h.advanceTo(3 * time.Second)
	if out := h.take(); out != "" {
		t.Errorf("printed %q, want nothing", out)
	}
}

func TestInterruptGivesElapsedTimeCompactly(t *testing.T) {
	tests := []struct {
		at   time.Duration
		want string
	}{
		{at: 0, want: "0s"},
		{at: 1499 * time.Millisecond, want: "1s"},
		{at: 1500 * time.Millisecond, want: "2s"},
		{at: 72 * time.Second, want: "1m12s"},
		{at: time.Hour + 2*time.Minute + 3*time.Second, want: "1h2m3s"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			h := newHarness(t, scanIDs...)
			h.start(scanInfo)
			h.advanceTo(tt.at)
			h.take()
			h.p.Interrupt()
			want := "\nbedrock: interrupted at " + tt.want +
				": 0 of 4 checks done; the report is partial\n"
			if got := h.take(); got != want {
				t.Errorf("Interrupt at %v printed %q, want %q", tt.at, got, want)
			}
		})
	}
}

func TestDoneCountsEachListedRunOnce(t *testing.T) {
	tests := []struct {
		name           string
		ids            []string
		done           []string
		wantBeat       string
		wantUnfinished []string
	}{
		{
			name:           "unknown ID",
			ids:            []string{"dns.soa", "web.hsts"},
			done:           []string{"dns.nope"},
			wantBeat:       "0 of 2 checks done; waiting on dns.soa, web.hsts",
			wantUnfinished: []string{"dns.soa", "web.hsts"},
		},
		{
			name:           "repeated ID",
			ids:            []string{"dns.soa", "web.hsts"},
			done:           []string{"dns.soa", "dns.soa", "dns.soa"},
			wantBeat:       "1 of 2 checks done; waiting on web.hsts",
			wantUnfinished: []string{"web.hsts"},
		},
		{
			name:           "ID listed twice, done once",
			ids:            []string{"dns.soa", "dns.soa", "web.hsts"},
			done:           []string{"dns.soa"},
			wantBeat:       "1 of 3 checks done; waiting on dns.soa, web.hsts",
			wantUnfinished: []string{"dns.soa", "web.hsts"},
		},
		{
			name:           "ID listed twice, done three times",
			ids:            []string{"dns.soa", "dns.soa", "web.hsts"},
			done:           []string{"dns.soa", "dns.soa", "dns.soa"},
			wantBeat:       "2 of 3 checks done; waiting on web.hsts",
			wantUnfinished: []string{"web.hsts"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, tt.ids...)
			h.start(scanInfo)
			h.take()
			for _, id := range tt.done {
				h.p.Done(id)
			}
			h.advanceTo(3 * time.Second)
			if got, want := h.take(), "bedrock: 3s: "+tt.wantBeat+"\n"; got != want {
				t.Errorf("heartbeat = %q, want %q", got, want)
			}
			if got := h.p.Interrupt(); !slices.Equal(got, tt.wantUnfinished) {
				t.Errorf("Interrupt returned %q, want %q", got, tt.wantUnfinished)
			}
		})
	}
}

func TestNilWriterTracksSilently(t *testing.T) {
	clock := newFakeClock()
	p := New(nil, scanIDs, clock)
	p.Start(scanInfo)
	p.Done("dns.mx")
	p.Done("web.hsts")
	// Any write to the nil writer would panic, so getting here proves silence.
	if got, want := p.Interrupt(), []string{"dns.soa", "email.spf"}; !slices.Equal(got, want) {
		t.Errorf("Interrupt returned %q, want %q", got, want)
	}
	p.Stop()
	p.Stop()
	if n := clock.armCount(); n != 0 {
		t.Errorf("a silent Progress armed %d heartbeat timers, want none", n)
	}
}

func TestStopBeforeStartIsSafeAndFinal(t *testing.T) {
	h := newHarness(t, scanIDs...)
	h.p.Stop()
	h.p.Stop()
	h.p.Start(scanInfo)
	got, want := h.p.Interrupt(), []string{"dns.mx", "dns.soa", "email.spf", "web.hsts"}
	if !slices.Equal(got, want) {
		t.Errorf("Interrupt returned %q, want %q", got, want)
	}
	if out := h.take(); out != "" {
		t.Errorf("printed %q after Stop, want nothing", out)
	}
	if n := h.clock.armCount(); n != 0 {
		t.Errorf("Start after Stop armed %d heartbeat timers, want none", n)
	}
}

func TestStartTwiceStartsOnce(t *testing.T) {
	h := newHarness(t, scanIDs...)
	h.start(scanInfo)
	h.p.Start(scanInfo)
	h.advanceTo(3 * time.Second)
	want := startLine + "bedrock: 3s: 0 of 4 checks done; waiting on dns.mx, dns.soa and 2 more\n"
	if got := h.take(); got != want {
		t.Errorf("got %q, want one start line and one heartbeat: %q", got, want)
	}
}

func TestStopEndsTheHeartbeatGoroutine(t *testing.T) {
	h := newHarness(t, scanIDs...)
	h.start(scanInfo)
	h.advanceTo(3 * time.Second)
	h.take()

	var wg sync.WaitGroup
	for range 3 {
		wg.Go(h.p.Stop)
	}
	wg.Wait()
	if h.clock.lastAfter != 10*time.Second {
		t.Errorf("the heartbeat goroutine last waited %v, want 10s", h.clock.lastAfter)
	}
	waitNoProgressGoroutines(t)

	h.clock.advance(time.Hour) // fires the timer the goroutine abandoned
	h.p.Interrupt()
	h.p.Stop()
	if out := h.take(); out != "" {
		t.Errorf("printed %q after Stop, want nothing", out)
	}
}

func TestConcurrentDoneCountsEveryCheckOnce(t *testing.T) {
	ids := make([]string, 50)
	for i := range ids {
		ids[i] = fmt.Sprintf("check.%02d", i)
	}
	h := newHarness(t, ids...)
	h.start(scanInfo)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Go(func() {
			h.p.Done(id)
			h.p.Done(id)
			h.p.Done("check.unknown")
		})
	}
	for _, at := range []time.Duration{3 * time.Second, 13 * time.Second, 23 * time.Second} {
		h.advanceTo(at)
	}
	wg.Wait()
	h.advanceTo(33 * time.Second)
	h.p.Stop()

	out := h.take()
	if !strings.HasSuffix(out, "\nbedrock: 33s: 50 of 50 checks done\n") {
		t.Errorf("want a last heartbeat with every check done, got:\n%s", out)
	}
	if counts := doneCounts(t, out); len(counts) != 4 || !slices.IsSorted(counts) {
		t.Errorf("want 4 heartbeats whose done counts never go back, got %v", counts)
	}
	if got := h.p.Interrupt(); len(got) != 0 {
		t.Errorf("Interrupt returned %q, want no unfinished checks", got)
	}
}

// doneCounts returns the done count of every heartbeat line in out.
func doneCounts(t *testing.T, out string) []int {
	t.Helper()
	var counts []int
	for line := range strings.Lines(out) {
		if strings.HasPrefix(line, "bedrock: scanning ") {
			continue
		}
		var secs, done int
		if _, err := fmt.Sscanf(line, "bedrock: %ds: %d of", &secs, &done); err != nil {
			t.Fatalf("unexpected heartbeat %q: %v", line, err)
		}
		counts = append(counts, done)
	}
	return counts
}

func TestInterruptRacingHeartbeatsPrintsOneFinalLine(t *testing.T) {
	h := newHarness(t, scanIDs...)
	h.start(scanInfo)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { h.p.Interrupt() })
	}
	for _, at := range []time.Duration{3 * time.Second, 13 * time.Second, 23 * time.Second} {
		h.advanceTo(at)
	}
	wg.Wait()
	h.p.Stop()

	out := h.take()
	i := strings.Index(out, "bedrock: interrupted at ")
	if i < 0 || strings.Count(out, "interrupted at") != 1 {
		t.Fatalf("want exactly one interrupt line, got:\n%s", out)
	}
	if strings.Count(out[i:], "\n") != 1 {
		t.Errorf("a line followed the interrupt line:\n%s", out)
	}
}

func TestHostileTextCannotReachTheTerminalRaw(t *testing.T) {
	// Sorted, so each heartbeat names the next two IDs.
	ids := []string{"a.\nnewline", "b.\x1b[31mesc", "c.\rcr", "d.\u009bc1", "e.\x9braw",
		"f.\u202ebidi\u2028line\u2029para\ttab\u200bzero"}
	h := newHarness(t, ids...)
	h.start(Info{Target: "evil\r\x1b[2J\x07.example\n\u202e\t", Timeout: time.Second})
	h.advanceTo(3 * time.Second)
	h.p.Done(ids[0])
	h.p.Done(ids[1])
	h.advanceTo(13 * time.Second)
	h.p.Done(ids[2])
	h.p.Done(ids[3])
	h.advanceTo(23 * time.Second)
	h.p.Interrupt()
	h.p.Stop()

	out := h.take()
	if strings.IndexFunc(out, isControlExceptLF) >= 0 || !utf8.ValidString(out) {
		t.Errorf("a control character or invalid UTF-8 reached the output: %q", out)
	}
	if strings.IndexFunc(out, isFormatOrSeparator) >= 0 {
		t.Errorf("a format or separator character reached the output raw: %q", out)
	}
	if !hostileShape.MatchString(out) {
		t.Errorf("an injected newline split a line: %q", out)
	}
}

// hostileShape is the start line and three heartbeats, then the blank row
// and the interrupt line.
var hostileShape = regexp.MustCompile(`^(bedrock: [^\n]*\n){4}\nbedrock: interrupted [^\n]*\n$`)

func isControlExceptLF(r rune) bool {
	return r != '\n' && unicode.IsControl(r)
}

func isFormatOrSeparator(r rune) bool {
	return unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

func TestSystemClockFollowsRealTime(t *testing.T) {
	c := SystemClock()
	before := time.Now()
	now := c.Now()
	if now.Before(before) || now.After(time.Now()) {
		t.Errorf("SystemClock().Now() = %v, want a time between %v and now", now, before)
	}
	select {
	case <-c.After(time.Nanosecond):
	case <-time.After(testTimeout):
		t.Fatal("SystemClock().After(1ns) never fired")
	}
}
