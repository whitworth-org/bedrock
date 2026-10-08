// Package progress reports a running scan on a terminal's stderr as plain
// lines: a start line, a heartbeat 3s after the start and then every 10s,
// and a line when the scan is interrupted. Lines are only ever appended,
// never redrawn with CR or escape sequences, so screen readers announce each
// one once and scrollback keeps them all.
package progress

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/whitworth-org/bedrock/internal/report"
)

const (
	firstHeartbeat = 3 * time.Second
	heartbeatEvery = 10 * time.Second
	// maxNamed bounds how many unfinished check IDs a heartbeat names, to
	// keep the line short.
	maxNamed = 2
)

// Clock supplies the time. SystemClock is the real one; tests inject a fake
// one to drive heartbeats without sleeping.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

// SystemClock returns a Clock backed by the time package.
func SystemClock() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Info describes the scan for the start line.
type Info struct {
	Target  string
	Active  bool // active probes are enabled, i.e. no --no-active
	Timeout time.Duration
}

// Progress tracks which checks have finished and reports it as lines on a
// writer, typically a terminal's stderr. Lines are written only between
// Start and Stop.
type Progress struct {
	w     io.Writer
	clock Clock
	total int

	// out serialises writes and guards the fields from start to exited.
	// Lock order is out, then mu. Done takes only mu, so a stalled terminal
	// never holds up a finishing check.
	out         sync.Mutex
	start       time.Time
	started     bool // set only when w is non-nil
	stopped     bool
	interrupted bool
	stop        chan struct{} // closed by Stop to end the heartbeats
	exited      chan struct{} // closed when the heartbeat goroutine returns

	mu      sync.Mutex
	pending map[string]int // unfinished runs per check ID
	done    int
}

// New returns a Progress for the given checks; an ID listed twice must
// finish twice. A nil w makes the Progress silent: it still tracks which
// checks are done, so Interrupt can name the unfinished ones.
func New(w io.Writer, checkIDs []string, clock Clock) *Progress {
	pending := make(map[string]int, len(checkIDs))
	for _, id := range checkIDs {
		pending[id]++
	}
	return &Progress{w: w, clock: clock, total: len(checkIDs), pending: pending}
}

// Start prints the start line and starts the heartbeats: the first comes 3s
// after Start and then one every 10s, each giving the elapsed time, the
// checks done and up to two of the checks not done yet, which may still be
// queued rather than running. Start does nothing when the writer is nil,
// when it has already been called, or after Stop.
func (p *Progress) Start(info Info) {
	p.out.Lock()
	defer p.out.Unlock()
	if p.w == nil || p.started || p.stopped {
		return
	}
	p.started = true
	p.start = p.clock.Now()
	mode := "passive only"
	if info.Active {
		mode = "active probes"
	}
	p.emit(fmt.Sprintf("scanning %s: %d checks, %s, timeout %s",
		info.Target, p.total, mode, info.Timeout))
	p.stop, p.exited = make(chan struct{}), make(chan struct{})
	go p.heartbeats(p.stop, p.exited)
}

// Done records that one run of check id has finished. It is safe for
// concurrent use. Unknown IDs, and reports beyond the number of times an ID
// was listed in New, are ignored.
func (p *Progress) Done(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending[id] == 0 {
		return
	}
	p.pending[id]--
	if p.pending[id] == 0 {
		delete(p.pending, id)
	}
	p.done++
}

// Interrupt reports that the scan was cut short, and returns the sorted IDs
// of the checks unfinished at that moment. The first call that finds one
// prints "interrupted at <elapsed>: <done> of <total> checks done; the
// report is partial" after a newline that moves past the ^C the terminal
// echoed. An interrupt after every check finished cut nothing short, so it
// prints nothing. No heartbeat follows any call.
func (p *Progress) Interrupt() []string {
	p.out.Lock()
	defer p.out.Unlock()
	done, unfinished := p.snapshot()
	if p.live() && !p.interrupted && len(unfinished) > 0 {
		fmt.Fprintln(p.w)
		p.emit(fmt.Sprintf("interrupted at %s: %d of %d checks done; the report is partial",
			p.elapsed(), done, p.total))
	}
	p.interrupted = true
	return unfinished
}

// Stop ends the heartbeats and returns once their goroutine has exited;
// nothing is written after Stop returns. It is idempotent and safe to call
// without Start.
func (p *Progress) Stop() {
	p.out.Lock()
	p.stopped = true
	stop, exited := p.stop, p.exited
	p.stop = nil
	p.out.Unlock()
	if stop != nil {
		close(stop)
	}
	if exited != nil {
		<-exited
	}
}

func (p *Progress) heartbeats(stop <-chan struct{}, exited chan<- struct{}) {
	defer close(exited)
	wait := firstHeartbeat
	for {
		select {
		case <-stop:
			return
		case <-p.clock.After(wait):
			p.heartbeat()
			wait = heartbeatEvery
		}
	}
}

func (p *Progress) heartbeat() {
	p.out.Lock()
	defer p.out.Unlock()
	if !p.live() || p.interrupted {
		return
	}
	done, unfinished := p.snapshot()
	p.emit(fmt.Sprintf("%s: %d of %d checks done%s",
		p.elapsed(), done, p.total, waitingOn(unfinished)))
}

// live reports whether lines may be written; the caller holds p.out.
func (p *Progress) live() bool {
	return p.started && !p.stopped
}

func (p *Progress) snapshot() (done int, unfinished []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.done, slices.Sorted(maps.Keys(p.pending))
}

func (p *Progress) elapsed() string {
	return p.clock.Now().Sub(p.start).Round(time.Second).String()
}

// emit writes one line; the caller holds p.out. The whole message is made
// display-safe as the terminal report is, whatever the target or the check
// IDs contain: control characters cannot move the cursor or start a line,
// and invisible or reordering characters are spelled out.
func (p *Progress) emit(msg string) {
	fmt.Fprintf(p.w, "bedrock: %s\n", report.DisplaySafe(msg))
}

// waitingOn names up to maxNamed of the sorted unfinished check IDs. They
// are not necessarily running: a check can be queued for a worker.
func waitingOn(ids []string) string {
	switch {
	case len(ids) == 0:
		return ""
	case len(ids) <= maxNamed:
		return "; waiting on " + strings.Join(ids, ", ")
	default:
		return fmt.Sprintf("; waiting on %s and %d more",
			strings.Join(ids[:maxNamed], ", "), len(ids)-maxNamed)
	}
}
