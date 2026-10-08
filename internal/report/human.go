package report

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SGR sequences for the terminal report: the basic colours plus bold,
// painted only on bedrock's own words. Faint (2) and bright black (90) are
// never used because some themes render them invisible.
const (
	sgrReset  = "\x1b[0m"
	sgrBold   = "\x1b[1m"
	sgrRed    = "\x1b[1;31m"
	sgrYellow = "\x1b[33m"
	sgrGreen  = "\x1b[32m"
	sgrCyan   = "\x1b[36m"
)

// detailIndent puts detail lines and ID lists under the ID column: every
// status word is padded to six columns ("FAIL  ", "N/A   ").
const detailIndent = "      "

// idListWidth bounds a line of check IDs, indent included.
const idListWidth = 72

// View carries the facts about a run that the Report does not hold.
type View struct {
	Color          bool          // paint bedrock's own words; false emits no ESC byte
	Elapsed        time.Duration // scan time; 0 omits it, which keeps goldens stable
	Scanned        int           // results before --severity and --ids
	Passive        bool          // --no-active
	Resolvers      []string      // as given, credentials removed; none omits them
	Baseline       string        // --baseline path; "" when unset
	RegressionOnly bool          // --regression-only
	Interrupted    bool          // a signal cut the scan short
	Unfinished     []string      // check IDs still running at the interrupt
	Exit           int           // process exit code, computed once by main
}

// RenderHuman writes the terminal report for r. Sections run from least to
// most important (N/A, PASS, INFO, WARN, FAIL, regressions, summary), so
// the last screen holds the last fixes, the per-category counts and the
// verdict. Every string passes through sanitizeReport and displaySafe, so
// target data can neither move the cursor nor reorder text; untrusted text
// is never wrapped or truncated, and fixes print verbatim at column 0.
func RenderHuman(w io.Writer, r Report, v View) error {
	r, v = safeReport(r), safeView(v)
	h := &human{color: v.Color}
	h.header(r, v)
	h.notApplicable(r.Results)
	h.oneLiners("Passed", Pass, r.Results)
	h.oneLiners("Information", Info, r.Results)
	h.blocks("Warnings", Warn, r.Results)
	h.blocks("Failures", Fail, r.Results)
	h.regressions(r.Regressions, v.Baseline)
	h.unfinished(v.Unfinished)
	h.summary(r.Target, r.Summary)
	h.verdict(r, v)
	if _, err := io.WriteString(w, h.b.String()); err != nil {
		return fmt.Errorf("write terminal report for %s: %w", r.Target, err)
	}
	return nil
}

// Verdict states the run's result in one uncoloured line, without the
// "Result: " prefix or a newline: PASS, FAIL or INCOMPLETE, the counts
// behind it and the exit code, as in
// "FAIL. 10 FAIL (Email 9, WWW 1), 9 WARN. Exit code 1.". The word
// follows v.Exit, so the line cannot disagree with the process exit code.
func Verdict(r Report, v View) string {
	r, v = safeReport(r), safeView(v)
	word, _ := verdictWord(r, v)
	return word + ". " + verdictText(r, v)
}

// FailingIDs returns the distinct, display-safe IDs that make the run
// fail, in report order: the FAIL results or, in --regression-only mode,
// the regressions.
func FailingIDs(r Report, v View) []string {
	r = safeReport(r)
	var ids []string
	if v.RegressionOnly {
		for _, ref := range r.Regressions {
			ids = append(ids, ref.ID)
		}
	} else {
		for _, res := range r.Results {
			if res.Status == Fail {
				ids = append(ids, res.ID)
			}
		}
	}
	return distinct(ids)
}

// WrapIDs joins ids with ", " into lines of at most width columns,
// breaking only between IDs, so no ID is ever split. A line that breaks
// keeps its trailing comma, and an ID too long for a line (comma included)
// gets a line of its own. Width is measured in bytes, an upper bound on
// columns, so a non-ASCII ID can only wrap early.
func WrapIDs(ids []string, width int) []string {
	var lines []string
	cur := ""
	for i, id := range ids {
		piece := id
		if i < len(ids)-1 {
			piece += ","
		}
		switch {
		case i == 0:
			cur = piece
		case len(cur)+1+len(piece) <= width:
			cur += " " + piece
		default:
			lines = append(lines, cur)
			cur = piece
		}
	}
	if len(ids) > 0 {
		lines = append(lines, cur)
	}
	return lines
}

// human accumulates the report so RenderHuman makes a single write.
type human struct {
	b     strings.Builder
	color bool
}

func (h *human) line(s string) {
	h.b.WriteString(s)
	h.b.WriteByte('\n')
}

func (h *human) paint(sgr, s string) string {
	if !h.color || sgr == "" {
		return s
	}
	return sgr + s + sgrReset
}

func (h *human) heading(title string) {
	h.line("")
	h.line(h.paint(sgrBold, title))
}

// status pads the status word to the ID column; only the word is painted.
func (h *human) status(s Status) string {
	word := s.String()
	return h.paint(statusSGR(s), word) + strings.Repeat(" ", max(1, len(detailIndent)-len(word)))
}

func (h *human) header(r Report, v View) {
	n := len(r.Results)
	parts := []string{fmt.Sprintf("%d %s", n, plural(n, "result"))}
	if v.Scanned > n {
		parts[0] = fmt.Sprintf("%d of %d results", n, v.Scanned)
	}
	if v.Elapsed > 0 {
		parts = append(parts, v.Elapsed.Round(100*time.Millisecond).String())
	}
	if v.Passive {
		parts = append(parts, "passive only")
	}
	if n := len(v.Resolvers); n > 0 {
		parts = append(parts, plural(n, "resolver")+" "+strings.Join(v.Resolvers, ","))
	}
	if v.Interrupted {
		parts = append(parts, "interrupted")
	}
	h.line(fmt.Sprintf("bedrock report for %s (%s)", r.Target, strings.Join(parts, ", ")))
}

// notApplicable prints one line per reason (the result's evidence) with the
// IDs that share it, instead of a row per check. Like every heading, each
// count is of results.
func (h *human) notApplicable(rs []Result) {
	groups := naGroups(rs)
	n := 0
	for _, g := range groups {
		n += g.results()
	}
	if n == 0 {
		return
	}
	h.heading(fmt.Sprintf("Not run or not applicable (%d)", n))
	for _, g := range groups {
		why := g.reason
		if why == "" {
			why = "no reason given"
		}
		k := g.results()
		h.line(fmt.Sprintf("%s%d %s: %s", h.status(NotApplicable), k, plural(k, "result"), why))
		h.idLines(g.labels())
	}
}

func (h *human) idLines(ids []string) {
	for _, l := range WrapIDs(ids, idListWidth-len(detailIndent)) {
		h.line(detailIndent + l)
	}
}

// oneLiners prints a line per PASS or INFO entry. PASS shows the title,
// which states what passed; INFO adds its evidence.
func (h *human) oneLiners(title string, st Status, rs []Result) {
	gs := groups(rs, st)
	if len(gs) == 0 {
		return
	}
	h.heading(fmt.Sprintf("%s (%d)", title, countResults(gs)))
	for _, g := range gs {
		h.line(h.entry(st, g))
	}
}

// entry renders a one-line entry; a merged entry says how many results it
// stands for.
func (h *human) entry(st Status, g group) string {
	text := h.status(st) + g.ID + "  " + g.Title
	if ev := strings.Join(nonEmpty(g.evidence), "; "); st == Info && ev != "" {
		text += ": " + ev
	}
	return text + countNote(len(g.evidence))
}

// countNote says how many results a merged entry stands for, so the entries
// add up to the heading's count; a single result needs no note.
func countNote(n int) string {
	if n < 2 {
		return ""
	}
	return fmt.Sprintf(" (%d results)", n)
}

// blocks prints a WARN or FAIL entry in full: evidence, refs and fix.
func (h *human) blocks(title string, st Status, rs []Result) {
	gs := groups(rs, st)
	if len(gs) == 0 {
		return
	}
	h.heading(fmt.Sprintf("%s (%d)", title, countResults(gs)))
	for i, g := range gs {
		if i > 0 {
			h.line("")
		}
		h.line(h.status(st) + g.ID + "  " + g.Title + countNote(len(g.evidence)))
		for _, ev := range nonEmpty(g.evidence) {
			h.line(detailIndent + "evidence: " + ev)
		}
		if len(g.RFCRefs) > 0 {
			h.line(detailIndent + "refs: " + strings.Join(g.RFCRefs, ", "))
		}
		h.fix(g.Remediation)
	}
}

// fix prints the remediation verbatim at column 0 so it pastes as-is: in a
// zone file a leading blank makes a record inherit the previous owner name
// (RFC 1035 §5.1). The label counts the lines printed, trailing newlines
// excluded, so the end of a snippet with blank lines is unambiguous.
func (h *human) fix(rem string) {
	rem = strings.TrimRight(rem, "\n")
	if rem == "" {
		return
	}
	lines := strings.Split(rem, "\n")
	h.line(fmt.Sprintf("%sfix (%d %s):", detailIndent, len(lines), plural(len(lines), "line")))
	for _, l := range lines {
		h.line(l)
	}
}

// regressions lists the new failures when a baseline was given. Adjacent
// identical references merge into one line, as identical results do.
func (h *human) regressions(refs []ResultRef, baseline string) {
	if len(refs) == 0 {
		if baseline != "" {
			h.heading("No new failures since " + baseline)
		}
		return
	}
	rs := make([]Result, len(refs))
	for i, ref := range refs {
		rs[i] = Result{ID: ref.ID, Title: ref.Title, Status: Fail}
	}
	h.heading(fmt.Sprintf("New failures since %s (%d)", baselineName(baseline), len(refs)))
	for _, g := range groups(rs, Fail) {
		h.line(h.entry(Fail, g))
	}
}

// unfinished names the checks still running at the interrupt. A check's
// results can carry longer IDs (web.redirect reports web.redirect.<host>),
// and those it did report may describe the interrupt, not the target.
func (h *human) unfinished(ids []string) {
	if len(ids) == 0 {
		return
	}
	h.heading(fmt.Sprintf("Checks not finished when interrupted (%d)", len(ids)))
	h.idLines(ids)
	h.line(detailIndent + "Results from these checks may reflect the interrupt, not the target.")
}

// summary labels every count ("6 FAIL") so each row reads on its own, as
// a screen reader announces it. Only bedrock's own labels and numbers are
// padded.
func (h *human) summary(target string, s *Summary) {
	h.heading("Summary for " + target)
	labelWidth := utf8.RuneCountInString("Total")
	for _, c := range s.Categories {
		labelWidth = max(labelWidth, utf8.RuneCountInString(c.Category))
	}
	numWidth := len(strconv.Itoa(s.Totals.Total))
	for _, c := range s.Categories {
		h.counts(c.Category, c.Counts, labelWidth, numWidth)
	}
	h.counts("Total", s.Totals, labelWidth, numWidth)
}

func (h *human) counts(label string, c StatusCounts, labelWidth, numWidth int) {
	var b strings.Builder
	b.WriteString(label + strings.Repeat(" ", max(0, labelWidth-utf8.RuneCountInString(label))))
	cells := []struct {
		n  int
		st Status
	}{
		{c.Fail, Fail}, {c.Warn, Warn}, {c.Pass, Pass}, {c.Info, Info},
		{c.NotApplicable, NotApplicable},
	}
	for _, cell := range cells {
		num := strconv.Itoa(cell.n)
		word := num + " " + cell.st.String()
		if cell.n > 0 && (cell.st == Fail || cell.st == Warn) {
			word = h.paint(statusSGR(cell.st), word)
		}
		b.WriteString("  " + strings.Repeat(" ", max(0, numWidth-len(num))) + word)
	}
	h.line(b.String())
}

func (h *human) verdict(r Report, v View) {
	word, sgr := verdictWord(r, v)
	h.line("")
	h.line("Result: " + h.paint(sgr, word) + ". " + verdictText(r, v))
}

// verdictWord names the result and its colour. A PASS over nothing evaluated
// (no results shown) stays unpainted, so it cannot read as an all-clear at a
// glance.
func verdictWord(r Report, v View) (word, sgr string) {
	switch {
	case v.Interrupted:
		return "INCOMPLETE", sgrYellow
	case v.Exit != 0:
		return "FAIL", sgrRed
	case r.Summary.Totals.Total == 0:
		return "PASS", ""
	}
	return "PASS", sgrGreen
}

func verdictText(r Report, v View) string {
	var b strings.Builder
	if v.Interrupted {
		b.WriteString(interruptText(len(v.Unfinished)))
	}
	if v.RegressionOnly {
		b.WriteString(regressionText(r, v.Baseline))
	} else {
		b.WriteString(countsText(r.Summary, v.Scanned))
	}
	fmt.Fprintf(&b, " Exit code %d.", v.Exit)
	return b.String()
}

func interruptText(unfinished int) string {
	if unfinished > 0 {
		return fmt.Sprintf("Scan interrupted; %d %s did not finish. ",
			unfinished, plural(unfinished, "check"))
	}
	return "Scan interrupted; results are partial. "
}

func countsText(s *Summary, scanned int) string {
	t := s.Totals
	switch {
	case t.Total == 0 && scanned > 0:
		return fmt.Sprintf("0 of %d results shown; check --severity and --ids.", scanned)
	case t.Total == 0:
		return "No results."
	case t.Fail == 0:
		return fmt.Sprintf("0 FAIL, %d WARN.", t.Warn)
	}
	return fmt.Sprintf("%d FAIL (%s), %d WARN.", t.Fail, failsByCategory(s), t.Warn)
}

func regressionText(r Report, baseline string) string {
	return fmt.Sprintf("%d new FAIL since %s; %d FAIL in total.",
		len(r.Regressions), baselineName(baseline), r.Summary.Totals.Fail)
}

func baselineName(baseline string) string {
	if baseline == "" {
		return "the baseline"
	}
	return baseline
}

func failsByCategory(s *Summary) string {
	var parts []string
	for _, c := range s.Categories {
		if c.Counts.Fail > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", c.Category, c.Counts.Fail))
		}
	}
	return strings.Join(parts, ", ")
}

func statusSGR(s Status) string {
	switch s {
	case Fail:
		return sgrRed
	case Warn:
		return sgrYellow
	case Pass:
		return sgrGreen
	case Info:
		return sgrCyan
	}
	return ""
}

// group is one displayed entry: adjacent results in a section that share
// ID, category, title, refs and fix, with each result's evidence.
type group struct {
	Result
	evidence []string
}

func groups(rs []Result, st Status) []group {
	var out []group
	for _, r := range rs {
		if r.Status != st {
			continue
		}
		if k := len(out) - 1; k >= 0 && same(out[k].Result, r) {
			out[k].evidence = append(out[k].evidence, r.Evidence)
			continue
		}
		out = append(out, group{Result: r, evidence: []string{r.Evidence}})
	}
	return out
}

func same(a, b Result) bool {
	return a.ID == b.ID && a.Category == b.Category && a.Title == b.Title &&
		a.Remediation == b.Remediation && slices.Equal(a.RFCRefs, b.RFCRefs)
}

func countResults(gs []group) int {
	n := 0
	for _, g := range gs {
		n += len(g.evidence)
	}
	return n
}

// naGroup is one N/A reason with the results that share it. Adjacent
// repeats of an ID fold into one entry of ids; runs counts the results
// behind each entry.
type naGroup struct {
	reason string
	ids    []string
	runs   []int
}

func (g naGroup) results() int {
	n := 0
	for _, run := range g.runs {
		n += run
	}
	return n
}

// labels is ids with each folded entry's count.
func (g naGroup) labels() []string {
	out := make([]string, len(g.ids))
	for i, id := range g.ids {
		out[i] = id + countNote(g.runs[i])
	}
	return out
}

// naGroups groups the unrated results by reason, in order of first
// appearance. A status outside the four rated ones lands here too, so the
// view never drops a result.
func naGroups(rs []Result) []naGroup {
	var out []naGroup
	index := map[string]int{}
	for _, r := range rs {
		if isRated(r.Status) {
			continue
		}
		i, ok := index[r.Evidence]
		if !ok {
			i = len(out)
			index[r.Evidence] = i
			out = append(out, naGroup{reason: r.Evidence})
		}
		g := &out[i]
		if last := len(g.ids) - 1; last >= 0 && g.ids[last] == r.ID {
			g.runs[last]++
			continue
		}
		g.ids, g.runs = append(g.ids, r.ID), append(g.runs, 1)
	}
	return out
}

func isRated(s Status) bool {
	return s == Pass || s == Warn || s == Fail || s == Info
}

// safeReport is the view's copy of r: sanitised, display-safe, and with a
// summary recomputed from the results it holds, so the counts always match
// what the view lists.
func safeReport(r Report) Report {
	r = displaySafe(sanitizeReport(r))
	r.Summary = Summarize(r.Results)
	return r
}

func safeView(v View) View {
	v.Resolvers = displaySafeAll(v.Resolvers)
	v.Baseline = DisplaySafe(v.Baseline)
	v.Unfinished = displaySafeAll(v.Unfinished)
	return v
}

// displaySafeAll returns a display-safe copy of ss.
func displaySafeAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = DisplaySafe(s)
	}
	return out
}

// DisplaySafe returns s on one line as the terminal report shows untrusted
// text: control characters become U+FFFD, TAB a space, and characters that
// render as nothing or reorder text are spelled \uXXXX. Anything bedrock
// writes to a terminal outside the report goes through it too.
func DisplaySafe(s string) string {
	return visible(SanitizeForTerminal(s))
}

// displaySafe is the view-only pass over an already sanitised report,
// returning a copy that shares no slice with r. Characters that are not
// graphic (format characters such as bidi overrides and zero-width
// characters, line and paragraph separators, private-use and unassigned
// code points), default-ignorable fillers and variation selectors become
// visible \uXXXX text, and TAB becomes a space, so target data can neither
// hide or reorder text nor move the cursor. The summary is dropped; JSON
// output never comes through here.
func displaySafe(r Report) Report {
	out := Report{Target: visible(r.Target), Results: make([]Result, len(r.Results))}
	for i, res := range r.Results {
		out.Results[i] = visibleResult(res)
	}
	for _, ref := range r.Regressions {
		out.Regressions = append(out.Regressions,
			ResultRef{ID: visible(ref.ID), Title: visible(ref.Title)})
	}
	return out
}

func visibleResult(res Result) Result {
	res.ID = visible(res.ID)
	res.Category = visible(res.Category)
	res.Title = visible(res.Title)
	res.Evidence = visible(res.Evidence)
	res.Remediation = visible(res.Remediation)
	refs := make([]string, len(res.RFCRefs))
	for i, ref := range res.RFCRefs {
		refs[i] = visible(ref)
	}
	res.RFCRefs = refs
	return res
}

func visible(s string) string {
	if strings.IndexFunc(s, needsEscape) < 0 {
		return s
	}
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\t':
			b.WriteByte(' ')
		case needsEscape(c):
			b.WriteString(escapeRune(c))
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// needsEscape reports whether visible must replace c. LF passes because only
// a fix still holds one, as a line break from bedrock's template.
func needsEscape(c rune) bool {
	return c == '\t' || (c != '\n' && !unicode.IsGraphic(c)) ||
		unicode.In(c, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}

// escapeRune spells c as \uXXXX, or as \UXXXXXXXX beyond the Basic
// Multilingual Plane so the hex digits cannot run into the text after it.
func escapeRune(c rune) string {
	if c > 0xFFFF {
		return fmt.Sprintf(`\U%08X`, c)
	}
	return fmt.Sprintf(`\u%04X`, c)
}

func distinct(ids []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
