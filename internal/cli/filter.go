// Package cli holds CLI-side concerns: result filtering, JSON config loading,
// and any other glue that lives between flag parsing and the report renderer.
package cli

import (
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/report"
)

// Filter is applied to []report.Result after every check has run, before the
// report is rendered. Empty fields disable the corresponding filter.
type Filter struct {
	// Only keeps results whose Category is in this set (case-insensitive).
	Only []string
	// Exclude drops results whose Category is in this set (case-insensitive).
	Exclude []string
	// MinSeverity keeps only results at or above this severity, where the
	// ranking is Info < Pass < Warn < Fail. NotApplicable is always kept
	// since it's structurally important (--no-active mode).
	MinSeverity report.Status
	// SeveritySet is true when MinSeverity was supplied; without it the
	// renderer shows everything.
	SeveritySet bool
	// IDs keeps only results whose check ID exactly matches one of these.
	IDs []string
}

// ParseSeverity converts a flag value like "warn" / "fail" into a Status.
// Defaults to Info (i.e., show everything) when empty.
func ParseSeverity(s string) (report.Status, bool, error) {
	if strings.TrimSpace(s) == "" {
		return report.Info, false, nil
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return report.Info, true, nil
	case "pass":
		return report.Pass, true, nil
	case "warn", "warning":
		return report.Warn, true, nil
	case "fail", "failure", "error":
		return report.Fail, true, nil
	default:
		return report.Info, false, fmt.Errorf("invalid severity %q (want one of: info, pass, warn, fail)", s)
	}
}

// SplitCSV parses a comma-separated flag value, trimming whitespace and
// dropping empty entries. Returns nil for an empty input.
func SplitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Apply returns the subset of results that survive every active filter,
// preserving order.
func (f Filter) Apply(results []report.Result) []report.Result {
	if !f.active() {
		return results
	}
	keepCat := lowerSet(f.Only)
	dropCat := lowerSet(f.Exclude)
	keepID := stringSet(f.IDs)

	out := make([]report.Result, 0, len(results))
	for _, r := range results {
		cat := strings.ToLower(r.Category)
		if len(keepCat) > 0 {
			if _, ok := keepCat[cat]; !ok {
				continue
			}
		}
		if len(dropCat) > 0 {
			if _, ok := dropCat[cat]; ok {
				continue
			}
		}
		if len(keepID) > 0 {
			if _, ok := keepID[r.ID]; !ok {
				continue
			}
		}
		if f.SeveritySet && !meetsSeverity(r.Status, f.MinSeverity) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (f Filter) active() bool {
	return len(f.Only) > 0 || len(f.Exclude) > 0 || len(f.IDs) > 0 || f.SeveritySet
}

// meetsSeverity ranks Info < Pass < Warn < Fail. NotApplicable always passes
// because hiding it would mask --no-active and N/A states the operator needs
// to see.
func meetsSeverity(got, min report.Status) bool {
	if got == report.NotApplicable {
		return true
	}
	return rank(got) >= rank(min)
}

func rank(s report.Status) int {
	switch s {
	case report.Info:
		return 0
	case report.Pass:
		return 1
	case report.Warn:
		return 2
	case report.Fail:
		return 3
	default:
		return -1
	}
}

func lowerSet(in []string) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}
	return out
}

func stringSet(in []string) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[strings.TrimSpace(s)] = struct{}{}
	}
	return out
}
