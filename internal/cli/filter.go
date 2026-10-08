// Package cli holds CLI-side concerns: result filtering, JSON config loading,
// and any other glue that lives between flag parsing and the report renderer.
package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// Filter selects what a scan runs and reports. Only and Exclude choose the
// categories to run, through KeepCategory, before the scan; the other
// fields filter the results in Apply, before the report is rendered. Empty
// fields disable the corresponding filter.
type Filter struct {
	// Only runs just the categories in this set (case-insensitive).
	Only []string
	// Exclude skips the categories in this set (case-insensitive).
	Exclude []string
	// MinSeverity keeps only results at or above this severity, where the
	// ranking is Info < Pass < Warn < Fail. NotApplicable is always kept
	// since it's structurally important (--no-active mode).
	MinSeverity report.Status
	// SeveritySet is true when MinSeverity was supplied; without it the
	// renderer shows everything.
	SeveritySet bool
	// IDs keeps only results whose check ID exactly matches one of these,
	// and the run-level results.
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

// KeepCategory reports whether the scan runs the checks in category: it is
// in Only, when Only is set, and not in Exclude. Names match ignoring case
// and surrounding space, as ValidateCategories does.
func (f Filter) KeepCategory(category string) bool {
	matches := func(name string) bool {
		return strings.EqualFold(strings.TrimSpace(name), category)
	}
	if len(f.Only) > 0 && !slices.ContainsFunc(f.Only, matches) {
		return false
	}
	return !slices.ContainsFunc(f.Exclude, matches)
}

// Apply returns the results that pass the IDs and MinSeverity filters,
// preserving order. It leaves categories alone: KeepCategory already chose
// which ran. A run-level result such as dns.resolver.unreachable (see
// registry.RunLevel) is reported whatever Only, Exclude and IDs say.
func (f Filter) Apply(results []report.Result) []report.Result {
	if !f.active() {
		return results
	}
	keepID := stringSet(f.IDs)

	out := make([]report.Result, 0, len(results))
	for _, r := range results {
		if len(keepID) > 0 && !registry.RunLevel(r) {
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
	return len(f.IDs) > 0 || f.SeveritySet
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
