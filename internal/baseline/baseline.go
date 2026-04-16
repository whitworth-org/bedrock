// Package baseline implements regression detection across runs.
//
// A baseline is a previously-captured JSON report. Diff returns the subset
// of the current report that represents a regression vs the baseline:
// checks that were PASS or WARN previously and are now FAIL.
//
// This file is the minimal scaffold that main.go depends on. The full
// implementation (comparison rules, output format) lives alongside.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"bedrock/internal/report"
)

// Load reads a previously-saved JSON report from path.
func Load(path string) (*report.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var r report.Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	return &r, nil
}

// Diff returns results from current that are FAIL now and were PASS or WARN
// in baseline (or absent entirely — a brand-new check that fails counts as
// a regression). Identical pre-existing failures are NOT regressions.
func Diff(base *report.Report, current report.Report) []report.Result {
	if base == nil {
		return nil
	}
	prior := map[string]report.Status{}
	for _, r := range base.Results {
		prior[r.ID] = r.Status
	}
	var out []report.Result
	for _, r := range current.Results {
		if r.Status != report.Fail {
			continue
		}
		ps, seen := prior[r.ID]
		if !seen || ps == report.Pass || ps == report.Warn || ps == report.Info {
			out = append(out, r)
		}
	}
	return out
}
