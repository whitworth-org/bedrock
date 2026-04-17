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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/whitworth-org/bedrock/internal/report"
)

// maxBaselineBytes bounds how much of a baseline file we will decode. A
// baseline is a JSON report — in practice tens of KB — so 16 MiB is a
// generous upper bound that still protects the process from a truncated
// or adversarial file that balloons JSON depth.
const maxBaselineBytes = 16 << 20 // 16 MiB

// baselineDoc wraps the decoded report with per-ID metadata the normal
// report.Report doesn't need to carry. Specifically, we track IDs that
// appeared more than once in the baseline file so Diff can treat them as
// "absent" — if the baseline is ambiguous for an ID, any current Fail for
// that ID is surfaced as a regression.
type baselineDoc struct {
	Report      *report.Report
	DuplicateID map[string]struct{}
}

// Load reads a previously-saved JSON report from path. The file is capped
// at maxBaselineBytes; oversize or malformed input fails closed. Unknown
// top-level JSON fields are rejected via DisallowUnknownFields so the
// regression baseline schema cannot silently accept attacker-supplied
// extensions.
func Load(path string) (*report.Report, error) {
	doc, err := loadBaseline(path)
	if err != nil {
		return nil, err
	}
	return doc.Report, nil
}

// loadBaseline is Load but returns the full baselineDoc so Diff can
// consult the per-ID duplicate map. Exported API remains stable.
func loadBaseline(path string) (*baselineDoc, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline %s: %w", path, err)
	}
	defer f.Close()

	// Cap read to maxBaselineBytes. If the file is bigger we treat it as
	// an error rather than silently truncating.
	limited := io.LimitReader(f, maxBaselineBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	if len(data) > maxBaselineBytes {
		return nil, fmt.Errorf("baseline %s exceeds %d bytes", path, maxBaselineBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r report.Report
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}

	dup := map[string]struct{}{}
	seen := map[string]struct{}{}
	for _, res := range r.Results {
		if _, ok := seen[res.ID]; ok {
			dup[res.ID] = struct{}{}
			continue
		}
		seen[res.ID] = struct{}{}
	}
	return &baselineDoc{Report: &r, DuplicateID: dup}, nil
}

// Diff returns results from current that are FAIL now and were PASS or WARN
// in baseline (or absent entirely — a brand-new check that fails counts as
// a regression). Identical pre-existing failures are NOT regressions.
//
// If the baseline carries the same ID more than once we cannot safely
// decide which Status to compare against, so we treat every Fail for such
// an ID as a regression. This fails closed: an ambiguous baseline never
// masks a real failure.
func Diff(base *report.Report, current report.Report) []report.Result {
	if base == nil {
		return nil
	}
	prior := map[string]report.Status{}
	dup := map[string]struct{}{}
	seen := map[string]struct{}{}
	for _, r := range base.Results {
		if _, ok := seen[r.ID]; ok {
			dup[r.ID] = struct{}{}
			continue
		}
		seen[r.ID] = struct{}{}
		prior[r.ID] = r.Status
	}
	var out []report.Result
	for _, r := range current.Results {
		if r.Status != report.Fail {
			continue
		}
		if _, isDup := dup[r.ID]; isDup {
			// Ambiguous baseline entry: report as regression.
			out = append(out, r)
			continue
		}
		ps, ok := prior[r.ID]
		if !ok || ps == report.Pass || ps == report.Warn || ps == report.Info {
			out = append(out, r)
		}
	}
	return out
}
