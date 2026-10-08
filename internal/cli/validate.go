package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ValidateCategories returns an error for the first of names that is not one
// of known, ignoring case and surrounding space as Filter does. The message
// lists the known categories.
func ValidateCategories(names, known []string) error {
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		matches := func(k string) bool { return strings.EqualFold(k, trimmed) }
		if !slices.ContainsFunc(known, matches) {
			return fmt.Errorf("unknown category %q (want one of: %s)",
				name, strings.Join(known, ", "))
		}
	}
	return nil
}

// ValidateTimeout rejects a per-operation timeout of zero or less, which
// would expire every deadline before a single query is sent.
func ValidateTimeout(d time.Duration) error {
	if d <= 0 {
		return fmt.Errorf("invalid --timeout %s: want a duration greater than zero, e.g. 5s", d)
	}
	return nil
}

// ValidateRegressionOnly rejects --regression-only without --baseline: with
// no baseline there are no regressions, so every run would exit 0.
func ValidateRegressionOnly(regressionOnly bool, baseline string) error {
	if regressionOnly && baseline == "" {
		return errors.New("--regression-only requires --baseline <previous report>")
	}
	return nil
}
