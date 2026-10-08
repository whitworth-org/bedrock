package cli

import (
	"strings"
	"testing"
	"time"
)

var validateKnown = []string{"DNS", "DNSSEC", "Email", "Subdomain", "WWW"}

func TestValidateCategoriesAcceptsKnownNamesInAnyCase(t *testing.T) {
	for _, names := range [][]string{nil, {"Email"}, {"email", "wWw"}, {" dnssec ", "SUBDOMAIN"}} {
		if err := ValidateCategories(names, validateKnown); err != nil {
			t.Errorf("ValidateCategories(%q): %v", names, err)
		}
	}
}

func TestValidateCategoriesRejectsUnknownNames(t *testing.T) {
	for _, names := range [][]string{{"Emial"}, {"Email", "Web"}, {"BIMI"}, {""}} {
		err := ValidateCategories(names, validateKnown)
		if err == nil {
			t.Errorf("ValidateCategories(%q) accepted an unknown category", names)
			continue
		}
		want := "(want one of: DNS, DNSSEC, Email, Subdomain, WWW)"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateCategories(%q) = %q; want it to list %s", names, err, want)
		}
	}
}

func TestValidateTimeout(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second, -5 * time.Second} {
		if err := ValidateTimeout(d); err == nil {
			t.Errorf("ValidateTimeout(%s) accepted a timeout that is not positive", d)
		}
	}
	for _, d := range []time.Duration{time.Nanosecond, time.Millisecond, 5 * time.Second} {
		if err := ValidateTimeout(d); err != nil {
			t.Errorf("ValidateTimeout(%s): %v", d, err)
		}
	}
}

func TestValidateRegressionOnly(t *testing.T) {
	if err := ValidateRegressionOnly(true, ""); err == nil {
		t.Error("ValidateRegressionOnly(true, \"\") accepted --regression-only without --baseline")
	}
	cases := []struct {
		regressionOnly bool
		baseline       string
	}{{true, "baseline.json"}, {false, ""}, {false, "baseline.json"}}
	for _, c := range cases {
		if err := ValidateRegressionOnly(c.regressionOnly, c.baseline); err != nil {
			t.Errorf("ValidateRegressionOnly(%v, %q): %v", c.regressionOnly, c.baseline, err)
		}
	}
}
