package web

import (
	"strings"
	"testing"

	"granite-scan/internal/report"
)

func TestParseSetCookie(t *testing.T) {
	cases := []struct {
		raw  string
		want cookieAttrs
	}{
		{
			raw:  "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
			want: cookieAttrs{Name: "session", Secure: true, HTTPOnly: true, SameSite: "Lax"},
		},
		{
			raw:  "tracker=xyz; Path=/",
			want: cookieAttrs{Name: "tracker"},
		},
		{
			// case-insensitive attribute names
			raw:  "id=1; secure; httponly; samesite=Strict",
			want: cookieAttrs{Name: "id", Secure: true, HTTPOnly: true, SameSite: "Strict"},
		},
		{
			raw:  "lone",
			want: cookieAttrs{Name: "lone"},
		},
	}
	for _, tc := range cases {
		got := parseSetCookie(tc.raw)
		if got != tc.want {
			t.Errorf("parseSetCookie(%q) = %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}

func TestEvaluateCookie(t *testing.T) {
	good := evaluateCookie(
		cookieAttrs{Name: "session", Secure: true, HTTPOnly: true, SameSite: "Lax"},
		"session=abc; Secure; HttpOnly; SameSite=Lax",
	)
	if good.Status != report.Pass {
		t.Errorf("good cookie => %v, want Pass; evidence=%q", good.Status, good.Evidence)
	}

	noSecure := evaluateCookie(
		cookieAttrs{Name: "session", HTTPOnly: true, SameSite: "Lax"},
		"session=abc; HttpOnly; SameSite=Lax",
	)
	if noSecure.Status != report.Fail {
		t.Errorf("no-Secure cookie => %v, want Fail", noSecure.Status)
	}
	if !strings.Contains(noSecure.Evidence, "Secure") {
		t.Errorf("Fail evidence should mention Secure: %q", noSecure.Evidence)
	}
	if noSecure.Remediation == "" {
		t.Errorf("Fail must include Remediation")
	}

	jsExempt := evaluateCookie(
		cookieAttrs{Name: "__Host-js-csrf", Secure: true, SameSite: "Strict"},
		"__Host-js-csrf=abc; Secure; SameSite=Strict",
	)
	if jsExempt.Status != report.Pass {
		t.Errorf("__Host-js- cookie should be Pass without HttpOnly, got %v", jsExempt.Status)
	}

	noSameSite := evaluateCookie(
		cookieAttrs{Name: "session", Secure: true, HTTPOnly: true},
		"session=abc; Secure; HttpOnly",
	)
	if noSameSite.Status != report.Fail {
		t.Errorf("no SameSite => %v, want Fail", noSameSite.Status)
	}
}

func TestCookieSlug(t *testing.T) {
	cases := map[string]string{
		"session":         "session",
		"__Host-js-csrf":  "__Host-js-csrf",
		"weird name@val":  "weird_name_val",
		"":                "anon",
		"with/slash;semi": "with_slash_semi",
	}
	for in, want := range cases {
		if got := cookieSlug(in); got != want {
			t.Errorf("cookieSlug(%q) = %q, want %q", in, got, want)
		}
	}
}
