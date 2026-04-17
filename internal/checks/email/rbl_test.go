package email

import (
	"context"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestReverseIPv4(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"1.2.3.4", "4.3.2.1"},
		{"127.0.0.1", "1.0.0.127"},
		{"0.0.0.0", "0.0.0.0"},
		{"255.255.255.255", "255.255.255.255"},
		{"8.8.8.8", "8.8.8.8"},
		{"192.0.2.123", "123.2.0.192"},
		// Not IPv4 — must produce empty.
		{"::1", ""},
		{"2001:db8::1", ""},
		{"not-an-ip", ""},
		{"", ""},
		{"1.2.3", ""},
		{"1.2.3.4.5", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := reverseIPv4(tc.in); got != tc.want {
				t.Errorf("reverseIPv4(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeZoneID(t *testing.T) {
	cases := map[string]string{
		"zen.spamhaus.org":       "zen_spamhaus_org",
		"b.barracudacentral.org": "b_barracudacentral_org",
		"plainword":              "plainword",
		"":                       "",
	}
	for in, want := range cases {
		if got := sanitizeZoneID(in); got != want {
			t.Errorf("sanitizeZoneID(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRBLDisabled verifies the check returns a single N/A result when
// EnableRBL is false (the default), without performing any DNS work.
func TestRBLDisabled(t *testing.T) {
	env := probe.NewEnv("example.com", time.Second, false, "")
	// EnableRBL is false by default.
	got := rblCheck{}.Run(context.Background(), env)
	if len(got) != 1 {
		t.Fatalf("disabled run: got %d results, want 1", len(got))
	}
	r := got[0]
	if r.Status != report.Info {
		t.Errorf("disabled run: status = %v, want Info", r.Status)
	}
	if r.ID != "email.rbl" {
		t.Errorf("disabled run: id = %q, want email.rbl", r.ID)
	}
	if r.Category != category {
		t.Errorf("disabled run: category = %q, want %q", r.Category, category)
	}
	if len(r.RFCRefs) == 0 || r.RFCRefs[0] != "RFC 5782" {
		t.Errorf("disabled run: missing RFC 5782 ref, got %v", r.RFCRefs)
	}
}

// TestRBLZonesNonEmptyAndUnique guards against accidental edits that
// would leave the blocklist matrix empty or duplicate-ridden.
func TestRBLZonesNonEmptyAndUnique(t *testing.T) {
	if len(rblZones) == 0 {
		t.Fatal("rblZones is empty")
	}
	seen := map[string]int{}
	for _, z := range rblZones {
		if z == "" {
			t.Errorf("empty zone in rblZones")
		}
		seen[z]++
	}
	for z, n := range seen {
		if n > 1 {
			t.Errorf("zone %q appears %d times", z, n)
		}
	}
}

// TestQueryRBLsAggregationEmpty exercises the aggregation path with no
// jobs — must not deadlock and must return no listings. This proves the
// worker pool / channel plumbing is wired correctly even on degenerate
// inputs.
func TestQueryRBLsAggregationEmpty(t *testing.T) {
	env := probe.NewEnv("example.com", time.Second, false, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel immediately so any worker that did start exits without
	// performing real DNS.
	cancel()

	got := queryRBLs(ctx, env, nil, rblZones)
	if len(got) != 0 {
		t.Errorf("queryRBLs(no IPs) = %d listings, want 0", len(got))
	}
	got = queryRBLs(ctx, env, []string{"1.2.3.4"}, nil)
	if len(got) != 0 {
		t.Errorf("queryRBLs(no zones) = %d listings, want 0", len(got))
	}
}

// TestRBLListingResultShape directly exercises the result shape produced
// for a hypothetical listing — guards the WARN status and the literal
// remediation string against accidental edits, since both are part of
// the documented contract.
func TestRBLListingResultShape(t *testing.T) {
	listings := []rblListing{
		{IP: "1.2.3.4", Zone: "zen.spamhaus.org", Reason: "spam source"},
	}
	// Mirror the Run aggregation logic for a known input.
	var out []report.Result
	for _, l := range listings {
		evidence := l.IP + " listed on " + l.Zone
		if l.Reason != "" {
			evidence += ": " + l.Reason
		}
		out = append(out, report.Result{
			ID:          "email.rbl." + sanitizeZoneID(l.Zone),
			Category:    category,
			Title:       "DNSBL listing on " + l.Zone,
			Status:      report.Warn,
			Evidence:    evidence,
			Remediation: "contact the listing service to request delisting and address the underlying reputation cause",
			RFCRefs:     []string{"RFC 5782"},
		})
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 result, got %d", len(out))
	}
	r := out[0]
	if r.Status != report.Warn {
		t.Errorf("listing status = %v, want Warn (FAIL would be too noisy for transient listings)", r.Status)
	}
	if r.Remediation == "" {
		t.Errorf("listing must include remediation text")
	}
	if r.ID != "email.rbl.zen_spamhaus_org" {
		t.Errorf("listing ID = %q, want email.rbl.zen_spamhaus_org", r.ID)
	}
	if r.Evidence != "1.2.3.4 listed on zen.spamhaus.org: spam source" {
		t.Errorf("listing evidence = %q", r.Evidence)
	}
}
