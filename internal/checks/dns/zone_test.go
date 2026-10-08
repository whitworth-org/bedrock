package dns

import (
	"context"
	"strings"
	"testing"
	"time"

	miekg "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// TestZoneSOA_LookupsHaveTheirOwnTimeouts: the SOA lookup and the shared NS
// lookup each get a whole per-operation timeout, so two slow answers that
// together take longer than one timeout still give the MNAME check its NS
// list.
func TestZoneSOA_LookupsHaveTheirOwnTimeouts(t *testing.T) {
	const timeout = 500 * time.Millisecond
	fake := newFakeDNS(t)
	fake.add(t, testSOA, "example.test. 300 IN NS ns1.example.test.",
		"example.test. 300 IN NS ns2.example.test.")
	fake.setDelay("example.test.", 3*timeout/5)
	env := fake.env(t, "example.test", timeout)

	results := runZoneSOA(context.Background(), env)
	if len(results) != 2 || results[0].Status != report.Pass ||
		results[1].ID != "dns.zone.mname" || results[1].Status != report.Pass {
		t.Errorf("got %+v, want PASS for the SOA timers and for the MNAME in the NS list", results)
	}
}

// TestZoneSOA_AliasIsNotApplicable: a target that is a CNAME is not a zone
// apex, so neither the alias target's SOA nor a missing one is graded. The
// fake leaves the CNAME out of the SOA reply, as a resolver that flattens
// CNAME chains does, so only the CNAME lookup finds the alias.
func TestZoneSOA_AliasIsNotApplicable(t *testing.T) {
	fake := newFakeDNS(t)
	fake.add(t, "www.alias.test. 300 IN CNAME edge.cdn.test.")
	env := fake.env(t, "www.alias.test", time.Second)

	results := runZoneSOA(context.Background(), env)

	const want = "www.alias.test is an alias (CNAME to edge.cdn.test), not a zone apex"
	ids := []string{"dns.zone.soa", "dns.zone.mname"}
	if len(results) != len(ids) {
		t.Fatalf("got %+v, want N/A results %v", results, ids)
	}
	for i, r := range results {
		if r.ID != ids[i] || r.Status != report.NotApplicable || r.Evidence != want ||
			r.Remediation != "" {
			t.Errorf("got %+v, want %s N/A %q", r, ids[i], want)
		}
	}
}

// TestZoneSOA_NoSOA: a name with no SOA at or above it that is not an alias
// FAILs; when the CNAME lookup that rules out an alias fails, the result is
// inconclusive instead.
func TestZoneSOA_NoSOA(t *testing.T) {
	cases := []struct {
		name       string
		cnameRcode int
		status     report.Status
		evidence   string
	}{
		{"not an alias", miekg.RcodeSuccess, report.Fail, "no SOA returned for apex"},
		{"CNAME lookup failed", miekg.RcodeServerFailure, wantInconclusive,
			"could not determine: SOA lookup for host.example.test: CNAME lookup: " +
				"resolver answered SERVFAIL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			fake.add(t, "host.example.test. 300 IN A 192.0.2.1")
			fake.setTypeRcode("host.example.test.", miekg.TypeCNAME, tc.cnameRcode)
			env := fake.env(t, "host.example.test", time.Second)

			results := runZoneSOA(context.Background(), env)

			if len(results) != 1 || results[0].Status != tc.status ||
				results[0].Evidence != tc.evidence {
				t.Errorf("got %+v, want one dns.zone.soa %s %q", results, tc.status, tc.evidence)
			}
		})
	}
}

// TestZoneMX_LookupFailures: a failed apex MX lookup is inconclusive, while
// NXDOMAIN, which says the name does not exist, stays a WARN.
func TestZoneMX_LookupFailures(t *testing.T) {
	cases := []struct {
		name     string
		rcode    int
		status   report.Status
		evidence string
	}{
		{"SERVFAIL", miekg.RcodeServerFailure, wantInconclusive,
			"could not determine: MX lookup for example.test: resolver answered SERVFAIL"},
		{"NXDOMAIN", miekg.RcodeNameError, report.Warn, "lookup error: NXDOMAIN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeDNS(t)
			fake.setRcode("example.test.", tc.rcode)
			env := fake.env(t, "example.test", time.Second)

			results := runZoneMX(context.Background(), env)

			if len(results) != 1 || results[0].Status != tc.status ||
				results[0].Evidence != tc.evidence || results[0].Remediation != "" {
				t.Errorf("got %+v, want one dns.zone.mx %s %q", results, tc.status, tc.evidence)
			}
		})
	}
}

func TestSOATimers_PassWhenAllInRange(t *testing.T) {
	soa := &probe.SOA{
		NS:      "ns1.example.com",
		Mbox:    "hostmaster.example.com",
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1814400, // 21 days
		Minimum: 3600,
	}
	r := soaTimers("example.com", soa)
	if r.Status != report.Pass {
		t.Fatalf("expected Pass, got %s (evidence=%q)", r.Status, r.Evidence)
	}
}

func TestSOATimers_WarnsOnLowMinimum(t *testing.T) {
	soa := &probe.SOA{NS: "ns1.example.com", Mbox: "hostmaster.example.com",
		Refresh: 7200, Retry: 3600, Expire: 1814400, Minimum: 60}
	r := soaTimers("example.com", soa)
	if r.Status != report.Warn {
		t.Fatalf("expected Warn for 60s minimum, got %s", r.Status)
	}
	if !strings.Contains(r.Evidence, "MINIMUM=60") {
		t.Fatalf("evidence should call out MINIMUM=60: %q", r.Evidence)
	}
	if r.Remediation == "" {
		t.Fatalf("Warn on SOA timers must include a copy-pasteable remediation")
	}
}

func TestSOATimers_WarnsOnHighMinimum(t *testing.T) {
	soa := &probe.SOA{NS: "ns1.example.com", Mbox: "hostmaster.example.com",
		Refresh: 7200, Retry: 3600, Expire: 1814400, Minimum: 7 * 86400}
	r := soaTimers("example.com", soa)
	if r.Status != report.Warn {
		t.Fatalf("expected Warn for 7d minimum, got %s", r.Status)
	}
}

func TestSOATimers_WarnsOnBadMbox(t *testing.T) {
	soa := &probe.SOA{NS: "ns1.example.com", Mbox: "nope",
		Refresh: 7200, Retry: 3600, Expire: 1814400, Minimum: 3600}
	r := soaTimers("example.com", soa)
	if r.Status != report.Warn {
		t.Fatalf("expected Warn for malformed mbox, got %s", r.Status)
	}
	if !strings.Contains(r.Evidence, "RNAME") {
		t.Fatalf("evidence should mention RNAME: %q", r.Evidence)
	}
}

func TestSOAMNAMEvsNS_PassWhenPresent(t *testing.T) {
	soa := &probe.SOA{NS: "ns1.example.com"}
	r := soaMNAMEvsNS("example.com", soa, []string{"ns1.example.com", "ns2.example.com"})
	if r.Status != report.Pass {
		t.Fatalf("expected Pass when MNAME is in NS set, got %s", r.Status)
	}
}

func TestSOAMNAMEvsNS_InfoWhenHiddenPrimary(t *testing.T) {
	soa := &probe.SOA{NS: "hidden-master.example.net"}
	r := soaMNAMEvsNS("example.com", soa, []string{"ns1.example.com", "ns2.example.com"})
	if r.Status != report.Info {
		t.Fatalf("expected Info for hidden primary, got %s", r.Status)
	}
}

func TestSOAMNAMEvsNS_FailWhenEmpty(t *testing.T) {
	soa := &probe.SOA{NS: ""}
	r := soaMNAMEvsNS("example.com", soa, []string{"ns1.example.com"})
	if r.Status != report.Fail {
		t.Fatalf("expected Fail when MNAME empty, got %s", r.Status)
	}
	if r.Remediation == "" {
		t.Fatalf("Fail must include remediation")
	}
}

func TestSOARemediation_ContainsTarget(t *testing.T) {
	out := soaRemediationExample("example.org")
	if !strings.Contains(out, "example.org") {
		t.Fatalf("remediation should mention target: %q", out)
	}
	if !strings.Contains(out, "minimum") {
		t.Fatalf("remediation should include the MINIMUM line for RFC 2308 context")
	}
}

func TestSOARemediation_OneLineRecordWithPlaceholderSerial(t *testing.T) {
	out := soaRemediationExample("example.org")
	var records []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, ";") {
			records = append(records, line)
		}
	}
	if len(records) != 1 {
		t.Fatalf("want one SOA record line, got %d:\n%s", len(records), out)
	}
	fields := strings.Fields(records[0])
	if len(fields) != 10 || fields[2] != "SOA" || fields[5] != "<YYYYMMDDnn>" {
		t.Errorf("want owner IN SOA and seven RDATA fields with a <YYYYMMDDnn> serial, got %q",
			records[0])
	}
}
