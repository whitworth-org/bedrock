package dns

import (
	"strings"
	"testing"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
)

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
