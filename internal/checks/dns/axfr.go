package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	miekg "github.com/miekg/dns"

	"bedrock/internal/probe"
	"bedrock/internal/report"
)

// axfrCheck attempts an AXFR against each authoritative NS over TCP/53.
// RFC 5936 §6 makes clear that AXFR is privileged data; servers MUST refuse
// it from unauthenticated peers. A successful transfer (or REFUSED-but-data)
// is a Fail; REFUSED / NOTAUTH / NOTIMP / connection refused / timeout is a Pass.
//
// We don't add a new module for this — miekg/dns is already in go.mod and
// the probe package didn't expose a transfer helper.
type axfrCheck struct{}

func (axfrCheck) ID() string       { return "dns.axfr" }
func (axfrCheck) Category() string { return category }

func (axfrCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID:       "dns.axfr",
			Category: category,
			Title:    "AXFR refusal probe",
			Status:   report.NotApplicable,
			Evidence: "skipped: --no-active",
			RFCRefs:  []string{"RFC 5936 §6"},
		}}
	}

	ns := nameserverList(ctx, env)
	if len(ns) == 0 {
		return []report.Result{{
			ID:       "dns.axfr",
			Category: category,
			Title:    "AXFR refusal probe",
			Status:   report.NotApplicable,
			Evidence: "no NS records to probe",
			RFCRefs:  []string{"RFC 5936 §6"},
		}}
	}

	var results []report.Result
	for _, n := range ns {
		results = append(results, axfrProbe(ctx, env, n))
	}
	return results
}

func axfrProbe(ctx context.Context, env *probe.Env, nsHost string) report.Result {
	id := "dns.axfr." + nsHost

	// Resolve the NS to an IP first; if we can't, skip with NotApplicable.
	c, cancel := env.WithTimeout(ctx)
	ips, err := env.DNS.LookupA(c, nsHost)
	cancel()
	if err != nil || len(ips) == 0 {
		return report.Result{
			ID:       id,
			Category: category,
			Title:    "AXFR probe — " + nsHost,
			Status:   report.NotApplicable,
			Evidence: "could not resolve NS to IPv4",
			RFCRefs:  []string{"RFC 5936 §6"},
		}
	}
	addr := net.JoinHostPort(ips[0].String(), "53")

	tr := &miekg.Transfer{
		DialTimeout:  env.Timeout,
		ReadTimeout:  env.Timeout,
		WriteTimeout: env.Timeout,
	}
	m := new(miekg.Msg)
	m.SetAxfr(miekg.Fqdn(env.Target))

	envCh, err := tr.In(m, addr)
	if err != nil {
		// Connection refused / TCP/53 closed / TLS error == operationally fine.
		return report.Result{
			ID:       id,
			Category: category,
			Title:    "AXFR refused at " + nsHost,
			Status:   report.Pass,
			Evidence: fmt.Sprintf("dial/transfer to %s rejected: %s", addr, err.Error()),
			RFCRefs:  []string{"RFC 5936 §6"},
		}
	}

	var rrCount int
	var lastErr error
	for ev := range envCh {
		if ev == nil {
			continue
		}
		if ev.Error != nil {
			lastErr = ev.Error
			continue
		}
		rrCount += len(ev.RR)
	}

	// Refusal manifests as an error envelope before any answer RRs arrive.
	// miekg surfaces server rcode in the error string ("bad xfr rcode: 5").
	if rrCount == 0 {
		// Any error (REFUSED, NOTAUTH, NOTIMP, FORMERR, EOF, ...) means
		// the server did not hand us the zone. That's a Pass.
		evidence := "no RRs returned"
		if lastErr != nil {
			evidence += "; " + lastErr.Error()
		}
		return report.Result{
			ID:       id,
			Category: category,
			Title:    "AXFR refused at " + nsHost,
			Status:   report.Pass,
			Evidence: evidence,
			RFCRefs:  []string{"RFC 5936 §6"},
		}
	}

	return report.Result{
		ID:       id,
		Category: category,
		Title:    "AXFR allowed at " + nsHost + " (zone leak)",
		Status:   report.Fail,
		Evidence: fmt.Sprintf("transferred %d RRs from %s — full zone publicly exposed", rrCount, addr),
		Remediation: strings.TrimSpace(`
# BIND
allow-transfer { none; };           # disable AXFR globally
# or restrict to a TSIG key:
# allow-transfer { key transfer-key; };

# NSD
provide-xfr: 0.0.0.0/0 NOKEY        # remove; only list specific peers

# Knot DNS
acl: []                              # remove transfer ACLs from the zone block`),
		RFCRefs: []string{"RFC 5936 §6"},
	}
}
