package email

import (
	"context"
	"fmt"

	"github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runDANE looks up TLSA records for each MX at _25._tcp.<mx-host> per
// RFC 7672 §2.2.3. DANE only provides its security guarantees when the
// response is signed and validated — RFC 7672 §2.2.1 makes DNSSEC a hard
// prerequisite — so we require the resolver's AD bit on the TLSA answer in
// addition to validating each record's usage/selector/matching-type fields.
func runDANE(ctx context.Context, env *probe.Env) []report.Result {
	const title = "DANE TLSA records present per MX"
	refs := []string{"RFC 7672 §2.2", "RFC 6698"}

	mxs, err := targetMX(ctx, env)
	if err != nil {
		res := report.Result{ID: "email.dane", Category: category, Title: title, RFCRefs: refs}
		return []report.Result{checkutil.Inconclusive(res, err)}
	}
	hosts, skipped := mxHosts(mxs)
	if len(hosts) == 0 {
		return []report.Result{{
			ID:       "email.dane",
			Category: category,
			Title:    title,
			Status:   report.NotApplicable,
			Evidence: "no usable MX records — DANE not applicable",
			RFCRefs:  refs,
		}}
	}

	results := probeMXHosts(ctx, hosts, func(ctx context.Context, host string) report.Result {
		return probeDANE(ctx, env, host, refs)
	})
	if len(skipped) > 0 {
		results = append(results, skippedMXResult("email.dane", title, skipped, refs))
	}
	return results
}

// tlsaRecord is a local view of the parsed RDATA we actually care about.
type tlsaRecord struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	HexLen       int // length of the hex cert/hash string, for validation
}

// validTLSA reports whether r is a well-formed TLSA record per RFC 6698.
// The error return carries a short reason for evidence strings; callers
// treat any error as "malformed" regardless of the specific cause.
func validTLSA(r tlsaRecord) error {
	// Usage: 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE.
	if r.Usage > 3 {
		return fmt.Errorf("usage=%d out of range", r.Usage)
	}
	// Selector: 0 Cert, 1 SPKI.
	if r.Selector > 1 {
		return fmt.Errorf("selector=%d out of range", r.Selector)
	}
	// Matching type: 0 Full, 1 SHA-256, 2 SHA-512.
	if r.MatchingType > 2 {
		return fmt.Errorf("matching=%d out of range", r.MatchingType)
	}
	// Hex data length must match matching type.
	switch r.MatchingType {
	case 0: // Full — variable length, but never empty
		if r.HexLen < 2 {
			return fmt.Errorf("matching=0 full data too short (hex=%d)", r.HexLen)
		}
	case 1: // SHA-256 — 32 bytes = 64 hex chars
		if r.HexLen != 64 {
			return fmt.Errorf("matching=1 expects 64 hex chars (got %d)", r.HexLen)
		}
	case 2: // SHA-512 — 64 bytes = 128 hex chars
		if r.HexLen != 128 {
			return fmt.Errorf("matching=2 expects 128 hex chars (got %d)", r.HexLen)
		}
	}
	return nil
}

// probeDANE grades the TLSA RRset of one MX host. A lookup that could not
// complete is inconclusive: RFC 7672 §2.1.2 has a DANE client treat a
// failed TLSA lookup as an unusable server, so it is not "not deployed".
func probeDANE(ctx context.Context, env *probe.Env, mxHost string, refs []string) report.Result {
	id := "email.dane." + mxHost
	title := "DANE TLSA for " + mxHost
	name := "_25._tcp." + mxHost

	resp, err := lookupTLSA(ctx, env, name)
	if err != nil {
		res := report.Result{ID: id, Category: category, Title: title, RFCRefs: refs}
		return tlsaLookupFailed(ctx, res, name, err)
	}
	if resp.Rcode == dns.RcodeNameError {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "no TLSA records at " + name + " (DANE not deployed)",
			RFCRefs: refs,
		}
	}

	// Collect TLSA RRs from the answer section and validate each one.
	var (
		records    []tlsaRecord
		malformed  []tlsaRecord // for evidence of first bad record
		firstError error
	)
	for _, rr := range resp.Answer {
		t, ok := rr.(*dns.TLSA)
		if !ok {
			continue
		}
		rec := tlsaRecord{
			Usage:        t.Usage,
			Selector:     t.Selector,
			MatchingType: t.MatchingType,
			HexLen:       len(t.Certificate),
		}
		if err := validTLSA(rec); err != nil {
			if firstError == nil {
				firstError = err
				malformed = append(malformed, rec)
			}
			continue
		}
		records = append(records, rec)
	}

	if len(records) == 0 && len(malformed) == 0 {
		// No TLSA RRs at all (empty answer, e.g. NODATA).
		return report.Result{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "no TLSA records at " + name,
			RFCRefs: refs,
		}
	}

	if len(malformed) > 0 && len(records) == 0 {
		m := malformed[0]
		return report.Result{
			ID: id, Category: category, Title: title,
			Status: report.Fail,
			Evidence: fmt.Sprintf("malformed TLSA: usage=%d selector=%d matching=%d hexlen=%d",
				m.Usage, m.Selector, m.MatchingType, m.HexLen),
			Remediation: "Publish TLSA records whose matching-type hash length matches RFC 6698 (SHA-256=64 hex, SHA-512=128 hex) and whose usage/selector/matching-type fields are within their defined ranges.",
			RFCRefs:     refs,
		}
	}

	// Surface usage 0/1 (PKIX-TA / PKIX-EE) — RFC 7672 §3.1 says these are
	// not appropriate for SMTP and SHOULD be treated as unusable.
	for _, t := range records {
		if t.Usage == 0 || t.Usage == 1 {
			return report.Result{
				ID: id, Category: category, Title: title,
				Status:   report.Warn,
				Evidence: fmt.Sprintf("TLSA usage=%d at %s; SMTP DANE expects usage 2 or 3 (RFC 7672 §3.1)", t.Usage, name),
				RFCRefs:  refs,
			}
		}
	}

	// DNSSEC AD-bit gate. Without AD, the response is unauthenticated and
	// therefore spoofable — RFC 7672 §2.2.1.
	if !resp.AuthenticatedData {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Warn,
			Evidence:    fmt.Sprintf("TLSA records present but DNSSEC AD-bit unset — spoofable (%d record(s) at %s)", len(records), name),
			Remediation: "Use a DNSSEC-validating resolver and sign the zone containing _25._tcp.<mx-host> so that the TLSA RRset is authenticated.",
			RFCRefs:     refs,
		}
	}

	return report.Result{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("%d TLSA record(s) at %s (AD-bit set)", len(records), name),
		RFCRefs:  refs,
	}
}

// lookupTLSA queries the TLSA RRset at name with DO set, so the reply
// carries the AD bit: RFC 7672 §2.2.1 makes DNSSEC validation a hard
// prerequisite for SMTP DANE, as unsigned TLSA is spoofable. The DNS client
// gives the lookup its own --timeout. A reply with an rcode other than
// NOERROR or NXDOMAIN, such as SERVFAIL, comes back as a *probe.RcodeError;
// a lookup cut short by the end of the scan returns ctx's error.
func lookupTLSA(ctx context.Context, env *probe.Env, name string) (*dns.Msg, error) {
	resp, err := env.DNS.ExchangeWithDO(ctx, name, dns.TypeTLSA)
	switch {
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, err
	case resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError:
		return nil, &probe.RcodeError{Rcode: resp.Rcode}
	}
	return resp, nil
}

// tlsaLookupFailed grades res for a TLSA lookup at name that returned err.
func tlsaLookupFailed(
	ctx context.Context, res report.Result, name string, err error,
) report.Result {
	if checkutil.Incomplete(ctx, err) {
		return checkutil.Inconclusive(res, fmt.Errorf("TLSA lookup for %s: %w", name, err))
	}
	res.Status, res.Evidence = report.NotApplicable, "TLSA lookup error: "+err.Error()
	return res
}
