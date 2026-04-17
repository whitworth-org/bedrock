package email

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

type daneCheck struct{}

func (daneCheck) ID() string       { return "email.dane" }
func (daneCheck) Category() string { return category }

// Run looks up TLSA records for each MX at _25._tcp.<mx-host> per
// RFC 7672 §2.2.3. DANE only provides its security guarantees when the
// response is signed and validated — RFC 7672 §2.2.1 makes DNSSEC a hard
// prerequisite — so we require the resolver's AD bit on the TLSA answer in
// addition to validating each record's usage/selector/matching-type fields.
func (daneCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	refs := []string{"RFC 7672 §2.2", "RFC 6698"}

	mxs, err := env.DNS.LookupMX(ctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return []report.Result{{
			ID:       "email.dane",
			Category: category,
			Title:    "DANE TLSA records present per MX",
			Status:   report.NotApplicable,
			Evidence: "MX lookup failed: " + err.Error(),
			RFCRefs:  refs,
		}}
	}
	if len(mxs) == 0 || isNullMX(mxs) {
		return []report.Result{{
			ID:       "email.dane",
			Category: category,
			Title:    "DANE TLSA records present per MX",
			Status:   report.NotApplicable,
			Evidence: "no usable MX records — DANE not applicable",
			RFCRefs:  refs,
		}}
	}

	var results []report.Result
	for _, mx := range mxs {
		results = append(results, probeDANE(ctx, env, mx.Host, refs))
	}
	return results
}

// tlsaRecord is a local view of the parsed RDATA we actually care about.
// We decouple from probe.TLSA so a future signature-aware upstream lookup
// can populate the same shape without the check layer changing.
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

func probeDANE(ctx context.Context, env *probe.Env, mxHost string, refs []string) report.Result {
	id := "email.dane." + mxHost
	title := "DANE TLSA for " + mxHost
	name := "_25._tcp." + mxHost

	// Query with DO set so we can inspect the AD bit. RFC 7672 §2.2.1 makes
	// DNSSEC validation a hard prerequisite for SMTP DANE: unsigned TLSA is
	// not merely weak, it is spoofable.
	resp, err := env.DNS.ExchangeWithDO(ctx, name, dns.TypeTLSA)
	if err != nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "TLSA lookup error: " + err.Error(),
			RFCRefs: refs,
		}
	}
	if resp == nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "no TLSA response at " + name,
			RFCRefs: refs,
		}
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

// isNullMX reports whether the slice is the RFC 7505 single-record null MX.
func isNullMX(mxs []probe.MX) bool {
	return len(mxs) == 1 && mxs[0].Preference == 0 && (mxs[0].Host == "" || mxs[0].Host == ".")
}
