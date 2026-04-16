package email

import (
	"context"
	"errors"
	"fmt"

	"bedrock/internal/probe"
	"bedrock/internal/report"
)

type daneCheck struct{}

func (daneCheck) ID() string       { return "email.dane" }
func (daneCheck) Category() string { return category }

// Run looks up TLSA records for each MX at _25._tcp.<mx-host> per
// RFC 7672 §2.2.3. We do not validate the chain here — that requires a
// DNSSEC-validating resolver; we only verify that records exist and are
// usable (recognized usage / selector / matching-type combinations).
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

func probeDANE(ctx context.Context, env *probe.Env, mxHost string, refs []string) report.Result {
	id := "email.dane." + mxHost
	title := "DANE TLSA for " + mxHost
	name := "_25._tcp." + mxHost

	tlsa, err := env.DNS.LookupTLSA(ctx, name)
	if err != nil {
		if errors.Is(err, probe.ErrNXDOMAIN) {
			return report.Result{
				ID: id, Category: category, Title: title,
				Status: report.NotApplicable, Evidence: "no TLSA records at " + name + " (DANE not deployed)",
				RFCRefs: refs,
			}
		}
		return report.Result{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "TLSA lookup error: " + err.Error(),
			RFCRefs: refs,
		}
	}
	if len(tlsa) == 0 {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "no TLSA records at " + name,
			RFCRefs: refs,
		}
	}

	// Surface usage 0/1 (PKIX-TA / PKIX-EE) — RFC 7672 §3.1 says these are
	// not appropriate for SMTP and SHOULD be treated as unusable.
	for _, t := range tlsa {
		if t.Usage == 0 || t.Usage == 1 {
			return report.Result{
				ID: id, Category: category, Title: title,
				Status:   report.Warn,
				Evidence: fmt.Sprintf("TLSA usage=%d at %s; SMTP DANE expects usage 2 or 3 (RFC 7672 §3.1)", t.Usage, name),
				RFCRefs:  refs,
			}
		}
	}

	return report.Result{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("%d TLSA record(s) at %s", len(tlsa), name),
		RFCRefs:  refs,
	}
}

// isNullMX reports whether the slice is the RFC 7505 single-record null MX.
func isNullMX(mxs []probe.MX) bool {
	return len(mxs) == 1 && mxs[0].Preference == 0 && (mxs[0].Host == "" || mxs[0].Host == ".")
}
