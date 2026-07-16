package email

import (
	"context"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// runDKIM2Readiness reports the DNS-observable side of DKIM2 adoption
// (draft-ietf-dkim-dkim2-spec, draft -04). DKIM2 reuses the DKIM1 key
// location (<selector>._domainkey.<domain>) and its examples sign with
// ed25519, so a scanner can see published v=DKIM2 key records and
// DKIM2-ready algorithms — but not the Message-Instance / DKIM2-Signature
// chain of custody, which exists only in mail flow.
//
// Status policy: DKIM2 is an Internet-Draft, so absence is never a
// misconfiguration — this check emits Pass (signals present) or Info
// (guidance), and N/A when no DKIM keys are discoverable at all.
func runDKIM2Readiness(ctx context.Context, env *probe.Env) []report.Result {
	const id = "email.dkim2.readiness"
	const title = "DKIM2 readiness signals (draft-ietf-dkim-dkim2-spec)"
	refs := []string{"draft-ietf-dkim-dkim2-spec-04", "RFC 8463"}

	sweep := dkimSweep(ctx, env)
	if sweep == nil {
		return nil
	}
	found := sweep.Found()
	if len(found) == 0 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "no DKIM keys discoverable on common selectors; see email.dkim.selector.none",
			RFCRefs:  refs,
		}}
	}

	var dkim2Sels, edSels []string
	for _, p := range found {
		if p.Key.Version == "DKIM2" {
			dkim2Sels = append(dkim2Sels, p.Selector)
		}
		if p.Key.KeyType == "ed25519" {
			edSels = append(edSels, p.Selector)
		}
	}

	switch {
	case len(dkim2Sels) > 0:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.Pass,
			Evidence: "v=DKIM2 key record(s) published at: " + strings.Join(dkim2Sels, ", ") +
				" — the DNS side of DKIM2 (draft -04) is in place; the Message-Instance/" +
				"DKIM2-Signature chain is mail-flow behavior a DNS scan cannot observe",
			RFCRefs: refs,
		}}
	case len(edSels) > 0:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.Info,
			Evidence: "no v=DKIM2 key records; ed25519 key(s) at: " + strings.Join(edSels, ", ") +
				" — DKIM2 signs with ed25519, so the DNS-side migration is a version-tag change",
			RFCRefs: refs,
		}}
	default:
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.Info,
			Evidence: "no DKIM2 readiness signals (DKIM1/rsa keys only); DKIM2 reuses " +
				"<selector>._domainkey — publish an ed25519 key and a v=DKIM2 record once " +
				"your MTA supports draft-ietf-dkim-dkim2-spec",
			RFCRefs: refs,
		}}
	}
}
