package email

import (
	"context"
	"errors"
	"fmt"

	"bedrock/internal/probe"
	"bedrock/internal/registry"
	"bedrock/internal/report"
)

// arcCheck audits a domain's *prerequisites* for participating in ARC
// (Authenticated Received Chain, RFC 8617). ARC is fundamentally a
// per-message, per-hop validation — it stamps headers (AAR, AMS, AS) when
// an intermediary mutates a message so the final receiver can still trust
// the original DKIM/SPF/DMARC results. From a pure DNS audit we cannot
// validate live ARC chains; we can only verify that the domain owns the
// cryptographic and policy machinery ARC depends on.
//
// Status policy: ARC adoption is an enhancement, never a baseline
// requirement, so this check NEVER returns Fail. Missing prerequisites
// surface as Warn; a healthy or merely informational state is Info.
type arcCheck struct{}

func (arcCheck) ID() string       { return "email.arc" }
func (arcCheck) Category() string { return category }

func (arcCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	out := make([]report.Result, 0, 3)
	out = append(out, arcDKIMResult(ctx, env))
	out = append(out, arcDMARCResult(env))
	out = append(out, arcGuidanceResult())
	return out
}

// arcDKIMResult verifies the domain publishes at least one DKIM key suitable
// for signing ARC-Message-Signature headers (RFC 8617 §4.1.2 — the AMS uses
// the same algorithm machinery defined by RFC 6376).
//
// Probes a single common selector (default._domainkey) via the resolver. We
// intentionally do not re-probe the full selector list the dkim check sweeps
// — this is a posture hint, not a key inventory.
func arcDKIMResult(ctx context.Context, env *probe.Env) report.Result {
	const id = "email.arc.dkim"
	const title = "DKIM keys available for ARC signing"
	refs := []string{"RFC 8617 §4.1", "RFC 6376"}

	lookupCtx, cancel := env.WithTimeout(ctx)
	defer cancel()

	name := "default._domainkey." + env.Target
	txt, err := env.DNS.LookupTXT(lookupCtx, name)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		// Resolver error: cannot determine; emit Warn (never Fail per policy).
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Warn,
			Evidence: "could not resolve " + name + ": " + err.Error(),
			RFCRefs:  refs,
		}
	}
	if hasDKIMRecord(txt) {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "domain has DKIM keys suitable for ARC-Message-Signature signing (selector=default)",
			RFCRefs:  refs,
		}
	}
	return report.Result{
		ID: id, Category: category, Title: title,
		Status:   report.Warn,
		Evidence: "ARC requires DKIM keys (none found at " + name + ")",
		RFCRefs:  refs,
	}
}

// hasDKIMRecord returns true if any of the supplied TXT values looks like a
// DKIM key record (v=DKIM1 or a p= tag).
func hasDKIMRecord(txt []string) bool {
	for _, t := range txt {
		if _, err := ParseDKIM(t); err == nil {
			return true
		}
	}
	return false
}

// arcDMARCResult inspects the cached DMARC parse (populated by dmarcCheck via
// probe.CacheKeyDMARC). ARC is most valuable when the domain enforces DMARC
// (RFC 8617 §5 — ARC was designed so legitimate forwarders/mailing-lists
// don't get scored away under p=quarantine/p=reject).
func arcDMARCResult(env *probe.Env) report.Result {
	const id = "email.arc.dmarc"
	const title = "DMARC enforcement complements ARC"
	refs := []string{"RFC 8617 §5", "RFC 7489"}

	cached, ok := env.CacheGet(probe.CacheKeyDMARC)
	if !ok || cached == nil {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "no DMARC record cached; ARC adds value primarily once DMARC enforcement is in place",
			RFCRefs:  refs,
		}
	}
	d, ok := cached.(*DMARC)
	if !ok || d == nil {
		// Defensive: cache shape changed. Treat as informational, never fatal.
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "DMARC cache present but unrecognized shape; ARC value depends on enforcement",
			RFCRefs:  refs,
		}
	}
	if d.Policy == "none" || d.Policy == "" {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: fmt.Sprintf("ARC adds value primarily for domains that enforce DMARC; current policy=%s", policyOrNone(d.Policy)),
			RFCRefs:  refs,
		}
	}
	return report.Result{
		ID: id, Category: category, Title: title,
		Status:   report.Info,
		Evidence: fmt.Sprintf("DMARC enforced (p=%s); ARC will help legitimate forwarders preserve authentication results", d.Policy),
		RFCRefs:  refs,
	}
}

func policyOrNone(p string) string {
	if p == "" {
		return "none"
	}
	return p
}

// arcGuidanceResult is a single Info row that explains what ARC adds and how
// to deploy it. The Remediation field is informational here (not tied to a
// Fail) — renderers only show Remediation on Fail by default, but JSON/MD
// consumers and operators reading the source can still find the guidance.
func arcGuidanceResult() report.Result {
	return report.Result{
		ID:          "email.arc.guidance",
		Category:    category,
		Title:       "ARC (Authenticated Received Chain) deployment guidance",
		Status:      report.Info,
		Evidence:    "ARC preserves authentication results across legitimate intermediaries (mailing lists, forwarders) by stamping ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal headers on each hop.",
		Remediation: "Deploy at MTA / mail-gateway: stamp three headers per hop using the AMS+AS sealing pair defined in RFC 8617 §4 (ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal). Use the same DKIM key infrastructure as the domain's outbound DKIM signer.",
		RFCRefs:     []string{"RFC 8617 §4", "RFC 8617 §5"},
	}
}

func init() { registry.Register(arcCheck{}) }
