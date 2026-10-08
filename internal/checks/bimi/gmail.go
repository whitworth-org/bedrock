package bimi

import (
	"context"
	"fmt"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/checks/email"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

type gmailGateCheck struct{}

func (gmailGateCheck) ID() string       { return "bimi.gmail.dmarc" }
func (gmailGateCheck) Category() string { return category }

// Run grades the DMARC prerequisites for showing a BIMI logo (Gmail's
// requirements and BIMI Group draft §7.1): the record that supplies the
// Author Domain's policy and the Organizational Domain's record are at
// enforcement, publish no sp=none, apply to every message and are not in
// test mode. Strict alignment is a recommendation in the evidence only.
func (gmailGateCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	res := report.Result{
		ID: "bimi.gmail.dmarc", Category: category,
		Title:   "BIMI Gmail gate: DMARC quarantine|reject enforced",
		RFCRefs: []string{"Gmail BIMI requirements", "BIMI Group draft §7.1", "RFC 9989 §4.7"},
	}
	if ensureRecord(ctx, env) == nil {
		res.Status = report.NotApplicable
		res.Evidence = "no parsed BIMI record (TXT check did not produce one)"
		return []report.Result{res}
	}
	// An incomplete walk may have missed a record the gate depends on.
	walk := email.EnsureDMARCWalk(ctx, env)
	if err := walk.Incomplete(); err != nil {
		return []report.Result{checkutil.Inconclusive(res, err)}
	}
	if walk.Policy == nil {
		res.Status = report.Fail
		res.Evidence = "no DMARC record at _dmarc." + env.Target + " or any tree-walk ancestor"
		res.Remediation = dmarcRemediation(env.Target, "quarantine")
		return []report.Result{res}
	}
	return []report.Result{gradeGate(res, walk)}
}

// gateRecord is a DMARC record the gate grades and the domain publishing it.
type gateRecord struct {
	domain string
	rec    *email.DMARC
}

// gradeGate grades the records of walk, which found a policy, and lists
// every unmet gate in one result.
func gradeGate(res report.Result, walk *email.DMARCWalk) report.Result {
	records := gateRecords(walk)
	var unmet, fixes []string
	for _, r := range records {
		if gaps := unmetGates(r); len(gaps) > 0 {
			unmet = append(unmet, gaps...)
			fixes = append(fixes, dmarcRemediation(r.domain, enforcedPolicy(r.rec)))
		}
	}
	advice := alignmentAdvice(walk.Policy)
	if len(unmet) == 0 {
		res.Status = report.Pass
		res.Evidence = joinEvidence(gateSummary(walk, records), advice)
		return res
	}
	res.Status = report.Fail
	res.Evidence = joinEvidence(strings.Join(unmet, "; "), advice)
	res.Remediation = strings.Join(fixes, "\n")
	return res
}

// gateRecords returns the records BIMI requires at enforcement: the one
// that supplies the Author Domain's policy and, when that is a different
// record, the Organizational Domain's.
func gateRecords(walk *email.DMARCWalk) []gateRecord {
	records := []gateRecord{{walk.PolicyDomain, walk.Policy}}
	if walk.OrgDomain == walk.PolicyDomain {
		return records
	}
	for _, s := range walk.Steps {
		if s.Domain == walk.OrgDomain && s.Record != nil {
			return append(records, gateRecord{s.Domain, s.Record})
		}
	}
	return records
}

// unmetGates lists the gates r fails. The effective policy needs no gate of
// its own: it is p= of the Author Domain's record or sp= of an inherited
// one, and sp= falls back to p= when it is not published.
func unmetGates(r gateRecord) []string {
	at := " at _dmarc." + r.domain
	var unmet []string
	if r.rec.Policy != "quarantine" && r.rec.Policy != "reject" {
		unmet = append(unmet, "p="+r.rec.Policy+at+" (need quarantine or reject)")
	}
	if _, published := r.rec.Tags["sp"]; published && r.rec.SubdomainPolicy == "none" {
		unmet = append(unmet, "sp=none"+at+" (BIMI requires subdomains at enforcement too)")
	}
	if r.rec.Pct != 100 {
		unmet = append(unmet, fmt.Sprintf("pct=%d%s (retired in RFC 9989, but legacy "+
			"receivers still sample below 100, short of the full enforcement Gmail "+
			"requires: remove the tag)", r.rec.Pct, at))
	}
	if r.rec.TestMode == "y" {
		unmet = append(unmet, "t=y"+at+" (RFC 9989 test mode steps the policy down one "+
			"level, short of the enforcement Gmail requires: set t=n or remove the tag)")
	}
	return unmet
}

// gateSummary describes the records that met every gate.
func gateSummary(walk *email.DMARCWalk, records []gateRecord) string {
	parts := []string{"effective policy " + walk.EffectivePolicy() + " for " + walk.Author}
	for _, r := range records {
		parts = append(parts, fmt.Sprintf("_dmarc.%s p=%s sp=%s t=%s",
			r.domain, r.rec.Policy, r.rec.SubdomainPolicy, r.rec.TestMode))
	}
	return strings.Join(parts, "; ")
}

// alignmentAdvice recommends strict alignment when rec relaxes either mode.
// Neither Gmail nor the BIMI draft requires it, so it is never a gate.
func alignmentAdvice(rec *email.DMARC) string {
	if rec.Adkim == "s" && rec.Aspf == "s" {
		return ""
	}
	return fmt.Sprintf("recommended, not required: strict alignment adkim=s aspf=s "+
		"(published: adkim=%s aspf=%s)", rec.Adkim, rec.Aspf)
}

// joinEvidence appends advice, when there is any, to evidence.
func joinEvidence(evidence, advice string) string {
	if advice == "" {
		return evidence
	}
	return evidence + "; " + advice
}

// enforcedPolicy returns the policy a fix for rec publishes: reject when
// rec already rejects, so the fix never weakens it, else quarantine.
func enforcedPolicy(rec *email.DMARC) string {
	if rec.Policy == "reject" {
		return "reject"
	}
	return "quarantine"
}

func dmarcRemediation(domain, policy string) string {
	return fmt.Sprintf(`_dmarc.%s. IN TXT "v=DMARC1; p=%s; rua=mailto:dmarc@%s"`,
		domain, policy, domain)
}
