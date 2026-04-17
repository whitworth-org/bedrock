package dnssec

import (
	"context"
	"fmt"
	"sort"
	"strings"

	mdns "github.com/miekg/dns"

	"github.com/rwhitworth/bedrock/internal/probe"
	"github.com/rwhitworth/bedrock/internal/registry"
	"github.com/rwhitworth/bedrock/internal/report"
)

// cdsCheck audits CDS / CDNSKEY publication at the apex per RFC 7344 (the
// child-side signaling channel that lets a registrar/parent automate DS
// updates) and the RFC 8078 "delete DS" sentinel.
//
// Three independent results are produced:
//
//   - dnssec.cds.published     Info if absent, Pass if a well-formed CDS+CDNSKEY
//     pair is published, Warn if only one side exists.
//   - dnssec.cds.matches_ds    Pass when the published CDS matches the DS
//     currently at the parent, Fail (with remediation)
//     when they diverge, N/A when no CDS is published.
//   - dnssec.cds.signed        Info / Warn on whether the CDS RRset carries
//     an RRSIG (RFC 7344 §4.1 requires it).
//
// We deliberately avoid trying to verify the RRSIG cryptographically here —
// the chainCheck already exercises that machinery against DNSKEY/SOA. The CDS
// check only needs to confirm the operator is telling the parent the right
// thing.
type cdsCheck struct{}

func (cdsCheck) ID() string       { return "dnssec.cds" }
func (cdsCheck) Category() string { return category }

func (cdsCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	cctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	cdsResp, cdsErr := env.DNS.ExchangeWithDO(cctx, env.Target, mdns.TypeCDS)
	cdnskeyResp, cdnskeyErr := env.DNS.ExchangeWithDO(cctx, env.Target, mdns.TypeCDNSKEY)

	cdsSet := extractCDS(cdsResp)
	cdnskeySet := extractCDNSKEY(cdnskeyResp)

	// DS at the parent — prefer the cached set populated by chainCheck so we
	// don't re-query, but tolerate the case where chainCheck hasn't run yet
	// (tests, partial runs).
	dsSet := cachedDSs(env)
	if dsSet == nil {
		if dsResp, err := env.DNS.ExchangeWithDO(cctx, env.Target, mdns.TypeDS); err == nil {
			dsSet = extractDS(dsResp)
		}
	}

	results := []report.Result{}

	// --- dnssec.cds.published -------------------------------------------------
	switch {
	case cdsErr != nil && cdnskeyErr != nil:
		results = append(results, report.Result{
			ID:       "dnssec.cds.published",
			Category: category,
			Title:    "CDS / CDNSKEY lookup failed",
			Status:   report.Warn,
			Evidence: fmt.Sprintf("CDS: %s; CDNSKEY: %s", cdsErr.Error(), cdnskeyErr.Error()),
			RFCRefs:  []string{"RFC 7344 §3"},
		})
		// No point continuing — neither side is observable.
		return results

	case len(cdsSet) == 0 && len(cdnskeySet) == 0:
		// Operator has opted out of automated DS maintenance. RFC 7344 §3:
		// CDS/CDNSKEY publication is voluntary.
		results = append(results, report.Result{
			ID:       "dnssec.cds.published",
			Category: category,
			Title:    "No CDS/CDNSKEY published",
			Status:   report.Info,
			Evidence: "operator manages DS at parent manually (CDS/CDNSKEY are optional, RFC 7344 §3)",
			RFCRefs:  []string{"RFC 7344 §3"},
		})
		results = append(results, report.Result{
			ID:       "dnssec.cds.matches_ds",
			Category: category,
			Title:    "CDS/parent-DS match check skipped",
			Status:   report.NotApplicable,
			Evidence: "no CDS published",
			RFCRefs:  []string{"RFC 7344 §4"},
		})
		return results

	case len(cdsSet) > 0 && len(cdnskeySet) == 0:
		results = append(results, report.Result{
			ID:       "dnssec.cds.published",
			Category: category,
			Title:    "CDS published without matching CDNSKEY",
			Status:   report.Warn,
			Evidence: fmt.Sprintf("CDS count=%d, CDNSKEY count=0", len(cdsSet)),
			Remediation: "# RFC 7344 §3: publish a CDNSKEY RRset alongside CDS so the\n" +
				"# parent can independently re-derive the digest.",
			RFCRefs: []string{"RFC 7344 §3"},
		})

	case len(cdsSet) == 0 && len(cdnskeySet) > 0:
		results = append(results, report.Result{
			ID:       "dnssec.cds.published",
			Category: category,
			Title:    "CDNSKEY published without matching CDS",
			Status:   report.Warn,
			Evidence: fmt.Sprintf("CDS count=0, CDNSKEY count=%d", len(cdnskeySet)),
			Remediation: "# RFC 7344 §3: publish CDS records alongside CDNSKEY so parents\n" +
				"# that prefer the digest form can consume the signal.",
			RFCRefs: []string{"RFC 7344 §3"},
		})

	default:
		// Both sides present — verify mutual consistency.
		if delete := isDeleteSentinel(cdsSet, cdnskeySet); delete {
			// RFC 8078 §4: a single CDS / CDNSKEY with the all-zero "delete DS"
			// payload signals the parent should remove all DS records.
			results = append(results, report.Result{
				ID:       "dnssec.cds.published",
				Category: category,
				Title:    "CDS/CDNSKEY signal: remove DS at parent (RFC 8078 §4)",
				Status:   report.Info,
				Evidence: "all-zero CDS + CDNSKEY payload — operator is asking the parent to delete DS",
				RFCRefs:  []string{"RFC 8078 §4"},
			})
		} else {
			matched, mismatchEvidence := cdsConsistentWithCDNSKEY(cdsSet, cdnskeySet)
			if matched {
				results = append(results, report.Result{
					ID:       "dnssec.cds.published",
					Category: category,
					Title:    "CDS and CDNSKEY published and self-consistent",
					Status:   report.Pass,
					Evidence: fmt.Sprintf("CDS count=%d, CDNSKEY count=%d; every CDS digest matches a CDNSKEY",
						len(cdsSet), len(cdnskeySet)),
					RFCRefs: []string{"RFC 7344 §3", "RFC 7344 §4"},
				})
			} else {
				results = append(results, report.Result{
					ID:       "dnssec.cds.published",
					Category: category,
					Title:    "CDS digest does not match any published CDNSKEY",
					Status:   report.Fail,
					Evidence: mismatchEvidence,
					Remediation: "# Re-publish CDS so each record's digest is derived from one of\n" +
						"# the published CDNSKEY records. Most signers regenerate both\n" +
						"# RRsets in lockstep; a divergence usually means a stale CDS.",
					RFCRefs: []string{"RFC 7344 §3"},
				})
			}
		}
	}

	// --- dnssec.cds.matches_ds -----------------------------------------------
	// Skip when CDS is the delete sentinel — by definition there is no DS to
	// compare against once the parent acts on it; before the parent acts the
	// existing DS is expected to be different, not divergent.
	if !isDeleteSentinel(cdsSet, cdnskeySet) && len(cdsSet) > 0 {
		results = append(results, evaluateCDSvsDS(cdsSet, dsSet))
	}

	// --- dnssec.cds.signed ---------------------------------------------------
	// We only check presence of an RRSIG — the chain check verifies signing
	// keys against DNSKEY. RFC 7344 §4.1: CDS/CDNSKEY MUST be signed with a
	// key that has a corresponding DS at the parent.
	if len(cdsSet) > 0 {
		sigs := extractRRSIGCovering(cdsResp, mdns.TypeCDS)
		if len(sigs) == 0 {
			results = append(results, report.Result{
				ID:       "dnssec.cds.signed",
				Category: category,
				Title:    "CDS RRset is not signed",
				Status:   report.Warn,
				Evidence: "no RRSIG covering the CDS RRset",
				Remediation: "# RFC 7344 §4.1 requires CDS/CDNSKEY to be signed by a key the\n" +
					"# parent already trusts (i.e. one already in the DS RRset). An\n" +
					"# unsigned CDS will be ignored by conforming parents.",
				RFCRefs: []string{"RFC 7344 §4.1"},
			})
		} else {
			results = append(results, report.Result{
				ID:       "dnssec.cds.signed",
				Category: category,
				Title:    "CDS RRset carries an RRSIG",
				Status:   report.Info,
				Evidence: fmt.Sprintf("%d RRSIG(s) covering CDS", len(sigs)),
				RFCRefs:  []string{"RFC 7344 §4.1"},
			})
		}
	}

	return results
}

// evaluateCDSvsDS returns the dnssec.cds.matches_ds result, comparing the
// child's published CDS records against the DS records the parent currently
// publishes. RFC 7344 §4: parents that act on CDS replace their DS so the
// two RRsets converge.
func evaluateCDSvsDS(cdsSet []*mdns.CDS, dsSet []*mdns.DS) report.Result {
	if len(dsSet) == 0 {
		// CDS published but no DS at parent yet — common right after enabling
		// DNSSEC. RFC 8078 §3 (initial bootstrap) treats this as the operator
		// publishing CDS to ask the parent to add DS.
		return report.Result{
			ID:       "dnssec.cds.matches_ds",
			Category: category,
			Title:    "CDS published but parent has no DS (initial bootstrap, RFC 8078 §3)",
			Status:   report.Info,
			Evidence: fmt.Sprintf("CDS count=%d, parent DS count=0", len(cdsSet)),
			RFCRefs:  []string{"RFC 8078 §3"},
		}
	}

	if cdsMatchesDS(cdsSet, dsSet) {
		return report.Result{
			ID:       "dnssec.cds.matches_ds",
			Category: category,
			Title:    "CDS matches DS at parent",
			Status:   report.Pass,
			Evidence: fmt.Sprintf("CDS=[%s] DS=[%s]", formatCDSSet(cdsSet), formatDSSet(dsSet)),
			RFCRefs:  []string{"RFC 7344 §4"},
		}
	}

	return report.Result{
		ID:       "dnssec.cds.matches_ds",
		Category: category,
		Title:    "CDS does not match DS at parent",
		Status:   report.Fail,
		Evidence: fmt.Sprintf("CDS=[%s] DS=[%s]", formatCDSSet(cdsSet), formatDSSet(dsSet)),
		Remediation: "# Update DS records at the parent (registrar) to match the published CDS:\n" +
			cdsRemediationLines(cdsSet),
		RFCRefs: []string{"RFC 7344 §4", "RFC 8078 §3"},
	}
}

// cdsMatchesDS returns true when the CDS RRset is equivalent (as a set) to
// the DS RRset. Equivalence is per (KeyTag, Algorithm, DigestType, Digest);
// digest comparison is case-insensitive because the wire form is hex.
func cdsMatchesDS(cdsSet []*mdns.CDS, dsSet []*mdns.DS) bool {
	if len(cdsSet) != len(dsSet) {
		return false
	}
	cdsKeys := make(map[string]struct{}, len(cdsSet))
	for _, c := range cdsSet {
		cdsKeys[dsTuple(&c.DS)] = struct{}{}
	}
	for _, d := range dsSet {
		if _, ok := cdsKeys[dsTuple(d)]; !ok {
			return false
		}
	}
	return true
}

// dsTuple is the canonical key for set-equality comparisons. Digest is
// upper-cased so SHA256 hex from different sources compares equal.
func dsTuple(d *mdns.DS) string {
	return fmt.Sprintf("%d|%d|%d|%s", d.KeyTag, d.Algorithm, d.DigestType, strings.ToUpper(d.Digest))
}

// cdsConsistentWithCDNSKEY verifies that every CDS digest can be re-derived
// from one of the published CDNSKEY records. RFC 7344 §3 mandates this — the
// CDS RRset is, semantically, a hash projection of the CDNSKEY RRset.
func cdsConsistentWithCDNSKEY(cdsSet []*mdns.CDS, cdnskeySet []*mdns.CDNSKEY) (bool, string) {
	for _, cds := range cdsSet {
		matched := false
		for _, ck := range cdnskeySet {
			if ck.Algorithm != cds.Algorithm {
				continue
			}
			// CDNSKEY embeds DNSKEY, so ToDS is available.
			computed := ck.DNSKEY.ToDS(cds.DigestType)
			if computed == nil {
				continue
			}
			if computed.KeyTag == cds.KeyTag && strings.EqualFold(computed.Digest, cds.Digest) {
				matched = true
				break
			}
		}
		if !matched {
			return false, fmt.Sprintf("CDS keytag=%d alg=%d digest-type=%d not derivable from any CDNSKEY",
				cds.KeyTag, cds.Algorithm, cds.DigestType)
		}
	}
	return true, ""
}

// isDeleteSentinel implements RFC 8078 §4: a single CDS or CDNSKEY whose
// algorithm and digest fields are zero is the "delete DS" signal. Per the
// RFC the CDS payload is `0 0 0 00` and the CDNSKEY payload is
// `0 3 0 AA==` (algorithm zero, key field a single zero octet).
func isDeleteSentinel(cdsSet []*mdns.CDS, cdnskeySet []*mdns.CDNSKEY) bool {
	cdsDelete := len(cdsSet) == 1 &&
		cdsSet[0].Algorithm == 0 &&
		cdsSet[0].DigestType == 0 &&
		isAllZeroDigest(cdsSet[0].Digest)
	cdnskeyDelete := len(cdnskeySet) == 1 &&
		cdnskeySet[0].Algorithm == 0
	switch {
	case cdsDelete && len(cdnskeySet) == 0:
		return true
	case cdnskeyDelete && len(cdsSet) == 0:
		return true
	case cdsDelete && cdnskeyDelete:
		return true
	}
	return false
}

// isAllZeroDigest accepts an empty digest, "00", or a hex run of only zeros.
// Different signers serialize the sentinel slightly differently.
func isAllZeroDigest(digest string) bool {
	if digest == "" {
		return true
	}
	for _, r := range digest {
		if r != '0' {
			return false
		}
	}
	return true
}

func extractCDS(m *mdns.Msg) []*mdns.CDS {
	if m == nil {
		return nil
	}
	var out []*mdns.CDS
	for _, rr := range m.Answer {
		if c, ok := rr.(*mdns.CDS); ok {
			out = append(out, c)
		}
	}
	return out
}

func extractCDNSKEY(m *mdns.Msg) []*mdns.CDNSKEY {
	if m == nil {
		return nil
	}
	var out []*mdns.CDNSKEY
	for _, rr := range m.Answer {
		if c, ok := rr.(*mdns.CDNSKEY); ok {
			out = append(out, c)
		}
	}
	return out
}

func formatCDSSet(cdsSet []*mdns.CDS) string {
	parts := make([]string, 0, len(cdsSet))
	for _, c := range cdsSet {
		parts = append(parts, fmt.Sprintf("%d/%d/%d", c.KeyTag, c.Algorithm, c.DigestType))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func formatDSSet(dsSet []*mdns.DS) string {
	parts := make([]string, 0, len(dsSet))
	for _, d := range dsSet {
		parts = append(parts, fmt.Sprintf("%d/%d/%d", d.KeyTag, d.Algorithm, d.DigestType))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// cdsRemediationLines emits one DS line per CDS the operator has published —
// the literal record the registrar should publish so DS converges with CDS.
func cdsRemediationLines(cdsSet []*mdns.CDS) string {
	lines := make([]string, 0, len(cdsSet))
	for _, c := range cdsSet {
		lines = append(lines, fmt.Sprintf("# %s. IN DS %d %d %d %s",
			strings.TrimSuffix(c.Hdr.Name, "."), c.KeyTag, c.Algorithm, c.DigestType, strings.ToUpper(c.Digest)))
	}
	return strings.Join(lines, "\n")
}

func init() { registry.Register(cdsCheck{}) }
