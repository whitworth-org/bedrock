package dnssec

import (
	"context"
	"fmt"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"bedrock/internal/probe"
	"bedrock/internal/report"
)

// chainCheck audits the DS-DNSKEY-RRSIG chain at the target's apex.
//
// We rely on a recursive resolver to fetch the parent's DS records (the
// resolver walks the delegation), so a single DS query against the apex
// name is sufficient for our purposes.
type chainCheck struct{}

func (chainCheck) ID() string       { return "dnssec.chain" }
func (chainCheck) Category() string { return category }

func (chainCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	cctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	dsResp, dsErr := env.DNS.ExchangeWithDO(cctx, env.Target, mdns.TypeDS)
	keyResp, keyErr := env.DNS.ExchangeWithDO(cctx, env.Target, mdns.TypeDNSKEY)

	dsSet := extractDS(dsResp)
	keySet := extractDNSKEY(keyResp)

	// Cache for sibling checks (algorithms, nsec) so we don't refetch.
	env.CachePut(cacheKeyDS, dsSet)
	env.CachePut(cacheKeyDNSKEY, keySet)
	env.CachePut(cacheKeySigned, len(dsSet) > 0 && len(keySet) > 0)

	results := []report.Result{}

	// Surface lookup errors but keep going — a partial picture is still useful.
	if dsErr != nil {
		results = append(results, report.Result{
			ID:       "dnssec.signed",
			Category: category,
			Title:    "DS lookup failed",
			Status:   report.Warn,
			Evidence: dsErr.Error(),
			RFCRefs:  []string{"RFC 4034 §5", "RFC 3658"},
		})
		return results
	}

	// Unsigned domain: DNSSEC is opt-in, so this is Info, not Fail.
	if len(dsSet) == 0 && len(keySet) == 0 {
		results = append(results, report.Result{
			ID:       "dnssec.signed",
			Category: category,
			Title:    "Domain is not DNSSEC-signed",
			Status:   report.Info,
			Evidence: "no DS records at parent; no DNSKEY records at apex",
			Remediation: "# At your DNS provider, enable DNSSEC and publish the resulting DS\n" +
				"# record at your registrar. Example after generation:\n" +
				env.Target + ". IN DS 12345 13 2 ABCDEF1234... ; KSK SHA-256",
			RFCRefs: []string{"RFC 4033", "RFC 4034", "RFC 3658"},
		})
		return results
	}

	// Lame DNSSEC: child is signed but parent has no DS — chain is broken
	// and validating resolvers will treat the zone as bogus.
	if len(dsSet) == 0 && len(keySet) > 0 {
		results = append(results, report.Result{
			ID:       "dnssec.signed",
			Category: category,
			Title:    "Zone publishes DNSKEY but parent has no DS (lame DNSSEC)",
			Status:   report.Fail,
			Evidence: fmt.Sprintf("DNSKEY count=%d, DS count=0", len(keySet)),
			Remediation: "# Generate a DS record from your KSK and submit it to your registrar.\n" +
				"# Most provider control panels offer a copy-paste DS string.",
			RFCRefs: []string{"RFC 4035 §5", "RFC 3658 §2.4"},
		})
		return results
	}

	// Inverse: DS at parent but no DNSKEY at child — also broken.
	if len(dsSet) > 0 && len(keySet) == 0 {
		results = append(results, report.Result{
			ID:       "dnssec.signed",
			Category: category,
			Title:    "Parent has DS but zone does not publish DNSKEY (broken chain)",
			Status:   report.Fail,
			Evidence: fmt.Sprintf("DS count=%d, DNSKEY count=0", len(dsSet)),
			Remediation: "# Either publish the matching DNSKEY records at the apex or have\n" +
				"# the registrar remove the stale DS records.",
			RFCRefs: []string{"RFC 4035 §2.2", "RFC 4035 §5"},
		})
		return results
	}

	// Both sides exist — happy path entry.
	results = append(results, report.Result{
		ID:       "dnssec.signed",
		Category: category,
		Title:    "Domain is DNSSEC-signed (DS at parent, DNSKEY at apex)",
		Status:   report.Pass,
		Evidence: fmt.Sprintf("DS count=%d, DNSKEY count=%d", len(dsSet), len(keySet)),
		RFCRefs:  []string{"RFC 4034", "RFC 4035"},
	})

	if keyErr != nil {
		// We only get here if DS exists. Surface the DNSKEY fetch error.
		results = append(results, report.Result{
			ID:       "dnssec.chain",
			Category: category,
			Title:    "DNSKEY lookup failed",
			Status:   report.Warn,
			Evidence: keyErr.Error(),
			RFCRefs:  []string{"RFC 4034 §2"},
		})
		return results
	}

	// DS-to-DNSKEY linkage: every DS must reference a published KSK by its
	// computed digest. RFC 4034 §5.2 / RFC 4509 (SHA-256) / RFC 4034 §5.1.4.
	matchedAny := false
	for _, ds := range dsSet {
		if matchDS(ds, keySet) {
			matchedAny = true
			break
		}
	}
	if !matchedAny {
		results = append(results, report.Result{
			ID:       "dnssec.chain",
			Category: category,
			Title:    "No DS record matches any published DNSKEY",
			Status:   report.Fail,
			Evidence: fmt.Sprintf("DS keytags=%s, DNSKEY keytags=%s",
				dsKeyTags(dsSet), dnskeyKeyTags(keySet)),
			Remediation: "# Re-publish a DS that matches your current KSK, or roll the KSK\n" +
				"# through a proper KSK rollover (RFC 6781 §4.1).",
			RFCRefs: []string{"RFC 4034 §5", "RFC 4509", "RFC 6781 §4.1"},
		})
		// Continue — we still want to report on RRSIG presence/expiry below.
	}

	// RRSIG over DNSKEY RRset — the SEP key signs DNSKEY and the ZSK signs
	// the rest. Per RFC 4035 §2.2 a signed zone MUST publish RRSIG(DNSKEY).
	keyRRSIGs := extractRRSIGCovering(keyResp, mdns.TypeDNSKEY)
	if len(keyRRSIGs) == 0 {
		results = append(results, report.Result{
			ID:       "dnssec.chain",
			Category: category,
			Title:    "DNSKEY RRset has no RRSIG",
			Status:   report.Fail,
			Evidence: "expected at least one RRSIG over the DNSKEY RRset",
			Remediation: "# Re-sign the zone. Most DNS providers regenerate RRSIGs\n" +
				"# automatically; if yours does not, trigger a re-sign.",
			RFCRefs: []string{"RFC 4035 §2.2"},
		})
	} else {
		evalRRSIG(keyRRSIGs, keySet, asRRSet(keyResp.Answer, mdns.TypeDNSKEY), "DNSKEY", &results)
	}

	// RRSIG over SOA — confirms the ZSK is actively signing the zone.
	soaResp, soaErr := env.DNS.ExchangeWithDO(cctx, env.Target, mdns.TypeSOA)
	if soaErr != nil {
		results = append(results, report.Result{
			ID:       "dnssec.chain",
			Category: category,
			Title:    "SOA lookup failed",
			Status:   report.Warn,
			Evidence: soaErr.Error(),
			RFCRefs:  []string{"RFC 4035 §3"},
		})
		return results
	}
	soaRRSIGs := extractRRSIGCovering(soaResp, mdns.TypeSOA)
	if len(soaRRSIGs) == 0 {
		results = append(results, report.Result{
			ID:          "dnssec.chain",
			Category:    category,
			Title:       "SOA RRset has no RRSIG",
			Status:      report.Fail,
			Evidence:    "expected at least one RRSIG over the SOA RRset",
			Remediation: "# Re-sign the zone so the SOA carries a valid RRSIG.",
			RFCRefs:     []string{"RFC 4035 §2.2"},
		})
	} else {
		evalRRSIG(soaRRSIGs, keySet, asRRSet(soaResp.Answer, mdns.TypeSOA), "SOA", &results)
	}

	return results
}

// evalRRSIG appends Pass/Warn/Fail results for a set of RRSIGs covering a
// specific RRset. We check three things, in order:
//  1. validity period (RFC 4034 §3.1.5)
//  2. that the signing DNSKEY is published in the zone
//  3. cryptographic verification (RFC 4035 §5.3)
func evalRRSIG(sigs []*mdns.RRSIG, keys []*mdns.DNSKEY, rrset []mdns.RR, label string, out *[]report.Result) {
	now := time.Now().UTC()
	var verifiedBy *mdns.DNSKEY
	var lastErr error
	expired := 0
	unknownKey := 0

	for _, sig := range sigs {
		if !sig.ValidityPeriod(now) {
			expired++
			continue
		}
		key := findKey(keys, sig.KeyTag, sig.Algorithm)
		if key == nil {
			unknownKey++
			continue
		}
		// rrset may be nil if we never received the answer; skip verify in
		// that case but still report presence.
		if len(rrset) == 0 {
			verifiedBy = key
			break
		}
		if err := sig.Verify(key, rrset); err != nil {
			lastErr = err
			continue
		}
		verifiedBy = key
		break
	}

	if verifiedBy != nil {
		*out = append(*out, report.Result{
			ID:       "dnssec.chain",
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s verifies", label),
			Status:   report.Pass,
			Evidence: fmt.Sprintf("signed by DNSKEY keytag=%d alg=%s",
				verifiedBy.KeyTag(), mdns.AlgorithmToString[verifiedBy.Algorithm]),
			RFCRefs: []string{"RFC 4034 §3", "RFC 4035 §5.3"},
		})
		return
	}

	switch {
	case expired > 0:
		*out = append(*out, report.Result{
			ID:       "dnssec.chain",
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s is expired", label),
			Status:   report.Fail,
			Evidence: fmt.Sprintf("%d expired RRSIG(s); current time outside [inception, expiration]", expired),
			Remediation: "# Re-sign the zone immediately. Validating resolvers treat\n" +
				"# expired signatures as bogus and will return SERVFAIL.",
			RFCRefs: []string{"RFC 4034 §3.1.5"},
		})
	case unknownKey > 0:
		*out = append(*out, report.Result{
			ID:       "dnssec.chain",
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s signed by unknown DNSKEY", label),
			Status:   report.Fail,
			Evidence: fmt.Sprintf("%d RRSIG(s) reference a key tag not present in the DNSKEY RRset", unknownKey),
			Remediation: "# Either publish the missing DNSKEY or remove stale RRSIGs;\n" +
				"# typically caused by an interrupted ZSK rollover.",
			RFCRefs: []string{"RFC 4035 §5.3.1", "RFC 6781 §4.1"},
		})
	case lastErr != nil:
		*out = append(*out, report.Result{
			ID:       "dnssec.chain",
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s failed cryptographic verification", label),
			Status:   report.Fail,
			Evidence: lastErr.Error(),
			Remediation: "# Re-sign the zone. The RRSIG bytes do not validate against\n" +
				"# the published DNSKEY; the zone is bogus to validating resolvers.",
			RFCRefs: []string{"RFC 4035 §5.3"},
		})
	}
}

func extractDS(m *mdns.Msg) []*mdns.DS {
	if m == nil {
		return nil
	}
	var out []*mdns.DS
	for _, rr := range m.Answer {
		if d, ok := rr.(*mdns.DS); ok {
			out = append(out, d)
		}
	}
	return out
}

func extractDNSKEY(m *mdns.Msg) []*mdns.DNSKEY {
	if m == nil {
		return nil
	}
	var out []*mdns.DNSKEY
	for _, rr := range m.Answer {
		if k, ok := rr.(*mdns.DNSKEY); ok {
			out = append(out, k)
		}
	}
	return out
}

func extractRRSIGCovering(m *mdns.Msg, t uint16) []*mdns.RRSIG {
	if m == nil {
		return nil
	}
	var out []*mdns.RRSIG
	for _, rr := range m.Answer {
		if s, ok := rr.(*mdns.RRSIG); ok && s.TypeCovered == t {
			out = append(out, s)
		}
	}
	return out
}

// asRRSet returns the answer records of type t as an []mdns.RR — what
// RRSIG.Verify expects. Excludes the RRSIGs themselves.
func asRRSet(rrs []mdns.RR, t uint16) []mdns.RR {
	var out []mdns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			out = append(out, rr)
		}
	}
	return out
}

func findKey(keys []*mdns.DNSKEY, keyTag uint16, alg uint8) *mdns.DNSKEY {
	for _, k := range keys {
		if k.Algorithm == alg && k.KeyTag() == keyTag {
			return k
		}
	}
	return nil
}

// matchDS returns true if any DNSKEY hashes to the given DS. We compute the
// digest with miekg/dns's ToDS so the comparison is constant-folded against
// the same algorithm encoding the resolver returned.
func matchDS(ds *mdns.DS, keys []*mdns.DNSKEY) bool {
	for _, k := range keys {
		// SEP bit: only KSKs are supposed to be referenced by DS, but in the
		// wild some zones use a single combined-signing key, so we don't
		// require flags&SEP == SEP.
		if k.Algorithm != ds.Algorithm {
			continue
		}
		computed := k.ToDS(ds.DigestType)
		if computed == nil {
			continue
		}
		if strings.EqualFold(computed.Digest, ds.Digest) && computed.KeyTag == ds.KeyTag {
			return true
		}
	}
	return false
}

func dsKeyTags(dss []*mdns.DS) string {
	var parts []string
	for _, d := range dss {
		parts = append(parts, fmt.Sprintf("%d/%s", d.KeyTag, mdns.HashToString[d.DigestType]))
	}
	return strings.Join(parts, ",")
}

func dnskeyKeyTags(keys []*mdns.DNSKEY) string {
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d/%s", k.KeyTag(), mdns.AlgorithmToString[k.Algorithm]))
	}
	return strings.Join(parts, ",")
}
