package dnssec

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// Result IDs of the chain check: whether the zone is signed, then one result
// for each RRset the chain authenticates.
const (
	idSigned      = "dnssec.signed"
	idDSMatch     = "dnssec.chain.ds_match"
	idDNSKEYRRSIG = "dnssec.chain.dnskey_rrsig"
	idSOARRSIG    = "dnssec.chain.soa_rrsig"
)

// runChain audits the DS-DNSKEY-RRSIG chain at the target's apex.
//
// We rely on a recursive resolver to fetch the parent's DS records (the
// resolver walks the delegation), so a single DS query against the apex
// name is sufficient for our purposes. The DS+DNSKEY artefacts are
// produced once per run via ensureChainData and shared with the algorithms,
// nsec and cds checks; under the parallel registry whichever check runs first
// populates the cache.
func runChain(ctx context.Context, env *probe.Env) []report.Result {
	cd := ensureChainData(ctx, env)
	signed := signedResult(env.Target, cd)
	if signed.Status != report.Pass {
		return []report.Result{signed}
	}
	now := time.Now()
	linked := dsLinkedKeys(cd.dsSet, cd.keySet)
	return []report.Result{
		signed,
		dsMatchResult(cd.dsSet, cd.keySet, linked),
		dnskeyRRSIGResult(cd.keyResp, cd.keySet, linked, now),
		soaRRSIGResult(ctx, env, cd.keySet, now),
	}
}

// signedResult reports whether the parent publishes DS records and the apex
// DNSKEY records. Only a PASS, both published, lets the chain be followed; a
// failed lookup is inconclusive rather than a verdict on the zone.
func signedResult(target string, cd *chainData) report.Result {
	switch {
	case cd.dsErr != nil:
		return checkutil.Inconclusive(report.Result{
			ID:       idSigned,
			Category: category,
			Title:    "DS lookup failed",
			RFCRefs:  []string{"RFC 4034 §5", "RFC 3658"},
		}, cd.dsErr)
	case cd.keyErr != nil:
		return checkutil.Inconclusive(report.Result{
			ID:       idSigned,
			Category: category,
			Title:    "DNSKEY lookup failed",
			RFCRefs:  []string{"RFC 4034 §2"},
		}, cd.keyErr)
	case len(cd.dsSet) == 0 && len(cd.keySet) == 0:
		// Unsigned domain: DNSSEC is opt-in, so this is Info, not Fail.
		return report.Result{
			ID:       idSigned,
			Category: category,
			Title:    "Domain is not DNSSEC-signed",
			Status:   report.Info,
			Evidence: "no DS records at parent; no DNSKEY records at apex",
			Remediation: "# At your DNS provider, enable DNSSEC and publish the resulting DS\n" +
				"# record at your registrar. Example after generation:\n" +
				target + ". IN DS 12345 13 2 ABCDEF1234... ; KSK SHA-256",
			RFCRefs: []string{"RFC 4033", "RFC 4034", "RFC 3658"},
		}
	case len(cd.dsSet) == 0:
		// Lame DNSSEC: child is signed but parent has no DS — chain is broken
		// and validating resolvers will treat the zone as bogus.
		return report.Result{
			ID:       idSigned,
			Category: category,
			Title:    "Zone publishes DNSKEY but parent has no DS (lame DNSSEC)",
			Status:   report.Fail,
			Evidence: fmt.Sprintf("DNSKEY count=%d, DS count=0", len(cd.keySet)),
			Remediation: "# Generate a DS record from your KSK and submit it to your registrar.\n" +
				"# Most provider control panels offer a copy-paste DS string.",
			RFCRefs: []string{"RFC 4035 §5", "RFC 3658 §2.4"},
		}
	case len(cd.keySet) == 0:
		// Inverse: DS at parent but no DNSKEY at child — also broken.
		return report.Result{
			ID:       idSigned,
			Category: category,
			Title:    "Parent has DS but zone does not publish DNSKEY (broken chain)",
			Status:   report.Fail,
			Evidence: fmt.Sprintf("DS count=%d, DNSKEY count=0", len(cd.dsSet)),
			Remediation: "# Either publish the matching DNSKEY records at the apex or have\n" +
				"# the registrar remove the stale DS records.",
			RFCRefs: []string{"RFC 4035 §2.2", "RFC 4035 §5"},
		}
	}
	return report.Result{
		ID:       idSigned,
		Category: category,
		Title:    "Domain is DNSSEC-signed (DS at parent, DNSKEY at apex)",
		Status:   report.Pass,
		Evidence: fmt.Sprintf("DS count=%d, DNSKEY count=%d", len(cd.dsSet), len(cd.keySet)),
		RFCRefs:  []string{"RFC 4034", "RFC 4035"},
	}
}

// dsMatchResult reports whether a DS record at the parent references a
// published zone key (RFC 4034 §5.2, RFC 4509).
func dsMatchResult(dsSet []*mdns.DS, keys, linked []*mdns.DNSKEY) report.Result {
	if len(linked) == 0 {
		return report.Result{
			ID:       idDSMatch,
			Category: category,
			Title:    "No DS record matches any published DNSKEY",
			Status:   report.Fail,
			Evidence: fmt.Sprintf("DS keytags=%s, DNSKEY keytags=%s; a DS must match a zone key "+
				"(ZONE flag set) by algorithm, key tag and digest",
				dsKeyTags(dsSet), dnskeyKeyTags(keys)),
			Remediation: "# Re-publish a DS that matches your current KSK, or roll the KSK\n" +
				"# through a proper KSK rollover (RFC 6781 §4.1).",
			RFCRefs: []string{"RFC 4034 §5", "RFC 4509", "RFC 6781 §4.1"},
		}
	}
	return report.Result{
		ID:       idDSMatch,
		Category: category,
		Title:    "DS at the parent matches a published DNSKEY",
		Status:   report.Pass,
		Evidence: fmt.Sprintf("DS keytags=%s; matching DNSKEY keytags=%s",
			dsKeyTags(dsSet), dnskeyKeyTags(linked)),
		RFCRefs: []string{"RFC 4034 §5", "RFC 4035 §5.2"},
	}
}

// dnskeyRRSIGResult judges the RRSIGs over the apex DNSKEY RRset. Validators
// authenticate that RRset only through a key a DS references (RFC 4035
// §5.2), so when such a key exists, only its signatures count. When none
// does, ds_match has already failed and the signatures are judged on their
// own.
func dnskeyRRSIGResult(
	keyResp *mdns.Msg, keys, linked []*mdns.DNSKEY, now time.Time,
) report.Result {
	c := sigCheck{
		id:     idDNSKEYRRSIG,
		label:  "DNSKEY",
		signer: "DNSKEY",
		rrset:  asRRSet(keyResp.Answer, mdns.TypeDNSKEY),
		sigs:   extractRRSIGCovering(keyResp, mdns.TypeDNSKEY),
		keys:   keys,
	}
	if len(linked) == 0 || len(c.sigs) == 0 {
		return c.result(now)
	}
	linkedSigs := sigsByKeys(c.sigs, linked)
	if len(linkedSigs) == 0 {
		return report.Result{
			ID:       idDNSKEYRRSIG,
			Category: category,
			Title:    "DNSKEY RRset is not signed by a DS-referenced key",
			Status:   report.Fail,
			Evidence: fmt.Sprintf("RRSIG keytags=%s; DS-referenced DNSKEY keytags=%s",
				rrsigKeyTags(c.sigs), dnskeyKeyTags(linked)),
			Remediation: "# Sign the DNSKEY RRset with the key the parent's DS references\n" +
				"# (usually the KSK), or publish a DS for the key that signs it.",
			RFCRefs: []string{"RFC 4035 §5.2", "RFC 6781 §4.1"},
		}
	}
	c.sigs, c.keys, c.signer = linkedSigs, linked, "DS-referenced DNSKEY"
	return c.result(now)
}

// soaRRSIGResult judges the RRSIGs over the apex SOA RRset, which show that
// the zone's keys are signing its data.
func soaRRSIGResult(
	ctx context.Context, env *probe.Env, keys []*mdns.DNSKEY, now time.Time,
) report.Result {
	resp, err := queryApexCD(ctx, env, mdns.TypeSOA)
	if err != nil {
		return checkutil.Inconclusive(report.Result{
			ID:       idSOARRSIG,
			Category: category,
			Title:    "SOA lookup failed",
			RFCRefs:  []string{"RFC 4035 §3"},
		}, err)
	}
	return sigCheck{
		id:     idSOARRSIG,
		label:  "SOA",
		signer: "DNSKEY",
		rrset:  asRRSet(resp.Answer, mdns.TypeSOA),
		sigs:   extractRRSIGCovering(resp, mdns.TypeSOA),
		keys:   keys,
	}.result(now)
}

// sigCheck is an RRset whose RRSIGs the chain check judges, and the keys
// allowed to have made them.
type sigCheck struct {
	id     string // result ID
	label  string // RR type of the RRset, e.g. "SOA"
	signer string // how the evidence names a key, e.g. "DS-referenced DNSKEY"
	rrset  []mdns.RR
	sigs   []*mdns.RRSIG
	keys   []*mdns.DNSKEY
}

// result is PASS when one of the RRSIGs is current, was made by one of the
// keys and verifies over the RRset; otherwise it says why none does.
func (c sigCheck) result(now time.Time) report.Result {
	switch {
	case len(c.sigs) == 0:
		return report.Result{
			ID:       c.id,
			Category: category,
			Title:    fmt.Sprintf("%s RRset has no RRSIG", c.label),
			Status:   report.Fail,
			Evidence: fmt.Sprintf("expected at least one RRSIG over the %s RRset", c.label),
			Remediation: "# Re-sign the zone. Most DNS providers regenerate RRSIGs\n" +
				"# automatically; if yours does not, trigger a re-sign.",
			RFCRefs: []string{"RFC 4035 §2.2"},
		}
	case len(c.rrset) == 0:
		// Nothing to verify the RRSIGs over, so they prove nothing; only a
		// broken or tampered resolution path answers like this.
		return report.Result{
			ID:       c.id,
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s present without the %s RRset", c.label, c.label),
			Status:   report.Warn,
			Evidence: fmt.Sprintf("the answer carried %d RRSIG(s) over %s but no %s record "+
				"to verify them against", len(c.sigs), c.label, c.label),
			RFCRefs: []string{"RFC 4035 §5.3"},
		}
	}
	return c.verdict(tallySigs(c.sigs, c.keys, c.rrset, now), now)
}

// sigTally sorts RRSIGs by why they do or do not verify.
type sigTally struct {
	verifiedBy  *mdns.DNSKEY
	expired     []*mdns.RRSIG
	notYetValid []*mdns.RRSIG
	unknownKey  int
	verifyErr   error // the last signature that failed to verify
}

// tallySigs checks each RRSIG in turn until one verifies: its validity period
// (RFC 4034 §3.1.5), that one of keys made it, then the signature itself
// (RFC 4035 §5.3).
func tallySigs(
	sigs []*mdns.RRSIG, keys []*mdns.DNSKEY, rrset []mdns.RR, now time.Time,
) sigTally {
	var t sigTally
	for _, sig := range sigs {
		key := findKey(keys, sig.KeyTag, sig.Algorithm)
		switch {
		case notYetValid(sig, now):
			t.notYetValid = append(t.notYetValid, sig)
		case !sig.ValidityPeriod(now):
			t.expired = append(t.expired, sig)
		case key == nil:
			t.unknownKey++
		default:
			if err := sig.Verify(key, rrset); err != nil {
				t.verifyErr = err
				continue
			}
			t.verifiedBy = key
			return t
		}
	}
	return t
}

// notYetValid reports whether sig's inception is after now, compared in RFC
// 1982 serial arithmetic as RFC 4034 §3.1.5 requires.
func notYetValid(sig *mdns.RRSIG, now time.Time) bool {
	return int32(sig.Inception-uint32(now.Unix())) > 0
}

// verdict turns the tally of a non-empty set of RRSIGs into the result.
func (c sigCheck) verdict(t sigTally, now time.Time) report.Result {
	switch {
	case t.verifiedBy != nil:
		return report.Result{
			ID:       c.id,
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s verifies", c.label),
			Status:   report.Pass,
			Evidence: fmt.Sprintf("signed by %s keytag=%d alg=%s", c.signer,
				t.verifiedBy.KeyTag(), mdns.AlgorithmToString[t.verifiedBy.Algorithm]),
			RFCRefs: []string{"RFC 4034 §3", "RFC 4035 §5.3"},
		}
	case len(t.expired) > 0:
		return report.Result{
			ID:       c.id,
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s is expired", c.label),
			Status:   report.Fail,
			Evidence: c.validityEvidence("expired", t.expired, now),
			Remediation: "# Re-sign the zone immediately. Validating resolvers treat\n" +
				"# expired signatures as bogus and will return SERVFAIL.",
			RFCRefs: []string{"RFC 4034 §3.1.5"},
		}
	case len(t.notYetValid) > 0:
		return report.Result{
			ID:       c.id,
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s is not yet valid", c.label),
			Status:   report.Fail,
			Evidence: c.validityEvidence("not yet valid", t.notYetValid, now),
			Remediation: "# Check the signer's clock and re-sign the zone. Validating resolvers\n" +
				"# treat a signature used before its inception time as bogus.",
			RFCRefs: []string{"RFC 4034 §3.1.5"},
		}
	case t.unknownKey > 0:
		return report.Result{
			ID:       c.id,
			Category: category,
			Title:    fmt.Sprintf("RRSIG over %s signed by unknown DNSKEY", c.label),
			Status:   report.Fail,
			Evidence: fmt.Sprintf("%d RRSIG(s) reference a key tag not present in the "+
				"DNSKEY RRset", t.unknownKey),
			Remediation: "# Either publish the missing DNSKEY or remove stale RRSIGs;\n" +
				"# typically caused by an interrupted ZSK rollover.",
			RFCRefs: []string{"RFC 4035 §5.3.1", "RFC 6781 §4.1"},
		}
	}
	return report.Result{
		ID:       c.id,
		Category: category,
		Title:    fmt.Sprintf("RRSIG over %s failed cryptographic verification", c.label),
		Status:   report.Fail,
		Evidence: t.verifyErr.Error(),
		Remediation: "# Re-sign the zone. The RRSIG bytes do not validate against\n" +
			"# the published DNSKEY; the zone is bogus to validating resolvers.",
		RFCRefs: []string{"RFC 4035 §5.3"},
	}
}

// validityEvidence counts sigs, which share a validity problem described by
// state, and shows the first one's validity period against now.
func (c sigCheck) validityEvidence(state string, sigs []*mdns.RRSIG, now time.Time) string {
	first := sigs[0]
	return fmt.Sprintf("%d RRSIG(s) %s; RRSIG by %s keytag=%d is valid from %s to %s, now %s",
		len(sigs), state, c.signer, first.KeyTag, rrsigTime(first.Inception),
		rrsigTime(first.Expiration), now.UTC().Format(time.RFC3339))
}

// rrsigTime formats an RRSIG inception or expiration time.
func rrsigTime(t uint32) string {
	return time.Unix(int64(t), 0).UTC().Format(time.RFC3339)
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

// sigsByKeys returns the RRSIGs whose key tag and algorithm name one of keys.
func sigsByKeys(sigs []*mdns.RRSIG, keys []*mdns.DNSKEY) []*mdns.RRSIG {
	var out []*mdns.RRSIG
	for _, sig := range sigs {
		if findKey(keys, sig.KeyTag, sig.Algorithm) != nil {
			out = append(out, sig)
		}
	}
	return out
}

// dsLinkedKeys returns the zone keys (ZONE flag set) that a DS record matches
// by algorithm, key tag and digest: the only keys that can authenticate the
// apex DNSKEY RRset (RFC 4035 §5.2). The SEP flag is not required, since some
// zones sign everything with one combined key.
func dsLinkedKeys(dsSet []*mdns.DS, keys []*mdns.DNSKEY) []*mdns.DNSKEY {
	var linked []*mdns.DNSKEY
	for _, k := range keys {
		matches := func(ds *mdns.DS) bool { return dsMatchesKey(ds, k) }
		if k.Flags&mdns.ZONE != 0 && slices.ContainsFunc(dsSet, matches) {
			linked = append(linked, k)
		}
	}
	return linked
}

// dsMatchesKey reports whether ds is the digest of k (RFC 4034 §5.1.4),
// computed with miekg/dns's ToDS.
func dsMatchesKey(ds *mdns.DS, k *mdns.DNSKEY) bool {
	if k.Algorithm != ds.Algorithm {
		return false
	}
	computed := k.ToDS(ds.DigestType)
	return computed != nil && computed.KeyTag == ds.KeyTag &&
		strings.EqualFold(computed.Digest, ds.Digest)
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

func rrsigKeyTags(sigs []*mdns.RRSIG) string {
	var parts []string
	for _, s := range sigs {
		parts = append(parts, fmt.Sprintf("%d/%s", s.KeyTag, mdns.AlgorithmToString[s.Algorithm]))
	}
	return strings.Join(parts, ",")
}
