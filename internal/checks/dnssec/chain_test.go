package dnssec

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// chainZone is the zone the chain tests sign and serve.
const chainZone = "example.test."

// zoneKey is a DNSKEY of chainZone and its private key.
type zoneKey struct {
	key  *mdns.DNSKEY
	priv ed25519.PrivateKey
}

// newZoneKey derives a chainZone key with flags from seed, so key tags are
// the same on every run.
func newZoneKey(seed uint64, flags uint16) zoneKey {
	k, priv := testKey(seed, flags)
	k.Hdr.Name = chainZone
	return zoneKey{key: k, priv: priv}
}

// validity is the period an RRSIG is valid for.
type validity struct{ inception, expiration time.Time }

// sign returns k's RRSIG over rrset.
func (k zoneKey) sign(t *testing.T, rrset []mdns.RR, v validity) mdns.RR {
	t.Helper()
	sig := &mdns.RRSIG{
		Hdr:        mdns.RR_Header{Ttl: 3600},
		Algorithm:  k.key.Algorithm,
		SignerName: chainZone,
		KeyTag:     k.key.KeyTag(),
		Inception:  uint32(v.inception.Unix()),
		Expiration: uint32(v.expiration.Unix()),
	}
	if err := sig.Sign(k.priv, rrset); err != nil {
		t.Fatalf("sign with key %d: %v", k.key.KeyTag(), err)
	}
	return sig
}

// ds returns the parent's SHA-256 DS record for k.
func (k zoneKey) ds() mdns.RR {
	return k.key.ToDS(mdns.SHA256)
}

// signedZone holds the keys and validity periods the chain cases sign with:
// a KSK that the parent's DS references and a ZSK that signs the zone data.
type signedZone struct {
	t                       *testing.T
	ksk, zsk                zoneKey
	valid, expired, pending validity
}

func newSignedZone(t *testing.T) signedZone {
	t.Helper()
	now := time.Now()
	z := signedZone{
		t:       t,
		ksk:     newZoneKey(101, mdns.ZONE|mdns.SEP),
		zsk:     newZoneKey(102, mdns.ZONE),
		valid:   validity{now.Add(-time.Hour), now.Add(24 * time.Hour)},
		expired: validity{now.Add(-48 * time.Hour), now.Add(-24 * time.Hour)},
		pending: validity{now.Add(24 * time.Hour), now.Add(48 * time.Hour)},
	}
	if z.ksk.key.KeyTag() == z.zsk.key.KeyTag() {
		t.Fatalf("KSK and ZSK share key tag %d", z.ksk.key.KeyTag())
	}
	return z
}

// keys returns the zone's DNSKEY RRset: the KSK and the ZSK.
func (z signedZone) keys() []mdns.RR {
	return []mdns.RR{z.ksk.key, z.zsk.key}
}

// keySigs returns an RRSIG over the DNSKEY RRset by each of signers.
func (z signedZone) keySigs(v validity, signers ...zoneKey) []mdns.RR {
	var out []mdns.RR
	for _, k := range signers {
		out = append(out, k.sign(z.t, z.keys(), v))
	}
	return out
}

// soa returns the SOA RRset and the ZSK's current RRSIG over it.
func (z signedZone) soa() []mdns.RR {
	soa := []mdns.RR{&mdns.SOA{
		Hdr:     mdns.RR_Header{Name: chainZone, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET},
		Ns:      "ns1." + chainZone,
		Mbox:    "hostmaster." + chainZone,
		Serial:  1,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}}
	return append(soa, z.zsk.sign(z.t, soa, z.valid))
}

// healthy returns the records of a zone whose DS references the KSK, whose
// KSK signs the DNSKEY RRset and whose ZSK signs the SOA, plus extra.
func (z signedZone) healthy(extra ...mdns.RR) []mdns.RR {
	return slices.Concat([]mdns.RR{z.ksk.ds()}, z.keys(), z.keySigs(z.valid, z.ksk), z.soa(), extra)
}

// zoneResolver is a recursive resolver serving rrs, the records of
// chainZone. It answers a query for chainZone with the records of the asked
// type, plus their RRSIGs when DO is set; other names are NXDOMAIN. With
// bogus set it SERVFAILs every query without CD, as a validating resolver
// does for a zone that fails validation. rcode overrides the rcode by query
// type, silent types are never answered, and every answer waits delay.
type zoneResolver struct {
	rrs    []mdns.RR
	bogus  bool
	rcode  map[uint16]int
	silent map[uint16]bool
	delay  time.Duration

	mu      sync.Mutex
	queries map[uint16]int // queries received by type
}

func (z *zoneResolver) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	q := req.Question[0]
	z.mu.Lock()
	if z.queries == nil {
		z.queries = map[uint16]int{}
	}
	z.queries[q.Qtype]++
	z.mu.Unlock()
	if z.silent[q.Qtype] {
		return
	}
	time.Sleep(z.delay)
	resp := new(mdns.Msg)
	resp.SetRcode(req, z.rcodeFor(req))
	if resp.Rcode == mdns.RcodeSuccess {
		opt := req.IsEdns0()
		resp.Answer = z.answer(q.Qtype, opt != nil && opt.Do())
	}
	_ = w.WriteMsg(resp)
}

func (z *zoneResolver) rcodeFor(req *mdns.Msg) int {
	q := req.Question[0]
	rcode, overridden := z.rcode[q.Qtype]
	switch {
	case overridden:
		return rcode
	case z.bogus && !req.CheckingDisabled:
		return mdns.RcodeServerFailure
	case !strings.EqualFold(q.Name, chainZone):
		return mdns.RcodeNameError
	}
	return mdns.RcodeSuccess
}

func (z *zoneResolver) answer(qtype uint16, do bool) []mdns.RR {
	var out []mdns.RR
	for _, rr := range z.rrs {
		sig, isSig := rr.(*mdns.RRSIG)
		if rr.Header().Rrtype == qtype || (do && isSig && sig.TypeCovered == qtype) {
			out = append(out, rr)
		}
	}
	return out
}

// count returns how many queries of type qtype z has received.
func (z *zoneResolver) count(qtype uint16) int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.queries[qtype]
}

// serveZone starts z and returns an Env for chainZone that resolves through
// it, each query bounded by timeout.
func serveZone(t *testing.T, z *zoneResolver, timeout time.Duration) *probe.Env {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	return probe.NewEnv(strings.TrimSuffix(chainZone, "."), timeout, false, startFakeResolver(t, z))
}

// runChainOn serves z and returns the chain check's results.
func runChainOn(t *testing.T, z *zoneResolver) []report.Result {
	t.Helper()
	return runChain(context.Background(), serveZone(t, z, 2*time.Second))
}

// byID indexes results by ID and fails the test when an ID repeats.
func byID(t *testing.T, results []report.Result) map[string]report.Result {
	t.Helper()
	if err := report.CheckUniqueIDs(results); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]report.Result, len(results))
	for _, r := range results {
		out[r.ID] = r
	}
	return out
}

// want is a result's expected status and substrings of its title and
// evidence.
type want struct {
	status   report.Status
	title    string
	evidence string
}

// checkResults fails the test unless results hold exactly the IDs in wants,
// each as wanted (see checkResult).
func checkResults(t *testing.T, results []report.Result, wants map[string]want) {
	t.Helper()
	got := byID(t, results)
	for id, w := range wants {
		r, ok := got[id]
		if !ok {
			t.Errorf("no %s result in %+v", id, results)
			continue
		}
		checkResult(t, r, w)
	}
	if len(got) != len(wants) {
		t.Errorf("got %d results, want %d: %+v", len(got), len(wants), results)
	}
}

// checkResult fails the test unless r is as wanted. A FAIL must carry a
// remediation and an inconclusive result must not.
func checkResult(t *testing.T, r report.Result, w want) {
	t.Helper()
	if r.Status != w.status || !strings.Contains(r.Title, w.title) ||
		!strings.Contains(r.Evidence, w.evidence) {
		t.Errorf("%s = %s %q (%s), want %s with title %q and evidence %q",
			r.ID, r.Status, r.Title, r.Evidence, w.status, w.title, w.evidence)
	}
	inconclusive := strings.HasPrefix(r.Evidence, "could not determine: ")
	if (r.Status == report.Fail && r.Remediation == "") || (inconclusive && r.Remediation != "") {
		t.Errorf("%s = %s %q with remediation %q", r.ID, r.Status, r.Evidence, r.Remediation)
	}
}

// healthyChain is the chain check's report on a healthy zone.
var healthyChain = map[string]want{
	idSigned:      {report.Pass, "Domain is DNSSEC-signed", "DS count=1, DNSKEY count=2"},
	idDSMatch:     {report.Pass, "DS at the parent matches a published DNSKEY", ""},
	idDNSKEYRRSIG: {report.Pass, "RRSIG over DNSKEY verifies", "signed by DS-referenced DNSKEY"},
	idSOARRSIG:    {report.Pass, "RRSIG over SOA verifies", ""},
}

// chainWants returns healthyChain with overrides applied.
func chainWants(overrides map[string]want) map[string]want {
	out := maps.Clone(healthyChain)
	maps.Copy(out, overrides)
	return out
}

// TestRunChain checks the chain check's verdict on each RRset of signed
// zones, served by a fake resolver.
func TestRunChain(t *testing.T) {
	z := newSignedZone(t)
	ds := []mdns.RR{z.ksk.ds()}
	kskSigned := fmt.Sprintf("signed by DNSKEY keytag=%d", z.ksk.key.KeyTag())
	notZone := newZoneKey(103, mdns.SEP)          // a DNSKEY without the ZONE flag
	orphan := newZoneKey(104, mdns.ZONE|mdns.SEP) // a KSK the zone does not publish
	withNotZone := append(z.keys(), notZone.key)
	cases := []struct {
		name  string
		bogus bool        // served by a validating resolver
		rrs   [][]mdns.RR // the zone's records
		wants map[string]want
	}{
		{
			name:  "valid chain",
			rrs:   [][]mdns.RR{z.healthy()},
			wants: healthyChain,
		},
		{
			name: "DNSKEY RRset signed only by a key without a DS",
			rrs:  [][]mdns.RR{ds, z.keys(), z.keySigs(z.valid, z.zsk), z.soa()},
			wants: chainWants(map[string]want{idDNSKEYRRSIG: {report.Fail,
				"DNSKEY RRset is not signed by a DS-referenced key",
				fmt.Sprintf("RRSIG keytags=%d/ED25519", z.zsk.key.KeyTag())}}),
		},
		{
			name: "DS-referenced key's RRSIG expired, another key's current",
			rrs: [][]mdns.RR{ds, z.keys(), z.keySigs(z.expired, z.ksk),
				z.keySigs(z.valid, z.zsk), z.soa()},
			wants: chainWants(map[string]want{idDNSKEYRRSIG: {report.Fail,
				"RRSIG over DNSKEY is expired",
				"1 RRSIG(s) expired; RRSIG by DS-referenced DNSKEY"}}),
		},
		{
			name: "RRSIG inception in the future",
			rrs:  [][]mdns.RR{ds, z.keys(), z.keySigs(z.pending, z.ksk), z.soa()},
			wants: chainWants(map[string]want{idDNSKEYRRSIG: {report.Fail,
				"RRSIG over DNSKEY is not yet valid", "1 RRSIG(s) not yet valid"}}),
		},
		{
			name: "DNSKEY RRset without RRSIG",
			rrs:  [][]mdns.RR{ds, z.keys(), z.soa()},
			wants: chainWants(map[string]want{idDNSKEYRRSIG: {report.Fail,
				"DNSKEY RRset has no RRSIG", ""}}),
		},
		{
			name: "RRSIG over SOA without the SOA RRset",
			rrs:  [][]mdns.RR{ds, z.keys(), z.keySigs(z.valid, z.ksk), sigsOf(z.soa())},
			wants: chainWants(map[string]want{idSOARRSIG: {report.Warn,
				"RRSIG over SOA present without the SOA RRset", "1 RRSIG(s) over SOA"}}),
		},
		{
			name: "DS references a key without the ZONE flag",
			rrs: [][]mdns.RR{{notZone.ds()}, withNotZone,
				{z.ksk.sign(t, withNotZone, z.valid)}, z.soa()},
			wants: chainWants(map[string]want{
				idSigned:      {report.Pass, "Domain is DNSSEC-signed", "DNSKEY count=3"},
				idDSMatch:     {report.Fail, "No DS record matches", "ZONE flag"},
				idDNSKEYRRSIG: {report.Pass, "RRSIG over DNSKEY verifies", kskSigned},
			}),
		},
		{
			name:  "bogus zone behind a validating resolver",
			bogus: true,
			rrs:   [][]mdns.RR{{orphan.ds()}, z.keys(), z.keySigs(z.valid, z.ksk), z.soa()},
			wants: chainWants(map[string]want{
				idDSMatch:     {report.Fail, "No DS record matches", ""},
				idDNSKEYRRSIG: {report.Pass, "RRSIG over DNSKEY verifies", kskSigned},
			}),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			zone := &zoneResolver{bogus: c.bogus, rrs: slices.Concat(c.rrs...)}
			checkResults(t, runChainOn(t, zone), c.wants)
		})
	}
}

// TestRunChainBrokenChains checks the FAIL verdicts for a chain broken
// between the parent and the zone, or at the RRSIG over the SOA.
func TestRunChainBrokenChains(t *testing.T) {
	z := newSignedZone(t)
	ds := []mdns.RR{z.ksk.ds()}
	orphan := newZoneKey(104, mdns.ZONE|mdns.SEP) // a KSK the zone does not publish
	soaSet := z.soa()[:1]                         // the SOA record without its RRSIG
	cases := []struct {
		name  string
		rrs   [][]mdns.RR // the zone's records
		wants map[string]want
	}{
		{
			name: "DNSKEY published without a DS at the parent",
			rrs:  [][]mdns.RR{z.keys(), z.keySigs(z.valid, z.ksk), z.soa()},
			wants: map[string]want{idSigned: {report.Fail,
				"Zone publishes DNSKEY but parent has no DS", "DNSKEY count=2, DS count=0"}},
		},
		{
			name: "DS at the parent without a DNSKEY",
			rrs:  [][]mdns.RR{ds, z.soa()},
			wants: map[string]want{idSigned: {report.Fail,
				"Parent has DS but zone does not publish DNSKEY", "DS count=1, DNSKEY count=0"}},
		},
		{
			name: "RRSIG over SOA by a key the zone does not publish",
			rrs: [][]mdns.RR{ds, z.keys(), z.keySigs(z.valid, z.ksk), soaSet,
				{orphan.sign(t, soaSet, z.valid)}},
			wants: chainWants(map[string]want{idSOARRSIG: {report.Fail,
				"RRSIG over SOA signed by unknown DNSKEY",
				"1 RRSIG(s) reference a key tag not present in the DNSKEY RRset"}}),
		},
		{
			name: "RRSIG over SOA with a corrupted signature",
			rrs: [][]mdns.RR{ds, z.keys(), z.keySigs(z.valid, z.ksk), soaSet,
				{corrupted(t, z.zsk.sign(t, soaSet, z.valid))}},
			wants: chainWants(map[string]want{idSOARRSIG: {report.Fail,
				"RRSIG over SOA failed cryptographic verification", "bad signature"}}),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			zone := &zoneResolver{rrs: slices.Concat(c.rrs...)}
			checkResults(t, runChainOn(t, zone), c.wants)
		})
	}
}

// corrupted returns a copy of rr, an RRSIG, with its first signature byte
// flipped.
func corrupted(t *testing.T, rr mdns.RR) mdns.RR {
	t.Helper()
	sig := mdns.Copy(rr).(*mdns.RRSIG)
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(raw) == 0 {
		t.Fatalf("decode RRSIG signature %q: %v", sig.Signature, err)
	}
	raw[0] ^= 0xff
	sig.Signature = base64.StdEncoding.EncodeToString(raw)
	return sig
}

// TestRunChainLookupFailures pins that a lookup the resolver could not
// answer makes the chain results inconclusive, while NXDOMAIN still reads as
// an empty answer.
func TestRunChainLookupFailures(t *testing.T) {
	z := newSignedZone(t)
	cases := []struct {
		name  string
		zone  *zoneResolver
		wants map[string]want
	}{
		{
			name: "DS SERVFAIL",
			zone: &zoneResolver{rrs: z.healthy(),
				rcode: map[uint16]int{mdns.TypeDS: mdns.RcodeServerFailure}},
			wants: map[string]want{idSigned: {report.Warn, "DS lookup failed",
				"could not determine: resolver answered SERVFAIL"}},
		},
		{
			name: "DNSKEY REFUSED",
			zone: &zoneResolver{rrs: z.healthy(),
				rcode: map[uint16]int{mdns.TypeDNSKEY: mdns.RcodeRefused}},
			wants: map[string]want{idSigned: {report.Warn, "DNSKEY lookup failed",
				"could not determine: resolver answered REFUSED"}},
		},
		{
			name: "DNSKEY unanswered",
			zone: &zoneResolver{rrs: z.healthy(), silent: map[uint16]bool{mdns.TypeDNSKEY: true}},
			wants: map[string]want{idSigned: {report.Warn, "DNSKEY lookup failed",
				"could not determine: "}},
		},
		{
			name: "SOA SERVFAIL",
			zone: &zoneResolver{rrs: z.healthy(),
				rcode: map[uint16]int{mdns.TypeSOA: mdns.RcodeServerFailure}},
			wants: chainWants(map[string]want{idSOARRSIG: {report.Warn, "SOA lookup failed",
				"could not determine: resolver answered SERVFAIL"}}),
		},
		{
			name: "NXDOMAIN",
			zone: &zoneResolver{rcode: map[uint16]int{
				mdns.TypeDS: mdns.RcodeNameError, mdns.TypeDNSKEY: mdns.RcodeNameError}},
			wants: map[string]want{idSigned: {report.Info, "Domain is not DNSSEC-signed", ""}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := runChain(context.Background(), serveZone(t, c.zone, time.Second))
			checkResults(t, res, c.wants)
		})
	}
}

// TestRunChainQueriesHaveOwnBudget pins that --timeout bounds each query on
// its own: DS and DNSKEY each answered within the timeout must both succeed
// even when together they take longer.
func TestRunChainQueriesHaveOwnBudget(t *testing.T) {
	z := newSignedZone(t)
	zone := &zoneResolver{rrs: z.healthy(), delay: 600 * time.Millisecond}

	res := runChain(context.Background(), serveZone(t, zone, time.Second))

	checkResults(t, res, healthyChain)
}
