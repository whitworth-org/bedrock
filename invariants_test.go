// invariants_test.go checks properties every default scan must keep, with
// a fake resolver serving a zone built from the record shapes that once gave
// two results the same ID: each result ID is unique, each remediation is
// free of control characters, repeated runs give identical results, and
// skipping a category with registry.Options.Keep leaves the other
// categories' results unchanged.

package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

const invTarget = "inv.example"

// invRunLimit bounds one scan of the fake zone, which takes well under a
// second. A check that waited for a check in a skipped category would never
// finish.
const invRunLimit = 30 * time.Second

// invZone answers queries for one zone from memory. Its names are
// lowercase; a query matches case-insensitively.
type invZone struct {
	origin string
	rrsets map[invKey][]mdns.RR
	sigs   map[invKey][]mdns.RR // RRSIGs over each RRset in rrsets
	names  map[string]bool
	wild   string // TXT data every <selector>._domainkey name answers
	nsec3  mdns.RR
}

type invKey struct {
	name  string
	rtype uint16
}

// invSigner is a zone key and its private half.
type invSigner struct {
	key  *mdns.DNSKEY
	priv crypto.Signer
}

// invBuildZone returns the zone the tests serve. Its fixtures each once
// gave results a repeated ID: a DS RRset with digest types 1 and 2, DNSKEYs
// of algorithms 8 and 13, MX hosts that differ only in letter case, a
// declined BIMI record, DMARC p=none with pct below 100 and a _domainkey
// wildcard.
func invBuildZone(t *testing.T) *invZone {
	t.Helper()
	origin := mdns.Fqdn(invTarget)
	z := &invZone{
		origin: origin,
		rrsets: map[invKey][]mdns.RR{},
		sigs:   map[invKey][]mdns.RR{},
		names:  map[string]bool{},
	}
	for _, rr := range []string{
		origin + " 3600 IN SOA ns1." + origin + " hostmaster." + origin +
			" 2026100801 7200 3600 1209600 3600",
		origin + " 3600 IN NS ns1." + origin,
		origin + " 3600 IN NS ns2." + origin,
		"ns1." + origin + " 3600 IN A 192.0.2.53",
		"ns2." + origin + " 3600 IN A 198.51.100.53",
		origin + " 3600 IN MX 10 mx." + origin,
		origin + " 3600 IN MX 20 " + strings.ToUpper("mx."+origin),
		"mx." + origin + " 3600 IN A 192.0.2.25",
		`_dmarc.` + origin + ` 3600 IN TXT "v=DMARC1; p=none; pct=50"`,
		`default._bimi.` + origin + ` 3600 IN TXT "v=BIMI1; l=; a="`,
	} {
		z.add(t, invParse(t, rr))
	}

	ksk := invNewKey(t, origin, mdns.ECDSAP256SHA256, 256, 257)
	zsk := invNewKey(t, origin, mdns.RSASHA256, 2048, 256)
	z.add(t, ksk.key, zsk.key, ksk.key.ToDS(mdns.SHA1), ksk.key.ToDS(mdns.SHA256))
	z.signApex(t, ksk, zsk)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate DKIM key: %v", err)
	}
	z.wild = "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)
	z.nsec3 = invParse(t, mdns.HashName(origin, mdns.SHA1, 0, "")+"."+origin+
		" 3600 IN NSEC3 1 0 0 - "+mdns.HashName("ns1."+origin, mdns.SHA1, 0, "")+
		" A NS SOA MX RRSIG DNSKEY NSEC3PARAM")
	return z
}

func invParse(t *testing.T, s string) mdns.RR {
	t.Helper()
	rr, err := mdns.NewRR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return rr
}

// invNewKey generates a DNSKEY of algorithm alg for owner.
func invNewKey(t *testing.T, owner string, alg uint8, bits int, flags uint16) invSigner {
	t.Helper()
	key := &mdns.DNSKEY{
		Hdr: mdns.RR_Header{
			Name: owner, Rrtype: mdns.TypeDNSKEY, Class: mdns.ClassINET, Ttl: 3600,
		},
		Flags: flags, Protocol: 3, Algorithm: alg,
	}
	priv, err := key.Generate(bits)
	if err != nil {
		t.Fatalf("generate algorithm %d key: %v", alg, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("algorithm %d key %T is not a crypto.Signer", alg, priv)
	}
	return invSigner{key: key, priv: signer}
}

func (z *invZone) add(t *testing.T, rrs ...mdns.RR) {
	t.Helper()
	for _, rr := range rrs {
		h := rr.Header()
		h.Name = strings.ToLower(h.Name)
		k := invKey{h.Name, h.Rrtype}
		z.rrsets[k] = append(z.rrsets[k], rr)
		z.names[h.Name] = true
	}
}

// signApex signs every RRset at the apex with each key, as RFC 4035 §2.2
// asks of a zone with keys of two algorithms.
func (z *invZone) signApex(t *testing.T, keys ...invSigner) {
	t.Helper()
	now := time.Now()
	for k, rrset := range z.rrsets {
		if k.name != z.origin || k.rtype == mdns.TypeDS {
			continue
		}
		for _, s := range keys {
			sig := &mdns.RRSIG{
				Hdr: mdns.RR_Header{
					Name: z.origin, Rrtype: mdns.TypeRRSIG, Class: mdns.ClassINET, Ttl: 3600,
				},
				Inception:  uint32(now.Add(-time.Hour).Unix()),
				Expiration: uint32(now.Add(30 * 24 * time.Hour).Unix()),
				KeyTag:     s.key.KeyTag(),
				SignerName: z.origin,
				Algorithm:  s.key.Algorithm,
			}
			if err := sig.Sign(s.priv, rrset); err != nil {
				t.Fatalf("sign %s %s: %v", k.name, mdns.TypeToString[k.rtype], err)
			}
			z.sigs[k] = append(z.sigs[k], sig)
		}
	}
}

// ServeDNS answers req from the zone, echoing its EDNS0 OPT record.
func (z *invZone) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
		resp.SetEdns0(opt.UDPSize(), do)
	}
	z.answer(resp, req.Question[0], do)
	_ = w.WriteMsg(resp)
}

// answer fills resp for q: the RRset and, when do is set, its RRSIGs; the
// wildcard TXT for any name under _domainkey; NODATA for a name that exists
// without that type; otherwise NXDOMAIN, with the zone's NSEC3 when do is
// set.
func (z *invZone) answer(resp *mdns.Msg, q mdns.Question, do bool) {
	k := invKey{strings.ToLower(q.Name), q.Qtype}
	switch {
	case len(z.rrsets[k]) > 0:
		resp.Answer = append(resp.Answer, z.rrsets[k]...)
		if do {
			resp.Answer = append(resp.Answer, z.sigs[k]...)
		}
	case strings.HasSuffix(k.name, "._domainkey."+z.origin):
		if q.Qtype == mdns.TypeTXT {
			resp.Answer = append(resp.Answer, &mdns.TXT{
				Hdr: mdns.RR_Header{
					Name: q.Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 3600,
				},
				Txt: []string{z.wild},
			})
		}
	case z.names[k.name]:
	default:
		resp.Rcode = mdns.RcodeNameError
		if do && mdns.IsSubDomain(z.origin, k.name) {
			resp.Ns = append(resp.Ns, z.nsec3)
		}
	}
}

// invRun scans invTarget with --no-active through resolver, running the
// categories keep accepts (all when keep is nil) on a fresh Env. It fails
// the test when the scan does not finish within invRunLimit.
func invRun(t *testing.T, resolver string, keep func(string) bool) []report.Result {
	t.Helper()
	env := probe.NewEnv(invTarget, 2*time.Second, false, resolver)
	ctx, cancel := context.WithTimeout(context.Background(), invRunLimit)
	defer cancel()
	done := make(chan []report.Result, 1)
	go func() { done <- registry.Run(ctx, env, registry.Options{Keep: keep}) }()
	select {
	case results := <-done:
		if ctx.Err() != nil {
			t.Fatalf("scan ran into its %s deadline", invRunLimit)
		}
		return results
	case <-time.After(invRunLimit + 5*time.Second):
		t.Fatalf("scan did not return within %s of its deadline", 5*time.Second)
		return nil
	}
}

// invDiff describes the first difference between two result lists.
func invDiff(got, want []report.Result) string {
	for i := range min(len(got), len(want)) {
		if !reflect.DeepEqual(got[i], want[i]) {
			return fmt.Sprintf("result %d is %+v, want %+v", i, got[i], want[i])
		}
	}
	return fmt.Sprintf("%d results, want %d", len(got), len(want))
}

func invIDs(results []report.Result) []string {
	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.ID
	}
	return ids
}

// invCheckFixtures fails the test when a fixture no longer reaches the
// check it exercises, which would leave that check's IDs untested, or when
// the run reported the answering fake resolver unreachable.
func invCheckFixtures(t *testing.T, results []report.Result) {
	t.Helper()
	ids := invIDs(results)
	for _, id := range []string{
		"dnssec.chain.ds_match", "dnssec.chain.dnskey_rrsig", "dnssec.chain.soa_rrsig",
		"dnssec.algorithm.ds", "dnssec.algorithm.dnskey", "dnssec.nsec.type",
		"email.dkim.wildcard", "email.dane.mx.inv.example", "bimi.txt", "bimi.gmail.dmarc",
		"email.dmarc.record", "dns.zone.mx",
	} {
		if !slices.Contains(ids, id) {
			t.Errorf("no %s result; the fixture zone no longer exercises it", id)
		}
	}
	if slices.Contains(ids, "dns.resolver.unreachable") {
		t.Error("dns.resolver.unreachable reported although the resolver answered")
	}
}

// invCheckResults fails the test on a repeated result ID or a remediation
// holding a control character.
func invCheckResults(t *testing.T, results []report.Result) {
	t.Helper()
	if err := report.CheckUniqueIDs(results); err != nil {
		t.Error(err)
	}
	for _, r := range results {
		if err := report.CheckRemediation(r.Remediation); err != nil {
			t.Errorf("%s: %v", r.ID, err)
		}
	}
}

// TestInvariantsDefaultScan scans the fixture zone and checks the run-wide
// invariants: unique result IDs, remediations without control characters,
// identical results from repeated runs, and an unchanged report for the
// other categories when one category is skipped.
func TestInvariantsDefaultScan(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	resolver := serveDNS(t, invBuildZone(t))
	full := invRun(t, resolver, nil)
	invCheckFixtures(t, full)
	invCheckResults(t, full)

	for run := 2; run <= 3; run++ {
		if got := invRun(t, resolver, nil); !reflect.DeepEqual(got, full) {
			t.Errorf("run %d differs from run 1: %s", run, invDiff(got, full))
		}
	}

	for _, skip := range registry.Categories() {
		t.Run("skip "+skip, func(t *testing.T) {
			want := slices.DeleteFunc(slices.Clone(full), func(r report.Result) bool {
				return r.Category == skip
			})
			got := invRun(t, resolver, func(cat string) bool { return cat != skip })
			if !reflect.DeepEqual(got, want) {
				t.Errorf("differs from the full scan minus %s: %s", skip, invDiff(got, want))
			}
		})
	}
}

// TestInvariantsUnreachableResolver scans through a resolver that never
// answers and expects the run-level dns.resolver.unreachable FAIL, which
// keeps the exit code at 1 when every DNS result is inconclusive.
func TestInvariantsUnreachableResolver(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()

	env := probe.NewEnv(invTarget, 200*time.Millisecond, false, pc.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), invRunLimit)
	defer cancel()
	results := registry.Run(ctx, env, registry.Options{})
	if ctx.Err() != nil {
		t.Fatalf("scan ran into its %s deadline", invRunLimit)
	}
	i := slices.IndexFunc(results, func(r report.Result) bool {
		return r.ID == "dns.resolver.unreachable"
	})
	if i < 0 {
		t.Fatalf("no dns.resolver.unreachable result among %v", invIDs(results))
	}
	if r := results[i]; r.Status != report.Fail || r.Category != "DNS" {
		t.Errorf("dns.resolver.unreachable = %+v, want a DNS FAIL", r)
	}
}

// servfailAll answers every query with SERVFAIL.
type servfailAll struct{}

func (servfailAll) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	resp := new(mdns.Msg)
	resp.SetRcode(req, mdns.RcodeServerFailure)
	_ = w.WriteMsg(resp)
}

// TestInvariantsResolverFailuresAreInconclusive scans through a resolver
// that answers every query with SERVFAIL. A lookup that fails says nothing
// about the target, so every result that reports one is inconclusive: WARN,
// evidence starting "could not determine: " and no remediation. Only the
// results that grade the resolvers rather than the target are exempt: the
// run-level dns.resolver.unreachable FAIL and the dnssec.sentinel INFO.
func TestInvariantsResolverFailuresAreInconclusive(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	results := invRun(t, serveDNS(t, servfailAll{}), nil)
	resolverChecks := map[string]bool{"dns.resolver.unreachable": true, "dnssec.sentinel": true}
	for _, r := range results {
		if resolverChecks[r.ID] || !strings.Contains(r.Evidence, "SERVFAIL") {
			continue
		}
		if r.Status != report.Warn || !strings.HasPrefix(r.Evidence, "could not determine: ") ||
			r.Remediation != "" {
			t.Errorf("%s = %s %q (remediation %q), want inconclusive",
				r.ID, r.Status, r.Evidence, r.Remediation)
		}
	}
}
