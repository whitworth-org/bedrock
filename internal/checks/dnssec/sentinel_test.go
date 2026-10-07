package dnssec

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// SHA-256 DS digests of root KSK-2017 (20326) and KSK-2024 (38696) as IANA
// publishes them at https://data.iana.org/root-anchors/root-anchors.xml.
const (
	digest20326 = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
	digest38696 = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
)

// Evidence the check gives for a root DNSKEY RRset signed by KSK-2017, as
// today, or by KSK-2024, as after the 2026-10-11 roll.
const (
	rootPreRoll  = "active root KSKs 20326,38696 (DNSKEY RRset signed by 20326, signature verified)"
	rootPostRoll = "active root KSKs 20326,38696 (DNSKEY RRset signed by 38696, signature verified)"

	brokenText = " cannot validate: it SERVFAILs every sentinel name yet returns the root " +
		"DNSKEY RRset with checking disabled, so it may lack a trust anchor for the KSK " +
		"signing that RRset, have a wrong clock, or forward to a resolver with other trust " +
		"anchors (RFC 8509 §3.1)"
	vindText = " shows no sentinel processing (not implemented, disabled, masked by a " +
		"forwarder, or skipped for answers synthesized from cached NSEC records, RFC 8198), " +
		"so its trust anchors are unknown"
	nonVText = " gives no validation signal (answers lack AD, and the RFC 8509 §3 bogus-name " +
		"test was not run)"
	holdDown = " (absent, or still in the RFC 5011 hold-down) and trusts "
)

// fixtureTime falls inside the validity period of the captured root RRSIG,
// 2026-10-01 to 2026-10-22.
var fixtureTime = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// rootDNSKEYRRs returns the root DNSKEY RRset and its RRSIG as captured on
// 2026-10-07.
func rootDNSKEYRRs(t *testing.T) []mdns.RR {
	t.Helper()
	data, err := os.ReadFile("testdata/root-dnskey.zone")
	if err != nil {
		t.Fatalf("read root DNSKEY fixture: %v", err)
	}
	zp := mdns.NewZoneParser(bytes.NewReader(data), ".", "root-dnskey.zone")
	var rrs []mdns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("parse root DNSKEY fixture: %v", err)
	}
	return rrs
}

func answerMsg(rrs ...mdns.RR) *mdns.Msg {
	return &mdns.Msg{Answer: rrs}
}

// dnskeyReply is a resolver's reply to ". DNSKEY" carrying rrs.
func dnskeyReply(rcode int, rrs ...mdns.RR) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion(".", mdns.TypeDNSKEY)
	m.Response = true
	m.Rcode = rcode
	m.Answer = rrs
	return m
}

func fixtureRootKeys(t *testing.T) rootKeys {
	t.Helper()
	root, err := rootKeysFrom(dnskeyReply(mdns.RcodeSuccess, rootDNSKEYRRs(t)...), nil, fixtureTime)
	if err != nil {
		t.Fatalf("root keys from the fixture: %v", err)
	}
	return root
}

// TestRootKSKDigestsMatchIANA proves the remediation's DS computation on the
// real root KSKs reproduces the digests IANA publishes.
func TestRootKSKDigestsMatchIANA(t *testing.T) {
	want := map[uint16]string{20326: digest20326, 38696: digest38696}

	ksks := fixtureRootKeys(t).ksks

	if len(ksks) != len(want) {
		t.Fatalf("want %d active root KSKs, got %d", len(want), len(ksks))
	}
	for _, k := range ksks {
		ds := k.ToDS(mdns.SHA256)
		if got := strings.ToUpper(ds.Digest); got != want[ds.KeyTag] {
			t.Errorf("KSK %d: DS digest %s, want %s", ds.KeyTag, got, want[ds.KeyTag])
		}
	}
}

func TestIsActiveRootKSK(t *testing.T) {
	cases := []struct {
		name  string
		owner string
		flags uint16
		proto uint8
		want  bool
	}{
		{"KSK", ".", 257, 3, true},
		{"ZSK", ".", 256, 3, false},
		{"revoked KSK", ".", 385, 3, false},
		{"SEP without ZONE", ".", 1, 3, false},
		{"protocol other than 3", ".", 257, 2, false},
		{"owner other than the root", "example.", 257, 3, false},
	}
	for _, c := range cases {
		k := &mdns.DNSKEY{Hdr: mdns.RR_Header{Name: c.owner}, Flags: c.flags, Protocol: c.proto}
		if got := isActiveRootKSK(k); got != c.want {
			t.Errorf("%s: isActiveRootKSK = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestActiveRootKSKs drops ZSKs and revoked keys and returns the KSKs
// ascending and unique by key tag, whatever order the answer used.
func TestActiveRootKSKs(t *testing.T) {
	rrs := rootDNSKEYRRs(t)
	ksks := activeRootKSKs(answerMsg(rrs...))
	if len(ksks) != 2 {
		t.Fatalf("fixture: want 2 active KSKs, got %d", len(ksks))
	}
	revoked, ok := mdns.Copy(ksks[0]).(*mdns.DNSKEY)
	if !ok {
		t.Fatal("mdns.Copy did not return a DNSKEY")
	}
	revoked.Flags |= mdns.REVOKE
	answer := append([]mdns.RR{ksks[1], revoked, ksks[1]}, rrs...)

	got := rootKeys{ksks: activeRootKSKs(answerMsg(answer...))}.tags()

	if want := []uint16{20326, 38696}; !slices.Equal(got, want) {
		t.Fatalf("active KSK tags = %v, want %v", got, want)
	}
}

// TestActiveRootKSKsDropsOversizedKey covers a KSK whose RDATA overflows
// miekg's 4096-byte pack buffer, which a TCP or DoH answer can carry. Keeping
// it would probe tag 00000 and leave sentinelRemediation a nil DS to print.
func TestActiveRootKSKsDropsOversizedKey(t *testing.T) {
	huge := rootKSK(make([]byte, mdns.DefaultMsgSize))
	if !isActiveRootKSK(huge) || huge.KeyTag() != 0 || huge.ToDS(mdns.SHA256) != nil {
		t.Fatal("precondition: want an active KSK that miekg cannot pack")
	}
	answer := append([]mdns.RR{huge}, rootDNSKEYRRs(t)...)

	got := rootKeys{ksks: activeRootKSKs(answerMsg(answer...))}.tags()

	if want := []uint16{20326, 38696}; !slices.Equal(got, want) {
		t.Fatalf("active KSK tags = %v, want %v", got, want)
	}
}

// TestVerifiedSigners lists only KSKs whose RRSIG over the root DNSKEY RRset
// verifies and is current: a key tag alone proves nothing.
func TestVerifiedSigners(t *testing.T) {
	rrs := rootDNSKEYRRs(t)
	synthetic := syntheticRoot(t, nil, 20326, 38696)
	cases := []struct {
		name string
		rrs  []mdns.RR
		at   time.Time
		want []uint16
	}{
		{"captured root", rrs, fixtureTime, []uint16{20326}},
		{"RRSIG listed twice", append(slices.Clone(rrs), sigsOf(rrs)...), fixtureTime,
			[]uint16{20326}},
		{"after the RRSIG expired", rrs, time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), nil},
		{"before the RRSIG's inception", rrs, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), nil},
		{"RRSIG re-tagged to the other KSK", retag(rrs, 38696), fixtureTime, nil},
		{"RRSIG naming no key in the RRset", retag(rrs, 12345), fixtureTime, nil},
		{"RRSIG signature corrupted", badSignature(rrs), fixtureTime, nil},
		{"signed by both KSKs", synthetic, time.Now(), []uint16{20326, 38696}},
		{"signed by a ZSK only", syntheticRoot(t, nil, 31698), time.Now(), nil},
	}
	for _, c := range cases {
		m := answerMsg(c.rrs...)
		if got := verifiedSigners(m, activeRootKSKs(m), c.at); !slices.Equal(got, c.want) {
			t.Errorf("%s: verifiedSigners = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRootKeysFrom reads the KSKs and verified signers from a usable root
// DNSKEY answer and names the fault in any other.
func TestRootKeysFrom(t *testing.T) {
	root := fixtureRootKeys(t)
	if !slices.Equal(root.tags(), []uint16{20326, 38696}) ||
		!slices.Equal(root.signers, []uint16{20326}) {
		t.Fatalf("fixture: KSKs %v signed by %v, want [20326 38696] signed by [20326]",
			root.tags(), root.signers)
	}
	otherQuery := dnskeyReply(mdns.RcodeSuccess, rootDNSKEYRRs(t)...)
	otherQuery.Question[0].Qtype = mdns.TypeA
	zsks := slices.DeleteFunc(rootDNSKEYRRs(t), func(rr mdns.RR) bool {
		k, ok := rr.(*mdns.DNSKEY)
		return ok && k.Flags&mdns.SEP != 0
	})
	cases := []struct {
		name string
		msg  *mdns.Msg
		err  error
		want string
	}{
		{"transport error", nil, errors.New("i/o timeout"), "i/o timeout"},
		{"no reply", nil, nil, "no reply"},
		{"reply to another query", otherQuery, nil, "reply does not match the query"},
		{"SERVFAIL", dnskeyReply(mdns.RcodeServerFailure), nil, "answered SERVFAIL"},
		{"ZSKs only", dnskeyReply(mdns.RcodeSuccess, zsks...), nil, "no active KSK"},
		{"more KSKs than the cap", dnskeyReply(mdns.RcodeSuccess, syntheticKSKs(maxRootKSKs+1)...),
			nil, "5 active KSKs (limit 4)"},
	}
	for _, c := range cases {
		if _, err := rootKeysFrom(c.msg, c.err, fixtureTime); err == nil || err.Error() != c.want {
			t.Errorf("%s: rootKeysFrom error = %v, want %q", c.name, err, c.want)
		}
	}
}

func TestRootKeysDescribe(t *testing.T) {
	root := fixtureRootKeys(t)
	if got := root.describe(); got != rootPreRoll {
		t.Errorf("describe = %q, want %q", got, rootPreRoll)
	}
	root.signers = nil
	want := "active root KSKs 20326,38696 (no RRSIG by an active KSK over the DNSKEY RRset verifies)"
	if got := root.describe(); got != want {
		t.Errorf("describe without a verified RRSIG = %q, want %q", got, want)
	}
}

// TestSentinelNames pins the RFC 8509 §2.1 label format: five zero-padded
// digits, is-ta before not-ta, under arpa. BIND and Knot only recognise
// sentinel labels of exactly 29 (is-ta) or 30 (not-ta) octets.
func TestSentinelNames(t *testing.T) {
	got := sentinelNames([]uint16{0, 42, 20326, 38696, 65535})

	want := []string{
		"root-key-sentinel-is-ta-00000.arpa.", "root-key-sentinel-not-ta-00000.arpa.",
		"root-key-sentinel-is-ta-00042.arpa.", "root-key-sentinel-not-ta-00042.arpa.",
		"root-key-sentinel-is-ta-20326.arpa.", "root-key-sentinel-not-ta-20326.arpa.",
		"root-key-sentinel-is-ta-38696.arpa.", "root-key-sentinel-not-ta-38696.arpa.",
		"root-key-sentinel-is-ta-65535.arpa.", "root-key-sentinel-not-ta-65535.arpa.",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("sentinelNames = %q, want %q", got, want)
	}
	for _, name := range got {
		label, _, _ := strings.Cut(name, ".")
		wantLen := 29
		if strings.Contains(label, "-not-ta-") {
			wantLen = 30
		}
		if len(label) != wantLen {
			t.Errorf("label %q is %d octets, want %d", label, len(label), wantLen)
		}
	}
}

var (
	ansNXAD           = sentinelReply{rcode: mdns.RcodeNameError, ad: true}
	ansNX             = sentinelReply{rcode: mdns.RcodeNameError}
	ansNoErrAD        = sentinelReply{rcode: mdns.RcodeSuccess, ad: true}
	ansNoErr          = sentinelReply{rcode: mdns.RcodeSuccess}
	ansServfail       = sentinelReply{rcode: mdns.RcodeServerFailure}
	ansRefused        = sentinelReply{rcode: mdns.RcodeRefused}
	ansTimeout        = sentinelReply{err: errors.New("i/o timeout")}
	ansServfailAnswer = sentinelReply{rcode: mdns.RcodeServerFailure, answer: true}
	ansRewritten      = sentinelReply{rcode: mdns.RcodeSuccess, ad: true, answer: true}
)

// TestClassify covers every row of the RFC 8509 §3 table plus the replies
// that cannot be classified.
func TestClassify(t *testing.T) {
	cases := []struct {
		name        string
		isTA, notTA sentinelReply
		want        sentinelClass
	}{
		{"Vnew", ansNXAD, ansServfail, classVnew},
		{"Vnew behind a forwarder that strips AD", ansNX, ansServfail, classVnew},
		{"Vnew with NOERROR", ansNoErrAD, ansServfail, classVnew},
		{"Vold", ansServfail, ansNXAD, classVold},
		{"Vold without AD", ansServfail, ansNoErr, classVold},
		{"Vind", ansNXAD, ansNXAD, classVind},
		{"Vind with NOERROR", ansNoErrAD, ansNXAD, classVind},
		{"nonV", ansNX, ansNX, classNonV},
		{"nonV with NOERROR", ansNoErr, ansNX, classNonV},
		{"both SERVFAIL", ansServfail, ansServfail, classServfail},
		{"AD on is-ta only", ansNXAD, ansNX, classOther},
		{"AD on not-ta only", ansNX, ansNXAD, classOther},
		{"is-ta timed out", ansTimeout, ansServfail, classOther},
		{"not-ta timed out", ansNXAD, ansTimeout, classOther},
		{"is-ta REFUSED", ansRefused, ansServfail, classOther},
		{"not-ta REFUSED", ansNXAD, ansRefused, classOther},
		{"SERVFAIL carrying an answer", ansServfailAnswer, ansNXAD, classOther},
		{"both SERVFAIL, one carrying an answer", ansServfail, ansServfailAnswer, classOther},
		{"rewritten is-ta answer", ansRewritten, ansServfail, classOther},
		{"rewritten not-ta answer", ansServfail, ansRewritten, classOther},
		{"rewritten answers", ansRewritten, ansRewritten, classOther},
	}
	for _, c := range cases {
		if got := classify(c.isTA, c.notTA); got != c.want {
			t.Errorf("%s: classify(%v, %v) = %d, want %d", c.name, c.isTA, c.notTA, got, c.want)
		}
	}
}

// sentinelMsg is a recursive resolver's reply to the A query for name, as
// edited by edits.
func sentinelMsg(name string, rcode int, edits ...func(*mdns.Msg)) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion(name, mdns.TypeA)
	m.Response = true
	m.RecursionAvailable = true
	m.Rcode = rcode
	for _, edit := range edits {
		edit(m)
	}
	return m
}

func withEDE(codes ...uint16) func(*mdns.Msg) {
	return func(m *mdns.Msg) {
		m.SetEdns0(1232, true)
		opt := m.IsEdns0()
		for _, code := range codes {
			opt.Option = append(opt.Option, &mdns.EDNS0_EDE{InfoCode: code, ExtraText: "x"})
		}
	}
}

func TestReplyAt(t *testing.T) {
	const name = "root-key-sentinel-is-ta-20326.arpa."
	errTimeout := errors.New("i/o timeout")
	addressed := func(m *mdns.Msg) {
		m.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA,
			Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	}
	cases := []struct {
		name string
		resp probe.MultiResp
		want sentinelReply
	}{
		{"NXDOMAIN with AD", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.AuthenticatedData = true })}, ansNXAD},
		{"question in other case", probe.MultiResp{Msg: sentinelMsg(strings.ToUpper(name),
			mdns.RcodeServerFailure)}, ansServfail},
		{"answer records", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeSuccess, addressed)},
			sentinelReply{rcode: mdns.RcodeSuccess, answer: true}},
		{"extended errors", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeServerFailure,
			withEDE(6, 29))}, sentinelReply{rcode: mdns.RcodeServerFailure, ede: "+EDE6+EDE29"}},
		{"transport error", probe.MultiResp{Err: errTimeout}, sentinelReply{err: errTimeout}},
		{"no message", probe.MultiResp{}, sentinelReply{err: errNoReply}},
		{"not a response", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.Response = false })}, sentinelReply{err: errMismatch}},
		{"other opcode", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.Opcode = mdns.OpcodeNotify })}, sentinelReply{err: errMismatch}},
		{"no question", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.Question = nil })}, sentinelReply{err: errMismatch}},
		{"two questions", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.Question = append(m.Question, m.Question[0]) })},
			sentinelReply{err: errMismatch}},
		{"other name", probe.MultiResp{Msg: sentinelMsg("example.", mdns.RcodeNameError)},
			sentinelReply{err: errMismatch}},
		{"other type", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.Question[0].Qtype = mdns.TypeAAAA })},
			sentinelReply{err: errMismatch}},
		{"other class", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.Question[0].Qclass = mdns.ClassCHAOS })},
			sentinelReply{err: errMismatch}},
		{"recursion not available", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.RecursionAvailable = false })},
			sentinelReply{err: errNotRecursive}},
		{"authoritative answer", probe.MultiResp{Msg: sentinelMsg(name, mdns.RcodeNameError,
			func(m *mdns.Msg) { m.Authoritative = true })}, sentinelReply{err: errLocalZone}},
	}
	for _, c := range cases {
		if got := replyAt([]probe.MultiResp{c.resp}, 0, name); got != c.want {
			t.Errorf("%s: replyAt = %+v, want %+v", c.name, got, c.want)
		}
	}
	if got := replyAt(nil, 0, name); got != (sentinelReply{err: errNoReply}) {
		t.Errorf("no slot for the upstream: replyAt = %+v, want errNoReply", got)
	}
}

func TestSentinelReplyString(t *testing.T) {
	cases := []struct {
		reply sentinelReply
		want  string
	}{
		{ansNXAD, "NXDOMAIN+AD"},
		{ansServfail, "SERVFAIL"},
		{ansTimeout, "error"},
		{ansRewritten, "NOERROR+AD+answer"},
		{sentinelReply{rcode: mdns.RcodeNameError, ad: true, ede: "+EDE29"}, "NXDOMAIN+AD+EDE29"},
	}
	for _, c := range cases {
		if got := c.reply.String(); got != c.want {
			t.Errorf("%+v.String() = %q, want %q", c.reply, got, c.want)
		}
	}
}

// pairFor returns an (is-ta, not-ta) reply pair that classifies as c.
func pairFor(c sentinelClass) [2]sentinelReply {
	switch c {
	case classVnew:
		return [2]sentinelReply{ansNXAD, ansServfail}
	case classVold:
		return [2]sentinelReply{ansServfail, ansNXAD}
	case classVind:
		return [2]sentinelReply{ansNXAD, ansNXAD}
	case classNonV:
		return [2]sentinelReply{ansNX, ansNX}
	case classServfail:
		return [2]sentinelReply{ansServfail, ansServfail}
	}
	return [2]sentinelReply{ansTimeout, ansTimeout}
}

// probeOf returns an upstream whose replies for tags classify as classes.
func probeOf(label string, tags []uint16, classes ...sentinelClass) resolverProbe {
	p := resolverProbe{label: label, tags: tags}
	for _, c := range classes {
		p.replies = append(p.replies, pairFor(c))
	}
	return p
}

func TestVerdict(t *testing.T) {
	type classes = []sentinelClass
	both := []uint16{20326, 38696}
	three := []uint16{20326, 38696, 40000}
	preRoll := rootKeys{signers: []uint16{20326}}
	postRoll := rootKeys{signers: []uint16{38696}}
	cases := []struct {
		name    string
		root    rootKeys
		tags    []uint16
		classes classes
		rootErr error
		want    resolverVerdict
	}{
		{"no tags", preRoll, nil, nil, nil, verdictUnknown},
		{"trusts both KSKs", preRoll, both, classes{classVnew, classVnew}, nil, verdictReady},
		{"lacks KSK-2024", preRoll, both, classes{classVnew, classVold}, nil, verdictMissing},
		{"lacks the KSK that signs", preRoll, both, classes{classVold, classVnew}, nil,
			verdictUnknown},
		{"dropped the retiring KSK after the roll", postRoll, both,
			classes{classVold, classVnew}, nil, verdictReady},
		{"trusts only the retiring KSK after the roll", postRoll, both,
			classes{classVnew, classVold}, nil, verdictUnknown},
		{"no verified signer, lacks KSK-2024", rootKeys{}, both,
			classes{classVnew, classVold}, nil, verdictMissing},
		{"no verified signer, lacks the retiring KSK", rootKeys{}, both,
			classes{classVold, classVnew}, nil, verdictReady},
		{"lone Vold", preRoll, []uint16{20326}, classes{classVold}, nil, verdictUnknown},
		{"trusts no active KSK", preRoll, both, classes{classVold, classVold}, nil,
			verdictUnknown},
		{"lacks an incoming third KSK", postRoll, three,
			classes{classVold, classVnew, classVold}, nil, verdictMissing},
		{"Vnew, Vold and an unclassified tag", preRoll, three,
			classes{classVnew, classVold, classOther}, nil, verdictUnknown},
		{"SERVFAILs every name", preRoll, both, classes{classServfail, classServfail}, nil,
			verdictBroken},
		{"SERVFAILs every name and the root DNSKEY query", preRoll, both,
			classes{classServfail, classServfail}, errors.New("answered SERVFAIL"),
			verdictUnknown},
		{"SERVFAILs one tag's names", preRoll, both, classes{classVnew, classServfail}, nil,
			verdictUnknown},
		{"sentinel not implemented", preRoll, both, classes{classVind, classVind}, nil,
			verdictUnsupported},
		{"not validating", preRoll, both, classes{classNonV, classNonV}, nil,
			verdictNotValidating},
		{"Vnew and an unclassified tag", preRoll, both, classes{classVnew, classOther}, nil,
			verdictUnknown},
		{"Vold and an unclassified tag", preRoll, both, classes{classVold, classOther}, nil,
			verdictUnknown},
		{"Vnew and Vind", preRoll, both, classes{classVnew, classVind}, nil, verdictUnknown},
		{"Vind and nonV", preRoll, both, classes{classVind, classNonV}, nil, verdictUnknown},
	}
	for _, c := range cases {
		p := probeOf("r1", c.tags, c.classes...)
		p.rootErr = c.rootErr
		if got := p.verdict(c.root); got != c.want {
			t.Errorf("%s: verdict = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestSentinelStatus(t *testing.T) {
	type verdicts = []resolverVerdict
	cases := []struct {
		name     string
		verdicts verdicts
		want     report.Status
		title    string
	}{
		{"no upstreams", nil, report.Info, titleSentinelUnknown},
		{"one ready", verdicts{verdictReady}, report.Pass, titleSentinelReady},
		{"all ready", verdicts{verdictReady, verdictReady}, report.Pass, titleSentinelReady},
		{"one missing", verdicts{verdictReady, verdictMissing}, report.Warn, titleSentinelMissing},
		{"missing then ready", verdicts{verdictMissing, verdictReady}, report.Warn,
			titleSentinelMissing},
		{"missing after unknown", verdicts{verdictUnknown, verdictMissing}, report.Warn,
			titleSentinelMissing},
		{"broken", verdicts{verdictBroken}, report.Warn, titleSentinelBroken},
		{"ready then broken", verdicts{verdictReady, verdictBroken}, report.Warn,
			titleSentinelBroken},
		{"missing and broken", verdicts{verdictMissing, verdictBroken}, report.Warn,
			titleSentinelBroken},
		{"ready and not validating", verdicts{verdictReady, verdictNotValidating}, report.Info,
			titleSentinelUnknown},
		{"not validating then ready", verdicts{verdictNotValidating, verdictReady}, report.Info,
			titleSentinelUnknown},
		{"ready and unknown", verdicts{verdictReady, verdictUnknown}, report.Info,
			titleSentinelUnknown},
		{"unknown then ready", verdicts{verdictUnknown, verdictReady}, report.Info,
			titleSentinelUnknown},
		{"unsupported", verdicts{verdictUnsupported}, report.Info, titleSentinelUnknown},
	}
	for _, c := range cases {
		if got, title := sentinelStatus(c.verdicts); got != c.want || title != c.title {
			t.Errorf("%s: sentinelStatus(%v) = %s %q, want %s %q", c.name, c.verdicts, got,
				title, c.want, c.title)
		}
	}
}

func TestDescribe(t *testing.T) {
	both := []uint16{20326, 38696}
	three := []uint16{20326, 38696, 40000}
	undetermined := resolverProbe{
		label:   "r1",
		tags:    both,
		replies: [][2]sentinelReply{{ansNXAD, ansNX}, {ansTimeout, ansRefused}},
	}
	synthNX := sentinelReply{rcode: mdns.RcodeNameError, ad: true, ede: "+EDE29"}
	synthesized := resolverProbe{
		label:   "r1",
		tags:    both,
		replies: [][2]sentinelReply{{ansNXAD, synthNX}, {synthNX, synthNX}},
	}
	rootFailed := probeOf("r1", both, classServfail, classServfail)
	rootFailed.rootErr = &url.Error{Op: "Post", URL: "https://doh.example/dns-query/profile-abc",
		Err: errors.New("doh status 502")}
	cases := []struct {
		name  string
		probe resolverProbe
		v     resolverVerdict
		want  string
	}{
		{"ready", probeOf("r1", both, classVnew, classVnew), verdictReady,
			"r1 trusts 20326,38696"},
		{"ready without the retiring KSK", probeOf("r1", both, classVold, classVnew),
			verdictReady, "r1 trusts 38696 but not retiring KSK 20326"},
		{"missing", probeOf("r1", both, classVnew, classVold), verdictMissing,
			"r1 does not yet trust 38696" + holdDown + "20326"},
		{"missing beside the retiring KSK", probeOf("r1", three, classVold, classVnew, classVold),
			verdictMissing, "r1 does not yet trust 40000" + holdDown +
				"38696 but not retiring KSK 20326"},
		{"broken", probeOf("r1", both, classServfail, classServfail), verdictBroken,
			"r1" + brokenText},
		{"unsupported", probeOf("r1", both, classVind, classVind), verdictUnsupported,
			"r1" + vindText},
		{"unsupported, answers synthesized", synthesized, verdictUnsupported,
			"r1" + vindText + " (answers carried +EDE29)"},
		{"not validating", probeOf("r1", both, classNonV, classNonV), verdictNotValidating,
			"r1" + nonVText},
		{"undetermined", undetermined, verdictUnknown, "r1 undetermined (" +
			"20326 is-ta=NXDOMAIN+AD not-ta=NXDOMAIN, 38696 is-ta=error not-ta=REFUSED: " +
			"i/o timeout)"},
		{"undetermined, root DNSKEY failed too", rootFailed, verdictUnknown,
			"r1 undetermined (root DNSKEY with checking disabled: doh status 502, replies " +
				"20326 is-ta=SERVFAIL not-ta=SERVFAIL, 38696 is-ta=SERVFAIL not-ta=SERVFAIL)"},
	}
	for _, c := range cases {
		if got := c.probe.describe(c.v); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// TestRawRepliesReportsFirstError keeps the first transport error, in tag
// order, when several replies failed.
func TestRawRepliesReportsFirstError(t *testing.T) {
	refused := sentinelReply{err: errors.New("connection refused")}
	p := resolverProbe{
		label:   "r1",
		tags:    []uint16{20326, 38696},
		replies: [][2]sentinelReply{{ansTimeout, ansNX}, {ansNX, refused}},
	}
	want := "20326 is-ta=error not-ta=NXDOMAIN, 38696 is-ta=NXDOMAIN not-ta=error: i/o timeout"

	if got := p.rawReplies(); got != want {
		t.Errorf("rawReplies = %q, want %q", got, want)
	}
}

// TestErrTextDropsDoHURL keeps a DoH URL's path, which can name an account,
// out of the evidence.
func TestErrTextDropsDoHURL(t *testing.T) {
	doh := &url.Error{Op: "Post", URL: "https://doh.example/dns-query/profile-abc123",
		Err: errors.New("ssrf dial: blocked")}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"plain error", errors.New("i/o timeout"), "i/o timeout"},
		{"DoH request error", doh, "ssrf dial: blocked"},
		{"wrapped DoH request error", fmt.Errorf("exchange: %w", doh), "ssrf dial: blocked"},
	}
	for _, c := range cases {
		if got := errText(c.err); got != c.want {
			t.Errorf("%s: errText = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestNeededTags covers the keys a resolver that cannot validate is told to
// trust: today's signer plus every active KSK that is not retiring, so the
// advice still holds after the roll.
func TestNeededTags(t *testing.T) {
	root := fixtureRootKeys(t)
	postRoll := root
	postRoll.signers = []uint16{38696}
	unsigned := root
	unsigned.signers = nil
	cases := []struct {
		name string
		root rootKeys
		want []uint16
	}{
		{"before the roll", root, []uint16{20326, 38696}},
		{"after the roll", postRoll, []uint16{38696}},
		{"no verified signer", unsigned, []uint16{20326, 38696}},
	}
	for _, c := range cases {
		if got := c.root.neededTags(); !slices.Equal(got, c.want) {
			t.Errorf("%s: neededTags = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCarriesEDE matches whole extended error codes only.
func TestCarriesEDE(t *testing.T) {
	cases := []struct {
		ede  string
		want bool
	}{
		{"", false},
		{"+EDE29", true},
		{"+EDE3+EDE29", true},
		{"+EDE290", false},
		{"+EDE2", false},
	}
	for _, c := range cases {
		p := resolverProbe{replies: [][2]sentinelReply{{{ede: c.ede}, {}}}}
		if got := p.carriesEDE(29); got != c.want {
			t.Errorf("carriesEDE(29) with %q = %v, want %v", c.ede, got, c.want)
		}
	}
}

func TestRcodeName(t *testing.T) {
	for rcode, want := range map[int]string{2: "SERVFAIL", 3: "NXDOMAIN", 12: "RCODE12"} {
		if got := rcodeName(rcode); got != want {
			t.Errorf("rcodeName(%d) = %q, want %q", rcode, got, want)
		}
	}
}

// TestSentinelRemediation pins the DS lines operators copy: one per KSK some
// resolver needs, in key tag order, with IANA's digests.
func TestSentinelRemediation(t *testing.T) {
	root := fixtureRootKeys(t)
	tags := root.tags()
	ds20326 := "\n# . IN DS 20326 8 2 " + digest20326
	ds38696 := "\n# . IN DS 38696 8 2 " + digest38696
	broken := "# b cannot validate: check its clock, its forwarders, and that it trusts "
	unsigned := root
	unsigned.signers = nil
	cases := []struct {
		name   string
		root   rootKeys
		probes []resolverProbe
		want   string
	}{
		{
			name: "one resolver lacks KSK-2024",
			root: root,
			probes: []resolverProbe{probeOf("a", tags, classVnew, classVold),
				probeOf("b", tags, classVnew, classVnew)},
			want: sentinelHeader + "# a lacks 38696.\n" + sentinelRefreshSteps + ds38696,
		},
		{
			name: "undetermined resolver is not named",
			root: root,
			probes: []resolverProbe{probeOf("a", tags, classVnew, classVold),
				probeOf("d", tags, classVold, classOther)},
			want: sentinelHeader + "# a lacks 38696.\n" + sentinelRefreshSteps + ds38696,
		},
		{
			name:   "a resolver that cannot validate needs the signer and the next KSK",
			root:   root,
			probes: []resolverProbe{probeOf("b", tags, classServfail, classServfail)},
			want: sentinelHeader + broken + "20326,38696.\n" + sentinelRefreshSteps + ds20326 +
				ds38696,
		},
		{
			name: "lacking and broken resolvers together",
			root: root,
			probes: []resolverProbe{probeOf("a", tags, classVnew, classVold),
				probeOf("b", tags, classServfail, classServfail)},
			want: sentinelHeader + "# a lacks 38696.\n" + broken + "20326,38696.\n" +
				sentinelRefreshSteps + ds20326 + ds38696,
		},
		{
			name:   "no verified signer: a resolver that cannot validate needs every KSK",
			root:   unsigned,
			probes: []resolverProbe{probeOf("b", tags, classServfail, classServfail)},
			want: sentinelHeader + broken + "20326,38696.\n" + sentinelRefreshSteps + ds20326 +
				ds38696,
		},
	}
	for _, c := range cases {
		verdicts := make([]resolverVerdict, len(c.probes))
		for i, p := range c.probes {
			verdicts[i] = p.verdict(c.root)
		}
		if got := sentinelRemediation(c.root, c.probes, verdicts); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}

// fakeResolver models a recursive resolver as RFC 8509 describes one. It
// answers ". DNSKEY" with keys, the RRSIGs only when DO is set (RFC 4035
// §3.2.1). When it validates, it SERVFAILs every query without CD unless it
// trusts a KSK that signs keys, and applies the sentinel to A and AAAA
// queries without CD unless noSentinel is set. It sets AD only for DO=1
// queries (RFC 6840 §5.8), and RA on every reply.
type fakeResolver struct {
	keys       []mdns.RR       // root DNSKEY RRset and its RRSIGs
	anchors    map[uint16]bool // trusted root key tags
	validating bool
	noSentinel bool                      // validates without implementing RFC 8509
	servfail   bool                      // answers every query SERVFAIL, even with CD=1
	silent     bool                      // never answers
	tamper     func(req, resp *mdns.Msg) // if set, edits each A reply before it is sent
	onRootKeys func()                    // if set, called before answering ". DNSKEY"

	mu   sync.Mutex
	seen []string // "<qname> <qtype>[ +do][ +cd]" for each query received
}

func anchorsOf(tags ...uint16) map[uint16]bool {
	anchors := map[uint16]bool{}
	for _, tag := range tags {
		anchors[tag] = true
	}
	return anchors
}

func trusting(keys []mdns.RR, tags ...uint16) *fakeResolver {
	return &fakeResolver{keys: keys, anchors: anchorsOf(tags...), validating: true}
}

func (f *fakeResolver) ServeDNS(w mdns.ResponseWriter, req *mdns.Msg) {
	q := req.Question[0]
	f.record(req)
	if isRootDNSKEY(q) && f.onRootKeys != nil {
		f.onRootKeys()
	}
	if f.silent {
		return
	}
	resp := new(mdns.Msg)
	resp.SetRcode(req, f.rcodeFor(req))
	resp.RecursionAvailable = true
	if isRootDNSKEY(q) && resp.Rcode == mdns.RcodeSuccess {
		resp.Answer = f.rootAnswer(req)
	}
	resp.AuthenticatedData = f.authentic(req, resp.Rcode)
	if q.Qtype == mdns.TypeA && f.tamper != nil {
		f.tamper(req, resp)
	}
	_ = w.WriteMsg(resp)
}

func (f *fakeResolver) record(req *mdns.Msg) {
	q := req.Question[0]
	s := q.Name + " " + mdns.TypeToString[q.Qtype]
	if opt := req.IsEdns0(); opt != nil && opt.Do() {
		s += " +do"
	}
	if req.CheckingDisabled {
		s += " +cd"
	}
	f.mu.Lock()
	f.seen = append(f.seen, s)
	f.mu.Unlock()
}

func isRootDNSKEY(q mdns.Question) bool {
	return q.Name == "." && q.Qtype == mdns.TypeDNSKEY
}

func (f *fakeResolver) rcodeFor(req *mdns.Msg) int {
	switch {
	case f.servfail, f.bogus(req):
		return mdns.RcodeServerFailure
	case isRootDNSKEY(req.Question[0]):
		return mdns.RcodeSuccess
	case f.appliesSentinel(req):
		return f.sentinelRcode(req.Question[0].Name)
	}
	return mdns.RcodeNameError
}

// bogus reports whether a validating resolver must fail req: with checking
// enabled it validates nothing unless it trusts a KSK that signs the root
// DNSKEY RRset.
func (f *fakeResolver) bogus(req *mdns.Msg) bool {
	if !f.validating || req.CheckingDisabled {
		return false
	}
	for _, rr := range f.keys {
		if sig, ok := rr.(*mdns.RRSIG); ok && f.anchors[sig.KeyTag] {
			return false
		}
	}
	return true
}

func (f *fakeResolver) appliesSentinel(req *mdns.Msg) bool {
	qtype := req.Question[0].Qtype
	return f.validating && !f.noSentinel && !req.CheckingDisabled &&
		(qtype == mdns.TypeA || qtype == mdns.TypeAAAA)
}

// sentinelRcode returns the original answer (NXDOMAIN) when an is-ta tag is
// trusted or a not-ta tag is not, and SERVFAIL otherwise.
func (f *fakeResolver) sentinelRcode(qname string) int {
	label, _, _ := strings.Cut(qname, ".")
	digits, isTA := strings.CutPrefix(label, "root-key-sentinel-is-ta-")
	if !isTA {
		var found bool
		if digits, found = strings.CutPrefix(label, "root-key-sentinel-not-ta-"); !found {
			return mdns.RcodeNameError
		}
	}
	tag, err := strconv.ParseUint(digits, 10, 16)
	if err != nil || len(digits) != 5 || f.anchors[uint16(tag)] == isTA {
		return mdns.RcodeNameError
	}
	return mdns.RcodeServerFailure
}

func (f *fakeResolver) authentic(req *mdns.Msg, rcode int) bool {
	opt := req.IsEdns0()
	return f.validating && opt != nil && opt.Do() && rcode != mdns.RcodeServerFailure
}

func (f *fakeResolver) rootAnswer(req *mdns.Msg) []mdns.RR {
	if opt := req.IsEdns0(); opt != nil && opt.Do() {
		return f.keys
	}
	return slices.DeleteFunc(slices.Clone(f.keys), func(rr mdns.RR) bool {
		_, isSig := rr.(*mdns.RRSIG)
		return isSig
	})
}

func (f *fakeResolver) queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(slices.Values(f.seen))
}

// startFakeResolver serves f on a loopback UDP port and returns its spec.
func startFakeResolver(t *testing.T, f *fakeResolver) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: f}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("fake resolver did not start within 2s")
	}
	return pc.LocalAddr().String()
}

// newSentinelEnv returns an Env whose upstreams are the fakes, in order, and
// the upstreams' specs.
func newSentinelEnv(t *testing.T, timeout time.Duration, fakes ...*fakeResolver) (
	*probe.Env, []string,
) {
	t.Helper()
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	specs := make([]string, len(fakes))
	for i, f := range fakes {
		specs[i] = startFakeResolver(t, f)
	}
	env, err := probe.NewEnvMulti("example.test", timeout, false, specs)
	if err != nil {
		t.Fatalf("NewEnvMulti(%v): %v", specs, err)
	}
	return env, specs
}

// expand replaces {0}, {1}, ... in tmpl with the upstream specs.
func expand(tmpl string, specs []string) string {
	pairs := make([]string, 0, 2*len(specs))
	for i, spec := range specs {
		pairs = append(pairs, "{"+strconv.Itoa(i)+"}", spec)
	}
	return strings.NewReplacer(pairs...).Replace(tmpl)
}

func runSentinelOnce(t *testing.T, ctx context.Context, env *probe.Env) report.Result {
	t.Helper()
	res := runSentinel(ctx, env)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(res), res)
	}
	r := res[0]
	if r.ID != sentinelID || r.Category != category || !slices.Equal(r.RFCRefs, sentinelRefs) {
		t.Errorf("result identity = %q/%q/%q", r.ID, r.Category, r.RFCRefs)
	}
	return r
}

// syntheticKSKs returns n root KSKs with distinct key tags.
func syntheticKSKs(n int) []mdns.RR {
	out := make([]mdns.RR, n)
	for i := range out {
		out[i] = rootKSK([]byte{byte(i + 1), 1, 0, 1})
	}
	return out
}

// rootKSK returns an active root KSK (flags 257, protocol 3) with public key pub.
func rootKSK(pub []byte) *mdns.DNSKEY {
	return &mdns.DNSKEY{
		Hdr:       mdns.RR_Header{Name: ".", Rrtype: mdns.TypeDNSKEY, Class: mdns.ClassINET},
		Flags:     mdns.ZONE | mdns.SEP,
		Protocol:  3,
		Algorithm: mdns.RSASHA256,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
}

// syntheticSeeds give Ed25519 root keys the real root key tags, so a test can
// sign a root DNSKEY RRset now and still probe the real tags.
var syntheticSeeds = []struct {
	seed  uint64
	flags uint16
	tag   uint16
}{
	{14655, mdns.ZONE | mdns.SEP, 20326}, // stands in for KSK-2017
	{2163, mdns.ZONE | mdns.SEP, 38696},  // stands in for KSK-2024
	{1, mdns.ZONE, 31698},                // a ZSK
}

// testKey derives an Ed25519 root DNSKEY with the given flags from seed.
func testKey(seed uint64, flags uint16) (*mdns.DNSKEY, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	binary.BigEndian.PutUint64(s[ed25519.SeedSize-8:], seed)
	priv := ed25519.NewKeyFromSeed(s)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &mdns.DNSKEY{
		Hdr: mdns.RR_Header{Name: ".", Rrtype: mdns.TypeDNSKEY, Class: mdns.ClassINET,
			Ttl: 172800},
		Flags:     flags,
		Protocol:  3,
		Algorithm: mdns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}, priv
}

// syntheticRoot returns a root DNSKEY RRset of KSKs 20326 and 38696, a ZSK
// (31698) and extra, plus an RRSIG over it by each of signers, valid from an
// hour ago until tomorrow.
func syntheticRoot(t *testing.T, extra []mdns.RR, signers ...uint16) []mdns.RR {
	t.Helper()
	privs := map[uint16]ed25519.PrivateKey{}
	var rrset []mdns.RR
	for _, s := range syntheticSeeds {
		k, priv := testKey(s.seed, s.flags)
		if k.KeyTag() != s.tag {
			t.Fatalf("seed %d: key tag %d, want %d", s.seed, k.KeyTag(), s.tag)
		}
		privs[s.tag] = priv
		rrset = append(rrset, k)
	}
	rrset = append(rrset, extra...)
	out := slices.Clone(rrset)
	now := time.Now()
	for _, tag := range signers {
		sig := &mdns.RRSIG{
			Hdr:        mdns.RR_Header{Ttl: 172800},
			Algorithm:  mdns.ED25519,
			SignerName: ".",
			KeyTag:     tag,
			Inception:  uint32(now.Add(-time.Hour).Unix()),
			Expiration: uint32(now.Add(24 * time.Hour).Unix()),
		}
		if err := sig.Sign(privs[tag], rrset); err != nil {
			t.Fatalf("sign the root DNSKEY RRset with %d: %v", tag, err)
		}
		out = append(out, sig)
	}
	return out
}

// editSigs returns rrs with edit applied to a copy of every RRSIG.
func editSigs(rrs []mdns.RR, edit func(*mdns.RRSIG)) []mdns.RR {
	out := make([]mdns.RR, len(rrs))
	for i, rr := range rrs {
		if sig, ok := rr.(*mdns.RRSIG); ok {
			c := *sig
			edit(&c)
			rr = &c
		}
		out[i] = rr
	}
	return out
}

func retag(rrs []mdns.RR, tag uint16) []mdns.RR {
	return editSigs(rrs, func(sig *mdns.RRSIG) { sig.KeyTag = tag })
}

func badSignature(rrs []mdns.RR) []mdns.RR {
	zeros := base64.StdEncoding.EncodeToString(make([]byte, 64))
	return editSigs(rrs, func(sig *mdns.RRSIG) { sig.Signature = zeros })
}

func sigsOf(rrs []mdns.RR) []mdns.RR {
	return slices.DeleteFunc(slices.Clone(rrs), func(rr mdns.RR) bool {
		_, isSig := rr.(*mdns.RRSIG)
		return !isSig
	})
}

func withoutKSKs(rrs []mdns.RR) []mdns.RR {
	return slices.DeleteFunc(slices.Clone(rrs), func(rr mdns.RR) bool {
		k, ok := rr.(*mdns.DNSKEY)
		return ok && k.Flags&mdns.SEP != 0
	})
}

type sentinelCase struct {
	name        string
	upstreams   []*fakeResolver
	status      report.Status
	title       string
	evidence    string   // {i} stands for upstream i's spec
	remediation []string // substrings it must contain; nil means it must be empty
	absent      []string // substrings it must not contain
	queries     []int    // queries each upstream must receive
}

// oneUpstreamCases cover each verdict with a single upstream. A resolver
// whose root DNSKEY query succeeds receives six queries: that one, the same
// with checking disabled, and four sentinel names.
func oneUpstreamCases(t *testing.T) []sentinelCase {
	pre, post := syntheticRoot(t, nil, 20326), syntheticRoot(t, nil, 38696)
	vind := trusting(pre, 20326, 38696)
	vind.noSentinel = true
	return []sentinelCase{
		{
			name:      "trusts both KSKs",
			upstreams: []*fakeResolver{trusting(pre, 20326, 38696)},
			status:    report.Pass,
			title:     titleSentinelReady,
			evidence:  rootPreRoll + "; {0} trusts 20326,38696",
			queries:   []int{6},
		},
		{
			name:      "lacks KSK-2024 before the roll",
			upstreams: []*fakeResolver{trusting(pre, 20326)},
			status:    report.Warn,
			title:     titleSentinelMissing,
			evidence:  rootPreRoll + "; {0} does not yet trust 38696" + holdDown + "20326",
			remediation: []string{
				sentinelHeader,
				"# {0} lacks 38696.\n",
				"\n# . IN DS 38696 15 2 ",
				"https://data.iana.org/root-anchors/root-anchors.xml",
			},
			absent:  []string{"DS 20326"},
			queries: []int{6},
		},
		{
			name:      "dropped the retiring KSK after the roll",
			upstreams: []*fakeResolver{trusting(post, 38696)},
			status:    report.Pass,
			title:     titleSentinelReady,
			evidence:  rootPostRoll + "; {0} trusts 38696 but not retiring KSK 20326",
			queries:   []int{6},
		},
		{
			name:      "lacks KSK-2024 after the roll",
			upstreams: []*fakeResolver{trusting(post, 20326)},
			status:    report.Warn,
			title:     titleSentinelBroken,
			evidence:  rootPostRoll + "; {0}" + brokenText,
			remediation: []string{
				"# {0} cannot validate: check its clock, its forwarders, and that it trusts " +
					"38696.\n",
				"\n# . IN DS 38696 15 2 ",
			},
			absent:  []string{"DS 20326", "lacks"},
			queries: []int{7},
		},
		{
			name:      "trusts only KSK-2024 before the roll",
			upstreams: []*fakeResolver{trusting(pre, 38696)},
			status:    report.Warn,
			title:     titleSentinelBroken,
			evidence:  rootPreRoll + "; {0}" + brokenText,
			remediation: []string{
				"# {0} cannot validate: check its clock, its forwarders, and that it trusts " +
					"20326,38696.\n",
				"\n# . IN DS 20326 15 2 ",
				"\n# . IN DS 38696 15 2 ",
			},
			queries: []int{7},
		},
		{
			name:      "no sentinel processing",
			upstreams: []*fakeResolver{vind},
			status:    report.Info,
			title:     titleSentinelUnknown,
			evidence:  rootPreRoll + "; {0}" + vindText,
			queries:   []int{6},
		},
		{
			name:      "not validating",
			upstreams: []*fakeResolver{{keys: pre, anchors: anchorsOf(20326)}},
			status:    report.Info,
			title:     titleSentinelUnknown,
			evidence:  rootPreRoll + "; {0}" + nonVText,
			queries:   []int{6},
		},
		{
			name:      "RRSIG does not verify",
			upstreams: []*fakeResolver{trusting(badSignature(pre), 20326, 38696)},
			status:    report.Pass,
			title:     titleSentinelReady,
			evidence: "active root KSKs 20326,38696 (no RRSIG by an active KSK over the " +
				"DNSKEY RRset verifies); {0} trusts 20326,38696",
			queries: []int{6},
		},
	}
}

// rootKeyCases cover how the root DNSKEY answer shapes the test: the KSK cap
// and each reason to skip it. A skipped test sends the root DNSKEY query
// twice, the second time with checking disabled, and nothing else.
func rootKeyCases(t *testing.T) []sentinelCase {
	pre := syntheticRoot(t, nil, 20326)
	capKeys := syntheticRoot(t, syntheticKSKs(maxRootKSKs-2), 20326)
	capTags := rootKeys{ksks: activeRootKSKs(answerMsg(capKeys...))}.tags()
	return []sentinelCase{
		{
			name:      "exactly the KSK cap",
			upstreams: []*fakeResolver{trusting(capKeys, capTags...)},
			status:    report.Pass,
			title:     titleSentinelReady,
			evidence: "active root KSKs " + joinTags(capTags) + " (DNSKEY RRset signed by " +
				"20326, signature verified); {0} trusts " + joinTags(capTags),
			queries: []int{2 + 2*maxRootKSKs},
		},
		{
			name:      "answers SERVFAIL even with checking disabled",
			upstreams: []*fakeResolver{{servfail: true}},
			status:    report.Info,
			title:     titleSentinelSkipped,
			evidence:  "no resolver returned a usable root DNSKEY RRset: {0}: answered SERVFAIL",
			queries:   []int{2},
		},
		{
			name:      "no active KSK",
			upstreams: []*fakeResolver{trusting(withoutKSKs(pre), 20326)},
			status:    report.Info,
			title:     titleSentinelSkipped,
			evidence:  "no resolver returned a usable root DNSKEY RRset: {0}: no active KSK",
			queries:   []int{2},
		},
		{
			name: "more KSKs than the cap",
			upstreams: []*fakeResolver{trusting(syntheticRoot(t, syntheticKSKs(maxRootKSKs-1),
				20326), 20326)},
			status: report.Info,
			title:  titleSentinelSkipped,
			evidence: "no resolver returned a usable root DNSKEY RRset: {0}: " +
				"5 active KSKs (limit 4)",
			queries: []int{2},
		},
	}
}

// tamperedCases cover replies that carry no sentinel signal: none may be read
// as a trust anchor state.
func tamperedCases(t *testing.T) []sentinelCase {
	pre := syntheticRoot(t, nil, 20326)
	synthesized := trusting(pre, 20326, 38696)
	synthesized.noSentinel = true
	synthesized.tamper = func(_, resp *mdns.Msg) {
		withEDE(mdns.ExtendedErrorCodeSynthesized)(resp)
	}
	tampered := func(anchors []uint16, edit func(req, resp *mdns.Msg)) []*fakeResolver {
		f := trusting(pre, anchors...)
		f.tamper = edit
		return []*fakeResolver{f}
	}
	addressed := func(resp *mdns.Msg) {
		resp.Answer = append(resp.Answer, &mdns.A{Hdr: mdns.RR_Header{Name: resp.Question[0].Name,
			Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(198, 51, 100, 7)})
	}
	allErrors := "20326 is-ta=error not-ta=error, 38696 is-ta=error not-ta=error: "
	return []sentinelCase{
		{
			name: "rewritten answers",
			upstreams: tampered([]uint16{20326, 38696}, func(_, resp *mdns.Msg) {
				resp.Rcode, resp.AuthenticatedData = mdns.RcodeSuccess, true
				addressed(resp)
			}),
			evidence: rootPreRoll + "; {0} undetermined (20326 is-ta=NOERROR+AD+answer " +
				"not-ta=NOERROR+AD+answer, 38696 is-ta=NOERROR+AD+answer not-ta=NOERROR+AD+answer)",
		},
		{
			name: "SERVFAIL carrying an answer",
			upstreams: tampered([]uint16{20326}, func(req, resp *mdns.Msg) {
				if req.Question[0].Name == "root-key-sentinel-is-ta-38696.arpa." {
					addressed(resp)
				}
			}),
			evidence: rootPreRoll + "; {0} undetermined (20326 is-ta=NXDOMAIN+AD " +
				"not-ta=SERVFAIL, 38696 is-ta=SERVFAIL+answer not-ta=NXDOMAIN+AD)",
		},
		{
			name: "question not echoed",
			upstreams: tampered([]uint16{20326, 38696}, func(_, resp *mdns.Msg) {
				resp.Question = []mdns.Question{{Name: "something-else.example.",
					Qtype: mdns.TypeTXT, Qclass: mdns.ClassINET}}
			}),
			evidence: rootPreRoll + "; {0} undetermined (" + allErrors +
				"reply does not match the query)",
		},
		{
			name: "authoritative answers",
			upstreams: tampered([]uint16{20326, 38696}, func(_, resp *mdns.Msg) {
				resp.Authoritative = true
			}),
			evidence: rootPreRoll + "; {0} undetermined (" + allErrors +
				"answered from local zone data (AA=1))",
		},
		{
			name: "recursion not available",
			upstreams: tampered([]uint16{20326, 38696}, func(_, resp *mdns.Msg) {
				resp.RecursionAvailable = false
			}),
			evidence: rootPreRoll + "; {0} undetermined (" + allErrors +
				"not a recursive resolver (RA=0))",
		},
		{
			name: "answer synthesized without the sentinel",
			upstreams: tampered([]uint16{20326, 38696}, func(req, resp *mdns.Msg) {
				if req.Question[0].Name == "root-key-sentinel-not-ta-38696.arpa." {
					resp.Rcode, resp.AuthenticatedData = mdns.RcodeNameError, true
					withEDE(mdns.ExtendedErrorCodeSynthesized)(resp)
				}
			}),
			evidence: rootPreRoll + "; {0} undetermined (20326 is-ta=NXDOMAIN+AD " +
				"not-ta=SERVFAIL, 38696 is-ta=NXDOMAIN+AD not-ta=NXDOMAIN+AD+EDE29 " +
				"(+EDE29: answered from cached NSEC records, RFC 8198, skipping the sentinel))",
		},
		{
			name:      "every answer synthesized from cached NSEC records",
			upstreams: []*fakeResolver{synthesized},
			evidence:  rootPreRoll + "; {0}" + vindText + " (answers carried +EDE29)",
		},
	}
}

// twoUpstreamCases pair a primary, which alone answers bedrock's other
// lookups, with a second upstream; the status must not depend on which one is
// ready. An upstream receives one query fewer when it is not asked for the
// root DNSKEY RRset with checking enabled.
func twoUpstreamCases(t *testing.T) []sentinelCase {
	pre, post := syntheticRoot(t, nil, 20326), syntheticRoot(t, nil, 38696)
	ready := func() *fakeResolver { return trusting(pre, 20326, 38696) }
	return []sentinelCase{
		{
			name:      "both ready",
			upstreams: []*fakeResolver{ready(), ready()},
			status:    report.Pass,
			title:     titleSentinelReady,
			evidence:  rootPreRoll + "; {0} (primary) trusts 20326,38696; {1} trusts 20326,38696",
			queries:   []int{6, 5},
		},
		{
			name:      "second upstream lacks KSK-2024",
			upstreams: []*fakeResolver{ready(), trusting(pre, 20326)},
			status:    report.Warn,
			title:     titleSentinelMissing,
			evidence: rootPreRoll + "; {0} (primary) trusts 20326,38696; " +
				"{1} does not yet trust 38696" + holdDown + "20326",
			remediation: []string{"# {1} lacks 38696.\n", "\n# . IN DS 38696 15 2 "},
			absent:      []string{"# {0} (primary) lacks", "DS 20326"},
			queries:     []int{6, 5},
		},
		{
			name:      "primary lacks KSK-2024",
			upstreams: []*fakeResolver{trusting(pre, 20326), ready()},
			status:    report.Warn,
			title:     titleSentinelMissing,
			evidence: rootPreRoll + "; {0} (primary) does not yet trust 38696" + holdDown +
				"20326; {1} trusts 20326,38696",
			remediation: []string{"# {0} (primary) lacks 38696.\n", "\n# . IN DS 38696 15 2 "},
			absent:      []string{"# {1} lacks", "DS 20326"},
			queries:     []int{6, 5},
		},
		{
			name:      "second upstream does not validate",
			upstreams: []*fakeResolver{ready(), {keys: pre}},
			status:    report.Info,
			title:     titleSentinelUnknown,
			evidence:  rootPreRoll + "; {0} (primary) trusts 20326,38696; {1}" + nonVText,
			queries:   []int{6, 5},
		},
		{
			name:      "primary does not validate",
			upstreams: []*fakeResolver{{keys: pre}, ready()},
			status:    report.Info,
			title:     titleSentinelUnknown,
			evidence:  rootPreRoll + "; {0} (primary)" + nonVText + "; {1} trusts 20326,38696",
			queries:   []int{6, 5},
		},
		{
			name:      "second upstream answers SERVFAIL even with checking disabled",
			upstreams: []*fakeResolver{ready(), {servfail: true}},
			status:    report.Info,
			title:     titleSentinelUnknown,
			evidence: rootPreRoll + "; {0} (primary) trusts 20326,38696; {1} undetermined (" +
				"root DNSKEY with checking disabled: answered SERVFAIL, replies " +
				"20326 is-ta=SERVFAIL not-ta=SERVFAIL, 38696 is-ta=SERVFAIL not-ta=SERVFAIL)",
			queries: []int{6, 5},
		},
		{
			name:      "primary answers SERVFAIL even with checking disabled",
			upstreams: []*fakeResolver{{servfail: true}, ready()},
			status:    report.Info,
			title:     titleSentinelUnknown,
			evidence: rootPreRoll + "; {0} (primary) undetermined (root DNSKEY with checking " +
				"disabled: answered SERVFAIL, replies 20326 is-ta=SERVFAIL not-ta=SERVFAIL, " +
				"38696 is-ta=SERVFAIL not-ta=SERVFAIL); {1} trusts 20326,38696",
			queries: []int{7, 6},
		},
		{
			name:      "primary lacks KSK-2024 after the roll",
			upstreams: []*fakeResolver{trusting(post, 20326), trusting(post, 20326, 38696)},
			status:    report.Warn,
			title:     titleSentinelBroken,
			evidence:  rootPostRoll + "; {0} (primary)" + brokenText + "; {1} trusts 20326,38696",
			remediation: []string{
				"# {0} (primary) cannot validate: check its clock, its forwarders, and that it " +
					"trusts 38696.\n",
				"\n# . IN DS 38696 15 2 ",
			},
			absent:  []string{"# {1}", "DS 20326"},
			queries: []int{7, 6},
		},
	}
}

// TestRunSentinel runs the check end to end against fake resolvers that
// implement RFC 8509, one or two at a time.
func TestRunSentinel(t *testing.T) {
	var cases []sentinelCase
	cases = append(cases, oneUpstreamCases(t)...)
	cases = append(cases, rootKeyCases(t)...)
	for _, c := range tamperedCases(t) {
		c.status, c.title, c.queries = report.Info, titleSentinelUnknown, []int{6}
		cases = append(cases, c)
	}
	cases = append(cases, twoUpstreamCases(t)...)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, specs := newSentinelEnv(t, 2*time.Second, c.upstreams...)

			r := runSentinelOnce(t, context.Background(), env)

			if r.Status != c.status || r.Title != c.title {
				t.Errorf("got %s %q, want %s %q", r.Status, r.Title, c.status, c.title)
			}
			if want := expand(c.evidence, specs); r.Evidence != want {
				t.Errorf("evidence:\n got %q\nwant %q", r.Evidence, want)
			}
			checkRemediation(t, r.Remediation, c, specs)
			for i, f := range c.upstreams {
				if got := len(f.queries()); got != c.queries[i] {
					t.Errorf("upstream %d got %d queries %q, want %d", i, got, f.queries(),
						c.queries[i])
				}
			}
		})
	}
}

func checkRemediation(t *testing.T, got string, c sentinelCase, specs []string) {
	t.Helper()
	if c.remediation == nil && got != "" {
		t.Errorf("want no remediation, got %q", got)
	}
	for _, sub := range c.remediation {
		if want := expand(sub, specs); !strings.Contains(got, want) {
			t.Errorf("remediation lacks %q:\n%s", want, got)
		}
	}
	for _, sub := range c.absent {
		if bad := expand(sub, specs); strings.Contains(got, bad) {
			t.Errorf("remediation contains %q:\n%s", bad, got)
		}
	}
}

// TestRunSentinelQueriesOnlyTheRoot pins what reaches each resolver: the
// root DNSKEY query with DO on the primary, the same with CD on every
// upstream, and the sentinel A queries with DO and without CD (RFC 8509
// §2.1). Nothing about the target leaves the host.
func TestRunSentinelQueriesOnlyTheRoot(t *testing.T) {
	keys := syntheticRoot(t, nil, 20326)
	primary, secondary := trusting(keys, 20326, 38696), trusting(keys, 20326)
	env, _ := newSentinelEnv(t, 2*time.Second, primary, secondary)

	runSentinelOnce(t, context.Background(), env)

	sentinels := []string{
		". DNSKEY +do +cd",
		"root-key-sentinel-is-ta-20326.arpa. A +do", "root-key-sentinel-is-ta-38696.arpa. A +do",
		"root-key-sentinel-not-ta-20326.arpa. A +do", "root-key-sentinel-not-ta-38696.arpa. A +do",
	}
	wantPrimary := append([]string{". DNSKEY +do"}, sentinels...)
	if got := primary.queries(); !slices.Equal(got, wantPrimary) {
		t.Errorf("primary queries = %q, want %q", got, wantPrimary)
	}
	if got := secondary.queries(); !slices.Equal(got, sentinels) {
		t.Errorf("secondary queries = %q, want %q", got, sentinels)
	}
}

// TestRunSentinelSilentPrimary skips the test when the only upstream never
// answers, and otherwise reads the root DNSKEY RRset from the next upstream.
func TestRunSentinelSilentPrimary(t *testing.T) {
	const timeout = 300 * time.Millisecond
	t.Run("alone", func(t *testing.T) {
		env, specs := newSentinelEnv(t, timeout, &fakeResolver{silent: true})

		r := runSentinelOnce(t, context.Background(), env)

		prefix := expand("no resolver returned a usable root DNSKEY RRset: {0}: ", specs)
		if r.Status != report.Info || r.Title != titleSentinelSkipped ||
			!strings.HasPrefix(r.Evidence, prefix) {
			t.Errorf("got %s %q %q, want a skipped INFO starting %q", r.Status, r.Title,
				r.Evidence, prefix)
		}
	})
	t.Run("with a ready second upstream", func(t *testing.T) {
		env, specs := newSentinelEnv(t, timeout, &fakeResolver{silent: true},
			trusting(syntheticRoot(t, nil, 20326), 20326, 38696))

		r := runSentinelOnce(t, context.Background(), env)

		prefix := expand(rootPreRoll+"; {0} (primary) undetermined (root DNSKEY with "+
			"checking disabled: ", specs)
		suffix := expand("; {1} trusts 20326,38696", specs)
		if r.Status != report.Info || !strings.HasPrefix(r.Evidence, prefix) ||
			!strings.HasSuffix(r.Evidence, suffix) {
			t.Errorf("got %s %q, want INFO starting %q and ending %q", r.Status, r.Evidence,
				prefix, suffix)
		}
	})
}

// TestRunSentinelSpecError skips the test, naming the configuration error,
// when no upstream could be set up.
func TestRunSentinelSpecError(t *testing.T) {
	env := probe.NewEnv("example.test", time.Second, false, " ")

	r := runSentinelOnce(t, context.Background(), env)

	want := "no resolver returned a usable root DNSKEY RRset: empty resolver spec"
	if r.Status != report.Info || r.Title != titleSentinelSkipped || r.Evidence != want {
		t.Errorf("got %s %q %q, want a skipped INFO %q", r.Status, r.Title, r.Evidence, want)
	}
}

// TestRunSentinelSilentSecondary reports a black-holed upstream as
// undetermined, and bounds the check to about one query timeout because
// every query of the round runs concurrently.
func TestRunSentinelSilentSecondary(t *testing.T) {
	const timeout = 500 * time.Millisecond
	env, specs := newSentinelEnv(t, timeout,
		trusting(syntheticRoot(t, nil, 20326), 20326, 38696), &fakeResolver{silent: true})

	start := time.Now()
	r := runSentinelOnce(t, context.Background(), env)
	elapsed := time.Since(start)

	prefix := expand(rootPreRoll+"; {0} (primary) trusts 20326,38696; {1} undetermined ("+
		"root DNSKEY with checking disabled: ", specs)
	replies := ", replies 20326 is-ta=error not-ta=error, 38696 is-ta=error not-ta=error: "
	if r.Status != report.Info || !strings.HasPrefix(r.Evidence, prefix) ||
		!strings.Contains(r.Evidence, replies) {
		t.Errorf("got %s %q, want INFO with evidence starting %q", r.Status, r.Evidence, prefix)
	}
	if elapsed >= 3*timeout {
		t.Errorf("check took %v; five sequential timeouts would take %v", elapsed, 5*timeout)
	}
}

// TestRunSentinelCancelled degrades to INFO rather than failing the scan,
// and sends nothing once the caller has cancelled.
func TestRunSentinelCancelled(t *testing.T) {
	primary := trusting(syntheticRoot(t, nil, 20326), 20326, 38696)
	env, specs := newSentinelEnv(t, 2*time.Second, primary)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := runSentinelOnce(t, ctx, env)

	prefix := expand("no resolver returned a usable root DNSKEY RRset: {0}: ", specs)
	if r.Status != report.Info || r.Title != titleSentinelSkipped ||
		!strings.HasPrefix(r.Evidence, prefix) || !strings.Contains(r.Evidence, "cancel") {
		t.Errorf("got %s %q %q, want a skipped INFO naming the cancellation", r.Status, r.Title,
			r.Evidence)
	}
	if got := primary.queries(); len(got) != 0 {
		t.Errorf("queries after cancellation = %q, want none", got)
	}
}

// TestRunSentinelCancelledAfterRootFetch sends no sentinel query once the
// caller has cancelled, even though the root DNSKEY answer already arrived.
func TestRunSentinelCancelledAfterRootFetch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	primary := trusting(syntheticRoot(t, nil, 20326), 20326, 38696)
	primary.onRootKeys = cancel
	env, specs := newSentinelEnv(t, 2*time.Second, primary)

	r := runSentinelOnce(t, ctx, env)

	prefix := expand(rootPreRoll+"; {0} undetermined (", specs)
	if r.Status != report.Info || !strings.HasPrefix(r.Evidence, prefix) ||
		!strings.Contains(r.Evidence, "cancel") {
		t.Errorf("got %s %q, want INFO with evidence starting %q and naming the cancellation",
			r.Status, r.Evidence, prefix)
	}
	if got := primary.queries(); !slices.Equal(got, []string{". DNSKEY +do"}) {
		t.Errorf("queries after cancellation = %q, want only the root DNSKEY query", got)
	}
}
