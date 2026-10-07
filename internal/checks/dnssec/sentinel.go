package dnssec

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// The RFC 8509 key-tag sentinel reports on the resolvers bedrock queries, not
// on the target domain, and nothing about the target leaves the host. Probing
// each upstream directly avoids RFC 8509 §4.2's assumption that a stub fails
// over between resolvers, and gives the extra precision that section mentions.
// The probes are A queries for root-key-sentinel-{is,not}-ta-<tag>.arpa. arpa
// is signed with NSEC, so a validating resolver authenticates its NXDOMAIN for
// those names, which meets the §2.1 preconditions. The names sit under arpa
// rather than the root because a resolver that mirrors the root zone (RFC
// 8806) answers root names from zone data, which BIND exempts from the
// sentinel. A resolver may also skip the sentinel for an answer it synthesizes
// from cached NSEC records (RFC 8198); that reads as no sentinel processing,
// never as a missing key.

const (
	sentinelID = "dnssec.sentinel"

	// maxRootKSKs caps how many root KSKs are probed so that a forged or
	// corrupt root DNSKEY RRset cannot multiply the query count. A root
	// rollover publishes two active KSKs at a time.
	maxRootKSKs = 4

	titleSentinelReady   = "Resolver root trust anchors are current"
	titleSentinelMissing = "Resolver missing an active root KSK trust anchor"
	titleSentinelBroken  = "Resolver cannot validate the root zone"
	titleSentinelUnknown = "Resolver root KSK trust state undetermined"
	titleSentinelSkipped = "Root KSK sentinel test skipped"

	sentinelHeader = "# A validating resolver fails every lookup (SERVFAIL), signed or not,\n" +
		"# once the root DNSKEY RRset is signed only by a KSK missing from its\n" +
		"# trust anchors.\n"

	sentinelRefreshSteps = "# Refresh the resolver's root trust anchors:\n" +
		"#   Unbound: unbound-anchor -F -a <auto-trust-anchor-file> refetches IANA's\n" +
		"#            anchors and checks them with ICANN's certificate; restart unbound.\n" +
		"#   BIND 9:  upgrade to a release whose built-in keys include the KSK, then run\n" +
		"#            rndc managed-keys destroy and rndc reconfig to start from them.\n" +
		"#   Static trust anchors (trust-anchor-file, static-ds): add the DS below.\n" +
		"# RFC 5011 tracking trusts a new KSK only after a 30-day hold-down (§2.4.1).\n" +
		"# Confirm each DS below at https://data.iana.org/root-anchors/root-anchors.xml\n" +
		"# before installing it as a trust anchor:"
)

var (
	sentinelRefs = []string{"RFC 8509 §3", "RFC 5011"}

	// retiringRootKSKs are root KSKs on their way out. KSK-2017 stops signing
	// the root DNSKEY RRset at the 2026-10-11 roll to KSK-2024 and is revoked
	// later, so a resolver that has dropped it loses nothing. Revisit this set
	// at the next roll.
	retiringRootKSKs = map[uint16]bool{20326: true}

	errNoReply      = errors.New("no reply")
	errMismatch     = errors.New("reply does not match the query")
	errNoActiveKSK  = errors.New("no active KSK")
	errNotRecursive = errors.New("not a recursive resolver (RA=0)")
	errLocalZone    = errors.New("answered from local zone data (AA=1)")
)

// rootKeys is the root DNSKEY RRset as an upstream returned it.
type rootKeys struct {
	ksks    []*mdns.DNSKEY // active KSKs, ascending by key tag, tags unique
	signers []uint16       // tags of the KSKs whose RRSIG over the RRset verifies
}

// sentinelReply is one sentinel query's outcome.
type sentinelReply struct {
	rcode  int
	ad     bool
	answer bool   // the Answer section is not empty
	ede    string // extended DNS error codes (RFC 8914), "+EDE<code>" each
	err    error
}

// sentinelClass is the RFC 8509 §3 resolver type for one key tag. The AD bit
// on the two answers stands in for the RFC's third ("bogus") query when
// telling Vind from nonV.
type sentinelClass int

const (
	classOther    sentinelClass = iota // no determination possible
	classVnew                          // key tag trusted
	classVold                          // key tag not (yet) trusted
	classVind                          // validating, no sentinel processing
	classNonV                          // not validating
	classServfail                      // both names SERVFAIL: "other" in §3
)

// replyKind reduces a reply to what the RFC 8509 §3 table distinguishes.
type replyKind int

const (
	replyUnusable replyKind = iota // error, unexpected rcode, or answer records
	replyServfail
	replyAnswered // NOERROR or NXDOMAIN with no answer: the "original answer"
)

// resolverVerdict summarizes one upstream across every probed KSK.
type resolverVerdict int

const (
	verdictUnknown resolverVerdict = iota
	verdictReady
	verdictMissing
	verdictBroken
	verdictUnsupported
	verdictNotValidating
)

// resolverProbe holds one upstream's replies: replies[i] is the (is-ta,
// not-ta) pair for tags[i]. rootErr says why the upstream's own root DNSKEY
// answer, sent with checking disabled, was unusable.
type resolverProbe struct {
	label   string
	tags    []uint16
	replies [][2]sentinelReply
	rootErr error
}

// runSentinel checks whether the resolvers bedrock uses can validate the root
// zone and trust its active KSKs. It never returns FAIL: the subject is the
// scanning environment, not the target, so it must not drive the exit code.
func runSentinel(ctx context.Context, env *probe.Env) []report.Result {
	now := time.Now()
	root, err := discoverRootKeys(ctx, env, now)
	if err != nil {
		return []report.Result{sentinelResult(report.Info, titleSentinelSkipped, err.Error(), "")}
	}
	tags := root.tags()
	names := sentinelNames(tags)
	resps, rootResps := sentinelRound(ctx, env, names)
	probes := groupByResolver(tags, names, resps, rootErrors(rootResps, now))
	return []report.Result{summarizeSentinel(root, probes)}
}

// discoverRootKeys reads the active root KSKs from the primary's root DNSKEY
// answer. A primary that cannot validate the root SERVFAILs that query, so on
// failure every upstream is asked with checking disabled, and the first
// usable answer in upstream order wins.
func discoverRootKeys(ctx context.Context, env *probe.Env, now time.Time) (rootKeys, error) {
	resp, err := env.DNS.ExchangeWithDO(ctx, ".", mdns.TypeDNSKEY)
	root, err := rootKeysFrom(resp, err, now)
	if err == nil {
		return root, nil
	}
	var failures []string
	for _, r := range env.DNS.ExchangeAllCheckingDisabled(ctx, ".", mdns.TypeDNSKEY) {
		if root, err = rootKeysFrom(r.Msg, r.Err, now); err == nil {
			return root, nil
		}
		failures = append(failures, labelled(r.Upstream, err))
	}
	return rootKeys{}, errors.New("no resolver returned a usable root DNSKEY RRset: " +
		strings.Join(failures, "; "))
}

// rootKeysFrom reads the active root KSKs from a root DNSKEY answer, and which
// of them sign it.
func rootKeysFrom(m *mdns.Msg, err error, now time.Time) (rootKeys, error) {
	m, err = checkReply(m, err, ".", mdns.TypeDNSKEY)
	if err != nil {
		return rootKeys{}, err
	}
	if m.Rcode != mdns.RcodeSuccess {
		return rootKeys{}, fmt.Errorf("answered %s", rcodeName(m.Rcode))
	}
	ksks := activeRootKSKs(m)
	switch {
	case len(ksks) == 0:
		return rootKeys{}, errNoActiveKSK
	case len(ksks) > maxRootKSKs:
		return rootKeys{}, fmt.Errorf("%d active KSKs (limit %d)", len(ksks), maxRootKSKs)
	}
	return rootKeys{ksks: ksks, signers: verifiedSigners(m, ksks, now)}, nil
}

// checkReply returns m if it answers the query for name and qtype: miekg/dns
// pairs a UDP reply with its query by message ID alone, and DoH not at all.
func checkReply(m *mdns.Msg, err error, name string, qtype uint16) (*mdns.Msg, error) {
	switch {
	case err != nil:
		return nil, err
	case m == nil:
		return nil, errNoReply
	case !echoesQuery(m, name, qtype):
		return nil, errMismatch
	}
	return m, nil
}

// echoesQuery reports whether m responds to a standard query for name and
// qtype in class IN.
func echoesQuery(m *mdns.Msg, name string, qtype uint16) bool {
	if !m.Response || m.Opcode != mdns.OpcodeQuery || len(m.Question) != 1 {
		return false
	}
	q := m.Question[0]
	return strings.EqualFold(q.Name, name) && q.Qtype == qtype && q.Qclass == mdns.ClassINET
}

// isActiveRootKSK reports whether k could serve as a root trust anchor today:
// a zone key with the SEP flag (RFC 4034 §2.1.1), protocol 3, and no RFC 5011
// REVOKE bit. RFC 8509 §2.2 also excludes keys a resolver holds in AddPend,
// which only the resolver can observe.
func isActiveRootKSK(k *mdns.DNSKEY) bool {
	return k.Hdr.Name == "." && k.Protocol == 3 &&
		k.Flags&(mdns.ZONE|mdns.SEP|mdns.REVOKE) == mdns.ZONE|mdns.SEP
}

// activeRootKSKs returns the active root KSKs in resp, ascending by key tag
// and unique by tag, because the sentinel names a key by its tag alone. It
// drops keys whose RDATA overflows miekg's 4096-byte pack buffer, which a TCP
// or DoH answer can carry: KeyTag reports 0 and ToDS nil for those.
func activeRootKSKs(resp *mdns.Msg) []*mdns.DNSKEY {
	var out []*mdns.DNSKEY
	for _, k := range extractDNSKEY(resp) {
		if isActiveRootKSK(k) && k.ToDS(mdns.SHA256) != nil {
			out = append(out, k)
		}
	}
	slices.SortStableFunc(out, func(a, b *mdns.DNSKEY) int {
		return cmp.Compare(a.KeyTag(), b.KeyTag())
	})
	return slices.CompactFunc(out, func(a, b *mdns.DNSKEY) bool {
		return a.KeyTag() == b.KeyTag()
	})
}

// verifiedSigners returns the tags of the KSKs among ksks whose RRSIG over the
// root DNSKEY RRset in m verifies and is current at now. The answer may come
// unvalidated, fetched with checking disabled, so an RRSIG's key tag alone
// proves nothing.
func verifiedSigners(m *mdns.Msg, ksks []*mdns.DNSKEY, now time.Time) []uint16 {
	rrset := asRRSet(m.Answer, mdns.TypeDNSKEY)
	var tags []uint16
	for _, sig := range extractRRSIGCovering(m, mdns.TypeDNSKEY) {
		k := findKey(ksks, sig.KeyTag, sig.Algorithm)
		if k != nil && !slices.Contains(tags, sig.KeyTag) && sig.ValidityPeriod(now) &&
			sig.Verify(k, rrset) == nil {
			tags = append(tags, sig.KeyTag)
		}
	}
	slices.Sort(tags)
	return tags
}

func (r rootKeys) tags() []uint16 {
	tags := make([]uint16, len(r.ksks))
	for i, k := range r.ksks {
		tags[i] = k.KeyTag()
	}
	return tags
}

// validatingTags returns the KSKs a resolver must trust to validate the root:
// the verified signers, or every active KSK when no signature verified.
func (r rootKeys) validatingTags() []uint16 {
	if len(r.signers) > 0 {
		return r.signers
	}
	return r.tags()
}

// neededTags returns the KSKs a resolver must trust to validate the root now
// and after the next roll: the validating tags plus every active KSK that is
// not retiring. Trusting only today's signer would break again at the roll.
func (r rootKeys) neededTags() []uint16 {
	tags := slices.Clone(r.validatingTags())
	for _, tag := range r.tags() {
		if !retiringRootKSKs[tag] && !slices.Contains(tags, tag) {
			tags = append(tags, tag)
		}
	}
	slices.Sort(tags)
	return tags
}

func (r rootKeys) describe() string {
	signed := "no RRSIG by an active KSK over the DNSKEY RRset verifies"
	if len(r.signers) > 0 {
		signed = "DNSKEY RRset signed by " + joinTags(r.signers) + ", signature verified"
	}
	return "active root KSKs " + joinTags(r.tags()) + " (" + signed + ")"
}

// sentinelNames returns the is-ta then not-ta name for each tag. RFC 8509
// §2.1 requires five zero-padded decimal digits.
func sentinelNames(tags []uint16) []string {
	names := make([]string, 0, 2*len(tags))
	for _, tag := range tags {
		names = append(names,
			fmt.Sprintf("root-key-sentinel-is-ta-%05d.arpa.", tag),
			fmt.Sprintf("root-key-sentinel-not-ta-%05d.arpa.", tag))
	}
	return names
}

// sentinelRound sends every sentinel name, and the root DNSKEY query with
// checking disabled, to every upstream at once; resps[i] holds the
// per-upstream replies to names[i]. Each fan-out caps only itself at 16
// concurrent queries, so for K KSKs and N upstreams up to (2K+1)·min(N,16)
// queries are in flight, 10 with two KSKs and two upstreams, and each upstream
// receives 2K+1 at once. Every query is bounded by the DNS client's
// per-operation timeout, so the round costs about one timeout.
func sentinelRound(ctx context.Context, env *probe.Env, names []string) (
	resps [][]probe.MultiResp, rootResps []probe.MultiResp,
) {
	resps = make([][]probe.MultiResp, len(names))
	var wg sync.WaitGroup
	wg.Go(func() { rootResps = env.DNS.ExchangeAllCheckingDisabled(ctx, ".", mdns.TypeDNSKEY) })
	for i, name := range names {
		wg.Go(func() { resps[i] = env.DNS.ExchangeAllWithDO(ctx, name, mdns.TypeA) })
	}
	wg.Wait()
	return resps, rootResps
}

// rootErrors says, per upstream, why its root DNSKEY answer was unusable.
func rootErrors(resps []probe.MultiResp, now time.Time) []error {
	errs := make([]error, len(resps))
	for u, r := range resps {
		_, errs[u] = rootKeysFrom(r.Msg, r.Err, now)
	}
	return errs
}

// groupByResolver regroups per-name replies by upstream: resps[2i] and
// resps[2i+1] answer names[2i] and names[2i+1], the is-ta and not-ta names for
// tags[i]. Every fan-out lists the same upstreams in the same order, so
// rootErrs[u] and resps[i][u] belong to one upstream. With several upstreams
// the primary is marked, because bedrock's other checks query it alone.
func groupByResolver(tags []uint16, names []string, resps [][]probe.MultiResp,
	rootErrs []error,
) []resolverProbe {
	probes := make([]resolverProbe, len(resps[0]))
	for u := range probes {
		label := resps[0][u].Upstream
		if u == 0 && len(probes) > 1 {
			label += " (primary)"
		}
		probes[u] = resolverProbe{label: label, tags: tags, rootErr: rootErrs[u]}
		for i := range tags {
			pair := [2]sentinelReply{
				replyAt(resps[2*i], u, names[2*i]), replyAt(resps[2*i+1], u, names[2*i+1]),
			}
			probes[u].replies = append(probes[u].replies, pair)
		}
	}
	return probes
}

// replyAt returns upstream u's reply to the A query for name. A reply that
// does not echo the query, or that comes from something other than a
// resolver answering from the DNS, carries no sentinel signal and counts as
// an error. A missing slot, which the fan-out's single-error shape can
// produce, counts as one too.
func replyAt(rs []probe.MultiResp, u int, name string) sentinelReply {
	if u >= len(rs) {
		return sentinelReply{err: errNoReply}
	}
	m, err := checkReply(rs[u].Msg, rs[u].Err, name, mdns.TypeA)
	switch {
	case err != nil:
		return sentinelReply{err: err}
	case !m.RecursionAvailable:
		return sentinelReply{err: errNotRecursive}
	case m.Authoritative:
		return sentinelReply{err: errLocalZone}
	}
	return sentinelReply{
		rcode:  m.Rcode,
		ad:     m.AuthenticatedData,
		answer: len(m.Answer) > 0,
		ede:    edeCodes(m),
	}
}

// edeCodes renders the extended DNS errors (RFC 8914) in m, which can say why
// a resolver answered as it did: code 29 marks an answer synthesized from
// cached NSEC records (RFC 8198). Their free-form text is left out.
func edeCodes(m *mdns.Msg) string {
	opt := m.IsEdns0()
	if opt == nil {
		return ""
	}
	var b strings.Builder
	for _, o := range opt.Option {
		if e, ok := o.(*mdns.EDNS0_EDE); ok {
			fmt.Fprintf(&b, "+EDE%d", e.InfoCode)
		}
	}
	return b.String()
}

// kindOf maps a reply onto the RFC 8509 §2.2 outcomes. "Return SERVFAIL"
// requires an empty Answer section, and the sentinel names do not exist, so
// a reply carrying answer records was rewritten and shows neither outcome.
func kindOf(r sentinelReply) replyKind {
	switch {
	case r.err != nil, r.answer:
		return replyUnusable
	case r.rcode == mdns.RcodeServerFailure:
		return replyServfail
	case r.rcode == mdns.RcodeSuccess, r.rcode == mdns.RcodeNameError:
		return replyAnswered
	}
	return replyUnusable
}

// classify applies the RFC 8509 §3 table to one tag's is-ta and not-ta
// replies. An original answer without AD still counts toward Vnew and Vold:
// the complementary name must SERVFAIL, which only sentinel processing
// explains, and a forwarder that strips AD (dnsmasq, for one) can sit in front
// of a sentinel-aware validator.
func classify(isTA, notTA sentinelReply) sentinelClass {
	switch [2]replyKind{kindOf(isTA), kindOf(notTA)} {
	case [2]replyKind{replyAnswered, replyServfail}:
		return classVnew
	case [2]replyKind{replyServfail, replyAnswered}:
		return classVold
	case [2]replyKind{replyServfail, replyServfail}:
		return classServfail
	case [2]replyKind{replyAnswered, replyAnswered}:
		return answeredClass(isTA.ad, notTA.ad)
	}
	return classOther
}

// answeredClass separates Vind from nonV when both names resolved: a
// validating resolver marks the signed zone's NXDOMAIN as authentic.
func answeredClass(isAD, notAD bool) sentinelClass {
	switch {
	case isAD && notAD:
		return classVind
	case !isAD && !notAD:
		return classNonV
	}
	return classOther
}

func (p resolverProbe) classes() []sentinelClass {
	out := make([]sentinelClass, len(p.replies))
	for i, pair := range p.replies {
		out[i] = classify(pair[0], pair[1])
	}
	return out
}

func (p resolverProbe) classCounts() map[sentinelClass]int {
	count := map[sentinelClass]int{}
	for _, c := range p.classes() {
		count[c]++
	}
	return count
}

// verdict combines the upstream's per-tag classes. A resolver that SERVFAILs
// every sentinel name yet returns the root DNSKEY RRset with checking
// disabled cannot validate the root; one whose DNSKEY answer failed too may
// just be down, so it stays unknown.
func (p resolverProbe) verdict(root rootKeys) resolverVerdict {
	n := len(p.replies)
	count := p.classCounts()
	switch {
	case n == 0:
		return verdictUnknown
	case count[classServfail] == n && p.rootErr == nil:
		return verdictBroken
	case count[classVind] == n:
		return verdictUnsupported
	case count[classNonV] == n:
		return verdictNotValidating
	case count[classVnew] > 0 && count[classVnew]+count[classVold] == n:
		return p.trustVerdict(root)
	}
	return verdictUnknown
}

// trustVerdict judges an upstream that shows sentinel processing, trusting
// some tags (Vnew) and not the rest (Vold). It can validate the root only
// through a trusted KSK that signs the root DNSKEY RRset, so trusting no
// verified signer contradicts itself. Lacking any other key that is not
// retiring leaves it unable to validate once that key signs.
func (p resolverProbe) trustVerdict(root rootKeys) resolverVerdict {
	signs := func(tag uint16) bool { return slices.Contains(root.signers, tag) }
	switch {
	case len(root.signers) > 0 && !slices.ContainsFunc(p.tagsWith(classVnew), signs):
		return verdictUnknown
	case len(p.lacking()) > 0:
		return verdictMissing
	}
	return verdictReady
}

// sentinelStatus is WARN when any upstream cannot validate or lacks a KSK,
// PASS when every upstream is ready, and INFO otherwise.
func sentinelStatus(verdicts []resolverVerdict) (report.Status, string) {
	notReady := func(v resolverVerdict) bool { return v != verdictReady }
	switch {
	case slices.Contains(verdicts, verdictBroken):
		return report.Warn, titleSentinelBroken
	case slices.Contains(verdicts, verdictMissing):
		return report.Warn, titleSentinelMissing
	case len(verdicts) > 0 && !slices.ContainsFunc(verdicts, notReady):
		return report.Pass, titleSentinelReady
	}
	return report.Info, titleSentinelUnknown
}

func summarizeSentinel(root rootKeys, probes []resolverProbe) report.Result {
	verdicts := make([]resolverVerdict, len(probes))
	parts := []string{root.describe()}
	for i, p := range probes {
		verdicts[i] = p.verdict(root)
		parts = append(parts, p.describe(verdicts[i]))
	}
	status, title := sentinelStatus(verdicts)
	remediation := ""
	if status == report.Warn {
		remediation = sentinelRemediation(root, probes, verdicts)
	}
	return sentinelResult(status, title, strings.Join(parts, "; "), remediation)
}

func (p resolverProbe) describe(v resolverVerdict) string {
	trusted := joinTags(p.tagsWith(classVnew)) + p.retiringNote()
	switch v {
	case verdictReady:
		return p.label + " trusts " + trusted
	case verdictMissing:
		return p.label + " does not yet trust " + joinTags(p.lacking()) +
			" (absent, or still in the RFC 5011 hold-down) and trusts " + trusted
	case verdictBroken:
		return p.label + " cannot validate: it SERVFAILs every sentinel name yet returns " +
			"the root DNSKEY RRset with checking disabled, so it may lack a trust anchor " +
			"for the KSK signing that RRset, have a wrong clock, or forward to a resolver " +
			"with other trust anchors (RFC 8509 §3.1)"
	case verdictUnsupported:
		return p.label + " shows no sentinel processing (not implemented, disabled, masked " +
			"by a forwarder, or skipped for answers synthesized from cached NSEC records, " +
			"RFC 8198), so its trust anchors are unknown" + p.edeNote()
	case verdictNotValidating:
		return p.label + " gives no validation signal (answers lack AD, and the RFC 8509 §3 " +
			"bogus-name test was not run)"
	}
	return p.label + " undetermined (" + p.undetermined() + ")"
}

func (p resolverProbe) tagsWith(c sentinelClass) []uint16 {
	var out []uint16
	for i, got := range p.classes() {
		if got == c {
			out = append(out, p.tags[i])
		}
	}
	return out
}

// lacking returns the untrusted (Vold) tags that are not retiring.
func (p resolverProbe) lacking() []uint16 {
	return slices.DeleteFunc(p.tagsWith(classVold), func(tag uint16) bool {
		return retiringRootKSKs[tag]
	})
}

// retiringNote names the retiring KSKs the upstream does not trust.
func (p resolverProbe) retiringNote() string {
	dropped := slices.DeleteFunc(p.tagsWith(classVold), func(tag uint16) bool {
		return !retiringRootKSKs[tag]
	})
	if len(dropped) == 0 {
		return ""
	}
	return " but not retiring KSK " + joinTags(dropped)
}

// edeNote lists the distinct extended DNS errors among the upstream's
// replies: +EDE29 says the resolver synthesized an answer from cached NSEC
// records, which skips the sentinel.
func (p resolverProbe) edeNote() string {
	var codes []string
	for _, pair := range p.replies {
		for _, r := range pair {
			if r.ede != "" && !slices.Contains(codes, r.ede) {
				codes = append(codes, r.ede)
			}
		}
	}
	if len(codes) == 0 {
		return ""
	}
	return " (answers carried " + strings.Join(codes, ", ") + ")"
}

// undetermined renders what the upstream returned, so it can be diagnosed
// with dig: its root DNSKEY failure, if any, then every sentinel reply. It
// never uses "; ", which separates resolvers in the evidence.
func (p resolverProbe) undetermined() string {
	out := p.rawReplies()
	if p.rootErr != nil {
		out = "root DNSKEY with checking disabled: " + errText(p.rootErr) + ", replies " + out
	}
	if p.carriesEDE(29) {
		out += " (+EDE29: answered from cached NSEC records, RFC 8198, skipping the sentinel)"
	}
	return out
}

// carriesEDE reports whether any reply carried the extended DNS error code.
func (p resolverProbe) carriesEDE(code int) bool {
	mark := "+EDE" + strconv.Itoa(code) + "+"
	for _, pair := range p.replies {
		for _, r := range pair {
			if strings.Contains(r.ede+"+", mark) {
				return true
			}
		}
	}
	return false
}

// rawReplies renders every reply, plus the first transport error.
func (p resolverProbe) rawReplies() string {
	parts := make([]string, len(p.tags))
	var firstErr error
	for i, tag := range p.tags {
		pair := p.replies[i]
		parts[i] = fmt.Sprintf("%d is-ta=%s not-ta=%s", tag, pair[0], pair[1])
		for _, r := range pair {
			if firstErr == nil && r.err != nil {
				firstErr = r.err
			}
		}
	}
	out := strings.Join(parts, ", ")
	if firstErr != nil {
		out += ": " + errText(firstErr)
	}
	return out
}

func (r sentinelReply) String() string {
	if r.err != nil {
		return "error"
	}
	s := rcodeName(r.rcode)
	if r.ad {
		s += "+AD"
	}
	if r.answer {
		s += "+answer"
	}
	return s + r.ede
}

// sentinelRemediation names each upstream that lacks a KSK or cannot validate
// and lists the keys it needs as DS records computed from the fetched root
// DNSKEY RRset. The DS lines stay commented: they come from an
// unauthenticated answer and must be checked against IANA before anyone
// installs them.
func sentinelRemediation(root rootKeys, probes []resolverProbe, verdicts []resolverVerdict) string {
	var b strings.Builder
	b.WriteString(sentinelHeader)
	needed := map[uint16]bool{}
	for i, p := range probes {
		var tags []uint16
		switch verdicts[i] {
		case verdictMissing:
			tags = p.lacking()
			fmt.Fprintf(&b, "# %s lacks %s.\n", p.label, joinTags(tags))
		case verdictBroken:
			tags = root.neededTags()
			fmt.Fprintf(&b, "# %s cannot validate: check its clock, its forwarders, and that "+
				"it trusts %s.\n", p.label, joinTags(tags))
		}
		for _, tag := range tags {
			needed[tag] = true
		}
	}
	b.WriteString(sentinelRefreshSteps)
	for _, k := range root.ksks {
		// activeRootKSKs keeps only keys ToDS can hash, so ds is never nil.
		if ds := k.ToDS(mdns.SHA256); needed[ds.KeyTag] {
			fmt.Fprintf(&b, "\n# . IN DS %d %d %d %s",
				ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
		}
	}
	return b.String()
}

func sentinelResult(status report.Status, title, evidence, remediation string) report.Result {
	return report.Result{
		ID:          sentinelID,
		Category:    category,
		Title:       title,
		Status:      status,
		Evidence:    evidence,
		Remediation: remediation,
		RFCRefs:     append([]string(nil), sentinelRefs...),
	}
}

// labelled prefixes err with the upstream's label, which the fan-out leaves
// empty when no upstream could be configured.
func labelled(label string, err error) string {
	if label == "" {
		return errText(err)
	}
	return label + ": " + errText(err)
}

// errText renders err without the request URL that a failed DoH exchange
// carries, because the URL's path can hold an account identifier.
func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Sprint(ue.Err)
	}
	return err.Error()
}

func joinTags(tags []uint16) string {
	parts := make([]string, len(tags))
	for i, tag := range tags {
		parts[i] = strconv.Itoa(int(tag))
	}
	return strings.Join(parts, ",")
}

func rcodeName(rcode int) string {
	if s, ok := mdns.RcodeToString[rcode]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(rcode)
}
