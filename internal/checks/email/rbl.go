package email

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

// rblZones is the fixed set of public DNS-based blocklists we query when
// the operator opts in via --enable-rbl. Listings here are reported as
// WARN (not FAIL): false positives and stale entries are common across
// these zones, and operator-curated allowlists belong upstream of this
// tool. Implements the protocol described in RFC 5782.
var rblZones = []string{
	"zen.spamhaus.org",
	"b.barracudacentral.org",
	"bl.spamcop.net",
	"dnsbl.sorbs.net",
	"psbl.surriel.com",
}

// rblWorkers bounds the concurrent DNS lookups issued against blocklist
// zones. 8 keeps load on shared resolvers reasonable while still finishing
// a typical (apex + a few MX A records) × len(rblZones) matrix quickly.
const rblWorkers = 8

type rblCheck struct{}

func (rblCheck) ID() string       { return "email.rbl" }
func (rblCheck) Category() string { return category }

// Run resolves the apex's A records and each MX host's A records, then
// queries every IPv4 against every entry in rblZones. Listings yield one
// WARN per (ip, zone) pair; a clean run yields a single PASS. IPv6 is
// reported once as INFO and skipped — most public DNSBLs do not index
// AAAA addresses reliably.
func (rblCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	refs := []string{"RFC 5782"}
	const id = "email.rbl"
	const title = "DNS blocklist (DNSBL) listings"

	if !env.EnableRBL {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "disabled (pass --enable-rbl to query third-party blocklists)",
			RFCRefs:  refs,
		}}
	}

	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	v4s, v6Count, gatherEvidence := gatherRBLTargets(ctx, env)
	var results []report.Result
	if v6Count > 0 {
		results = append(results, report.Result{
			ID: id + ".ipv6_skipped", Category: category,
			Title:    "DNSBL: IPv6 addresses skipped",
			Status:   report.Info,
			Evidence: fmt.Sprintf("%d IPv6 address(es) skipped: most public DNSBLs do not index AAAA records", v6Count),
			RFCRefs:  refs,
		})
	}
	if len(v4s) == 0 {
		results = append(results, report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "no IPv4 addresses to check (" + gatherEvidence + ")",
			RFCRefs:  refs,
		})
		return results
	}

	listings := queryRBLs(ctx, env, v4s, rblZones)
	if len(listings) == 0 {
		results = append(results, report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Pass,
			Evidence: fmt.Sprintf("checked %d IP(s) against %d DNSBL(s); no listings", len(v4s), len(rblZones)),
			RFCRefs:  refs,
		})
		return results
	}
	for _, l := range listings {
		evidence := l.IP + " listed on " + l.Zone
		if l.Reason != "" {
			evidence += ": " + l.Reason
		}
		results = append(results, report.Result{
			ID:          id + "." + sanitizeZoneID(l.Zone),
			Category:    category,
			Title:       "DNSBL listing on " + l.Zone,
			Status:      report.Warn,
			Evidence:    evidence,
			Remediation: "contact the listing service to request delisting and address the underlying reputation cause",
			RFCRefs:     refs,
		})
	}
	return results
}

// gatherRBLTargets resolves the apex A/AAAA records and each MX host's
// A/AAAA records, then returns deduped IPv4 strings, the count of IPv6
// addresses encountered (for the INFO note), and a short human-readable
// description of what was queried (used in the N/A path when we found
// nothing). Errors are tolerated: each lookup that fails just contributes
// no IPs.
func gatherRBLTargets(ctx context.Context, env *probe.Env) (ipv4s []string, ipv6Count int, evidence string) {
	seen := map[string]bool{}
	var v4 []string
	var v6 int

	addIP := func(ip net.IP) {
		if ip == nil {
			return
		}
		if v4Only := ip.To4(); v4Only != nil {
			s := v4Only.String()
			if !seen[s] {
				seen[s] = true
				v4 = append(v4, s)
			}
			return
		}
		v6++
	}

	// Apex A/AAAA.
	if as, err := env.DNS.LookupA(ctx, env.Target); err == nil {
		for _, ip := range as {
			addIP(ip)
		}
	}
	if as, err := env.DNS.LookupAAAA(ctx, env.Target); err == nil {
		for _, ip := range as {
			addIP(ip)
		}
	}

	// MX hosts: prefer the cached MX list to avoid duplicate work.
	mxs := mxFromCacheOrLookup(ctx, env)
	for _, mx := range mxs {
		if mx.Host == "" || mx.Host == "." { // null MX or empty
			continue
		}
		if as, err := env.DNS.LookupA(ctx, mx.Host); err == nil {
			for _, ip := range as {
				addIP(ip)
			}
		}
		if as, err := env.DNS.LookupAAAA(ctx, mx.Host); err == nil {
			for _, ip := range as {
				addIP(ip)
			}
		}
	}

	sort.Strings(v4)
	desc := fmt.Sprintf("apex %s + %d MX host(s)", env.Target, len(mxs))
	return v4, v6, desc
}

// mxFromCacheOrLookup reads probe.CacheKeyMX (populated by the null-MX
// check) and falls back to a fresh MX lookup if the cache is empty or the
// stored type does not match. Errors yield an empty slice so callers can
// proceed with the apex-only IP list.
func mxFromCacheOrLookup(ctx context.Context, env *probe.Env) []probe.MX {
	if v, ok := env.CacheGet(probe.CacheKeyMX); ok {
		if mxs, ok := v.([]probe.MX); ok {
			return mxs
		}
	}
	mxs, err := env.DNS.LookupMX(ctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return nil
	}
	return mxs
}

// rblListing captures one (IP, zone) hit and the optional reason TXT.
type rblListing struct {
	IP     string
	Zone   string
	Reason string
}

// queryRBLs runs the full IP × zone matrix in parallel through a worker
// pool and returns the listings sorted for stable output.
func queryRBLs(ctx context.Context, env *probe.Env, ips []string, zones []string) []rblListing {
	type job struct {
		ip, zone string
	}
	jobs := make(chan job)
	results := make(chan rblListing)

	var wg sync.WaitGroup
	workers := rblWorkers
	if workers > len(ips)*len(zones) && len(ips)*len(zones) > 0 {
		workers = len(ips) * len(zones)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Recover from any panic inside queryOneRBL (e.g. a surprise
			// from the DNS library on a malformed answer). The panicking
			// job is dropped; other workers continue. We don't surface a
			// dedicated Fail here because the per-worker channel is for
			// listings only — the registry catches unrecovered panics.
			defer func() {
				if r := recover(); r != nil {
					_ = r // silently drop: a single panicking lookup should
					// not crash the scan. The registry-level recover would
					// catch it anyway but at the cost of the whole email
					// category.
				}
			}()
			for j := range jobs {
				if hit, ok := queryOneRBL(ctx, env, j.ip, j.zone); ok {
					select {
					case results <- hit:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer func() { _ = recover() }()
		defer close(jobs)
		for _, ip := range ips {
			for _, z := range zones {
				select {
				case jobs <- job{ip: ip, zone: z}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		defer func() { _ = recover() }()
		wg.Wait()
		close(results)
	}()

	var listings []rblListing
	for r := range results {
		listings = append(listings, r)
	}
	sort.Slice(listings, func(i, j int) bool {
		if listings[i].Zone != listings[j].Zone {
			return listings[i].Zone < listings[j].Zone
		}
		return listings[i].IP < listings[j].IP
	})
	return listings
}

// queryOneRBL performs the standard RFC 5782 §2 lookup: reverse the
// IPv4 octets, append the zone, and ask for an A record. A non-empty
// answer (typically 127.0.0.x) means the IP is listed. The companion
// TXT lookup surfaces a human-readable reason when the zone supports it.
func queryOneRBL(ctx context.Context, env *probe.Env, ip, zone string) (rblListing, bool) {
	rev := reverseIPv4(ip)
	if rev == "" {
		return rblListing{}, false
	}
	name := rev + "." + zone

	addrs, err := env.DNS.LookupA(ctx, name)
	if err != nil || len(addrs) == 0 {
		return rblListing{}, false
	}
	// Optional reason — best-effort; ignore errors.
	reason := ""
	if txts, err := env.DNS.LookupTXT(ctx, name); err == nil && len(txts) > 0 {
		// One TXT line is plenty; collapse whitespace.
		reason = strings.Join(strings.Fields(strings.Join(txts, " ")), " ")
	}
	return rblListing{IP: ip, Zone: zone, Reason: reason}, true
}

// reverseIPv4 turns "1.2.3.4" into "4.3.2.1". Returns "" for inputs that
// are not valid IPv4 dotted-quads (per RFC 5782 §2.1, only IPv4 uses the
// reverse-octet form; IPv6 has its own nibble-reversed scheme that this
// tool does not currently implement).
func reverseIPv4(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

// sanitizeZoneID makes a DNSBL zone safe for use as a Result ID suffix.
// Result IDs are dot-delimited; replacing dots with underscores keeps the
// hierarchy readable in JSON/Markdown output.
func sanitizeZoneID(zone string) string {
	return strings.ReplaceAll(zone, ".", "_")
}

func init() { registry.Register(rblCheck{}) }
