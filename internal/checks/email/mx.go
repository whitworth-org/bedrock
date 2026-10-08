package email

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// maxMXHosts caps the MX hosts the STARTTLS and DANE checks probe. The
// domain owner picks every MX host and can publish thousands.
const maxMXHosts = 10

// mxConcurrency caps the MX hosts a check probes at once.
const mxConcurrency = 4

// isNullMX reports whether the slice is the RFC 7505 single-record null MX.
func isNullMX(mxs []probe.MX) bool {
	return len(mxs) == 1 && mxs[0].Preference == 0 && (mxs[0].Host == "" || mxs[0].Host == ".")
}

// mxLookup is the outcome of the target's MX lookup.
type mxLookup struct {
	mxs []probe.MX
	err error
}

// targetMX returns the target's MX RRset, empty when the name does not
// exist, or the error of its lookup. The lookup runs once per Env, under its
// own per-operation timeout, however many checks ask concurrently, so every
// check that reads the MX RRset sees the same answer.
func targetMX(ctx context.Context, env *probe.Env) ([]probe.MX, error) {
	l := probe.Shared(env, probe.CacheKeyMX, func() *mxLookup {
		c, cancel := env.WithTimeout(ctx)
		defer cancel()
		mxs, err := env.DNS.LookupMX(c, env.Target)
		if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
			return &mxLookup{err: fmt.Errorf("MX lookup for %s: %w", env.Target, err)}
		}
		return &mxLookup{mxs: mxs}
	})
	if l == nil {
		return nil, fmt.Errorf("MX lookup for %s: no result, because the check that ran it "+
			"panicked; see its registry.panic result", env.Target)
	}
	return l.mxs, l.err
}

// publishesNullMX reports whether the target publishes null MX. A failed MX
// lookup shows none, so the checks that ask still grade their own records;
// email.nullmx reports the failure.
func publishesNullMX(ctx context.Context, env *probe.Env) bool {
	mxs, _ := targetMX(ctx, env)
	return isNullMX(mxs)
}

// mxHosts returns the distinct exchange hosts in mxs, as mxHostName spells
// them, most preferred first and then by name, split into the first
// maxMXHosts and the rest. An empty host, such as a null MX ("0 .")
// published beside real ones, names no server and is left out.
func mxHosts(mxs []probe.MX) (probed, skipped []string) {
	sorted := make([]probe.MX, 0, len(mxs))
	for _, mx := range mxs {
		if host := mxHostName(mx.Host); host != "" {
			sorted = append(sorted, probe.MX{Preference: mx.Preference, Host: host})
		}
	}
	slices.SortFunc(sorted, func(a, b probe.MX) int {
		return cmp.Or(cmp.Compare(a.Preference, b.Preference), strings.Compare(a.Host, b.Host))
	})
	var hosts []string
	seen := make(map[string]bool, len(sorted))
	for _, mx := range sorted {
		if !seen[mx.Host] {
			seen[mx.Host] = true
			hosts = append(hosts, mx.Host)
		}
	}
	if len(hosts) <= maxMXHosts {
		return hosts, nil
	}
	return hosts[:maxMXHosts:maxMXHosts], hosts[maxMXHosts:]
}

// mxHostName returns an exchange host lowercase and without the trailing
// dot. An IP literal, which RFC 5321 §5 does not allow as an exchange but a
// domain can still publish, comes back in its canonical form, so the many
// spellings of one address are one host, probed once.
func mxHostName(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}

// probeMXHosts runs probeHost for each host, at most mxConcurrency at a
// time, and returns the results in host order.
func probeMXHosts(
	ctx context.Context, hosts []string, probeHost func(context.Context, string) report.Result,
) []report.Result {
	out := make([]report.Result, len(hosts))
	checkutil.ForEach(len(hosts), mxConcurrency, func(i int) {
		out[i] = probeHost(ctx, hosts[i])
	})
	return out
}

// skippedMXResult names the MX hosts beyond maxMXHosts that the check id
// did not probe.
func skippedMXResult(id, title string, skipped, refs []string) report.Result {
	return report.Result{
		ID: id, Category: category, Title: title,
		Status: report.Info,
		Evidence: fmt.Sprintf("probed the %d most preferred MX hosts; not probed: %s",
			maxMXHosts, checkutil.ListBounded(skipped, ", ")),
		RFCRefs: refs,
	}
}
