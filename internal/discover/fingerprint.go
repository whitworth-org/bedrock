package discover

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/probe/tlsfp"
	"github.com/whitworth-org/bedrock/internal/report"
)

// fingerprintHosts emits per-host JA3S and JA4S TLS server fingerprints for
// every discovered subdomain. Concurrency is bounded by maxConcurrentDials
// — same cap probeHosts uses, applied independently. One handshake per host.
//
// Hosts whose handshake fails produce no result here; probeHosts already
// surfaces the failure as subdomain.tls.<host>. Emitting an additional
// fingerprint failure for the same root cause would just stutter the noise.
//
// Output IDs follow the apex check shape so an operator can baseline both
// tiers with a single grep:
//
//	web.tls.fingerprint.ja3s.<apex|www>
//	subdomain.tls.fingerprint.ja3s.<host>
//
// All dials route through probe.SafeDialContext to keep the SSRF posture
// consistent with the rest of bedrock's HTTP client.
func fingerprintHosts(ctx context.Context, env *probe.Env, hosts []string) []report.Result {
	return fingerprintHostsAt(ctx, env, hosts, "443")
}

// fingerprintHostsAt is the port-parameterised inner loop. Production always
// targets :443; the test path injects an httptest port so we can exercise
// the orchestration end-to-end without binding privileged ports or relying
// on outbound network.
func fingerprintHostsAt(ctx context.Context, env *probe.Env, hosts []string, port string) []report.Result {
	if len(hosts) == 0 {
		return nil
	}
	timeout := env.Timeout
	dial := probe.SafeDialContext(timeout, false)

	sem := make(chan struct{}, maxConcurrentDials)
	var (
		mu  sync.Mutex
		out []report.Result
		wg  sync.WaitGroup
	)

	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			// Recover from panics so one bad host cannot abort the
			// fingerprint sweep, mirroring probeHosts' contract.
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					out = append(out, report.Result{
						ID:       "subdomain.tls.fingerprint." + host,
						Category: category,
						Title:    "TLS fingerprint panic (" + host + ")",
						Status:   report.Fail,
						Evidence: fmt.Sprintf("panic during fingerprint: %v", r),
					})
					mu.Unlock()
				}
			}()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			res, err := tlsfp.Capture(ctx, host, port, dial, timeout)
			if err != nil {
				return
			}
			alpn := res.ALPN
			if alpn == "" {
				alpn = "(none)"
			}
			mu.Lock()
			out = append(out,
				report.Result{
					ID:       "subdomain.tls.fingerprint.ja3s." + host,
					Category: category,
					Title:    "JA3S fingerprint — " + host,
					Status:   report.Info,
					Evidence: fmt.Sprintf(
						"JA3S=%s raw=%s tls=0x%04x cipher=0x%04x ext_count=%d",
						res.JA3S, res.JA3SString, res.WireVersion, res.Cipher, len(res.Extensions),
					),
				},
				report.Result{
					ID:       "subdomain.tls.fingerprint.ja4s." + host,
					Category: category,
					Title:    "JA4S fingerprint — " + host,
					Status:   report.Info,
					Evidence: fmt.Sprintf(
						"JA4S=%s tls=0x%04x cipher=0x%04x alpn=%s ext_count=%d",
						res.JA4S, res.NegotiatedTLS, res.Cipher, alpn, len(res.Extensions),
					),
				},
			)
			mu.Unlock()
		}(h)
	}
	wg.Wait()

	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
