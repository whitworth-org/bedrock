package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go/http3"

	"bedrock/internal/probe"
	"bedrock/internal/registry"
	"bedrock/internal/report"
)

// http3Check probes for HTTP/3 (QUIC) support via two independent signals:
//  1. The Alt-Svc response header on the served HTTPS root advertising "h3"
//     (per RFC 7838 / RFC 9114 §3.1.1).
//  2. An actual HTTP/3 GET against the apex over QUIC (RFC 9000 transport,
//     RFC 9114 application mapping).
//
// HTTP/3 is treated as an enhancement: not running it is INFO, not FAIL.
type http3Check struct{}

func (http3Check) ID() string       { return "web.http3" }
func (http3Check) Category() string { return category }

// http3RFCs are the specs cited by every result this check emits, kept in one
// place so renderers consistently surface the same provenance.
var http3RFCs = []string{"RFC 9114", "RFC 9000", "RFC 7838", "RFC 9110"}

func (http3Check) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.http3", Category: category,
			Title:    "HTTP/3 (QUIC) supported",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  http3RFCs,
		}}
	}

	// Signal 1: Alt-Svc on the cached HTTPS root response.
	altSvc := false
	var altSvcHeader string
	if resp := getHTTPSRoot(ctx, env); resp != nil {
		altSvcHeader = resp.Headers.Get("Alt-Svc")
		altSvc = altSvcAdvertisesH3(altSvcHeader)
	}

	// Signal 2: Best-effort QUIC dial. Errors here are common (UDP/443 blocked,
	// no h3 listener, firewall) and intentionally non-fatal — we only care if
	// the dial actually succeeded.
	quic, quicErr := dialHTTP3(ctx, env)

	r := report.Result{
		ID: "web.http3", Category: category,
		Title:   "HTTP/3 (QUIC) supported",
		RFCRefs: http3RFCs,
	}

	switch {
	case quic:
		r.Status = report.Pass
		r.Evidence = "HTTP/3 GET succeeded over QUIC against https://" + env.Target + "/"
		if altSvc {
			r.Evidence += "; Alt-Svc: " + altSvcHeader
		}
	case altSvc:
		r.Status = report.Pass
		r.Evidence = "Alt-Svc advertises h3 (" + altSvcHeader + "); QUIC dial did not succeed"
		if quicErr != nil {
			r.Evidence += " (" + quicErr.Error() + ")"
		}
	default:
		r.Status = report.Info
		r.Evidence = "no Alt-Svc h3 advertisement and QUIC dial did not succeed"
		if quicErr != nil {
			r.Evidence += " (" + quicErr.Error() + ")"
		}
		r.Remediation = http3Remediation()
	}
	return []report.Result{r}
}

// altSvcAdvertisesH3 reports whether an Alt-Svc header value advertises an
// HTTP/3 ("h3" or draft "h3-NN") alternative service per RFC 7838 §3 / RFC
// 9114 §3.1.1. Tokens look like `h3=":443"; ma=86400` and are comma-separated.
// Matching is intentionally tolerant: case-insensitive token name, ignores
// parameters, and accepts both final ("h3") and draft ("h3-29") protocol IDs.
func altSvcAdvertisesH3(header string) bool {
	if header == "" {
		return false
	}
	for _, raw := range strings.Split(header, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		// "clear" means the server is withdrawing all alternatives.
		if strings.EqualFold(entry, "clear") {
			return false
		}
		// Take the first ";"-delimited token (the protocol-id="authority" pair).
		head := entry
		if i := strings.IndexByte(head, ';'); i >= 0 {
			head = strings.TrimSpace(head[:i])
		}
		// Split protocol-id from its quoted authority on the first "=".
		name := head
		if i := strings.IndexByte(head, '='); i >= 0 {
			name = strings.TrimSpace(head[:i])
		}
		name = strings.ToLower(name)
		if name == "h3" || strings.HasPrefix(name, "h3-") {
			return true
		}
	}
	return false
}

// dialHTTP3 attempts a single HTTP/3 GET against https://<target>/ using the
// quic-go http3 transport. Returns (true, nil) on a successful response. Any
// dial/handshake/transport failure returns (false, err) — callers treat err as
// diagnostic, not fatal, since blocked UDP is a normal failure mode.
func dialHTTP3(ctx context.Context, env *probe.Env) (bool, error) {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	// Always release the underlying UDP socket so we don't leak sockets across
	// multi-host runs.
	defer tr.Close()

	gctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	client := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(gctx, http.MethodGet, "https://"+env.Target+"/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "bedrock/0.1 (+https://example.invalid/)")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be cleanly closed; cap to avoid
	// pulling a large page when we only need to confirm the round-trip worked.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return true, nil
}

func http3Remediation() string {
	return fmt.Sprintf(
		"enable HTTP/3 on your TLS server (e.g. nginx 1.25+: %s; %s)",
		`listen 443 quic`,
		`add_header Alt-Svc 'h3=":443"; ma=86400';`,
	)
}

func init() { registry.Register(http3Check{}) }
