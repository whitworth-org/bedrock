package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/whitworth-org/bedrock/internal/probe"
)

// startHTTP3Server serves h over HTTP/3 on 127.0.0.1 until the test ends.
// It returns the server's https:// origin and a pool that trusts its
// certificate.
func startHTTP3Server(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	t.Helper()
	// Borrow httptest's loopback certificate, which covers 127.0.0.1.
	certSrc := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certSrc.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certSrc.Certificate())
	certSrc.Close()

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	srv := &http3.Server{
		Handler:   h,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	}
	go func() { _ = srv.Serve(udp) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = udp.Close()
	})
	return "https://" + udp.LocalAddr().String(), roots
}

// getHTTP3Trusting runs getHTTP3 for target through the probe's transport,
// trusting roots.
func getHTTP3Trusting(t *testing.T, roots *x509.CertPool, target string) (bool, error) {
	t.Helper()
	tr := newHTTP3Transport()
	tr.TLSClientConfig.RootCAs = roots
	defer func() { _ = tr.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return getHTTP3(ctx, tr, target)
}

// TestHTTP3DoesNotFollowRedirects: a redirect is an HTTP/3 response like any
// other, and following it would dial a host the operator never targeted.
func TestHTTP3DoesNotFollowRedirects(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	var followed atomic.Int32
	redirect := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			followed.Add(1)
		}
		http.Redirect(w, r, "/moved", http.StatusMovedPermanently)
	}
	origin, roots := startHTTP3Server(t, http.HandlerFunc(redirect))

	ok, err := getHTTP3Trusting(t, roots, origin+"/")
	if !ok || err != nil {
		t.Fatalf("getHTTP3(%s) = %v, %v; want the 301 to count as an HTTP/3 response",
			origin, ok, err)
	}
	if n := followed.Load(); n != 0 {
		t.Errorf("getHTTP3 followed the redirect: %d requests reached its target", n)
	}
}

// TestHTTP3BoundsResponseHeaders: like the TCP transports, the HTTP/3
// transport refuses megabytes of response headers.
func TestHTTP3BoundsResponseHeaders(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "1")
	bloated := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Filler", strings.Repeat("a", 300<<10))
	}
	origin, roots := startHTTP3Server(t, http.HandlerFunc(bloated))

	if ok, err := getHTTP3Trusting(t, roots, origin+"/"); ok || err == nil {
		t.Errorf("getHTTP3(%s) = %v, %v; want a 300 KiB response header refused", origin, ok, err)
	}
}

// TestHTTP3DialsThroughDenylist: the QUIC dial goes through the SSRF
// denylist, so a loopback target is refused before any packet is sent.
func TestHTTP3DialsThroughDenylist(t *testing.T) {
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
	env := probe.NewEnv("127.0.0.1", time.Second, true, "127.0.0.1:1")

	ok, err := dialHTTP3(context.Background(), env)
	var blocked *probe.BlockedAddrError
	if ok || !errors.As(err, &blocked) {
		t.Errorf("dialHTTP3(127.0.0.1) = %v, %v; want the dial refused", ok, err)
	}
}

func TestAltSvcAdvertisesH3(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{
			name:   "empty header",
			header: "",
			want:   false,
		},
		{
			name:   "h3 only",
			header: `h3=":443"`,
			want:   true,
		},
		{
			name:   "h3 with ma parameter",
			header: `h3=":443"; ma=86400`,
			want:   true,
		},
		{
			name:   "draft h3-29",
			header: `h3-29=":443"; ma=86400`,
			want:   true,
		},
		{
			name:   "h3 alongside h2 (multi-value)",
			header: `h2=":443"; ma=86400, h3=":443"; ma=86400`,
			want:   true,
		},
		{
			name:   "case-insensitive protocol id",
			header: `H3=":443"`,
			want:   true,
		},
		{
			name:   "only h2 (HTTP/2 alt-svc, no HTTP/3)",
			header: `h2=":443"; ma=86400`,
			want:   false,
		},
		{
			name:   "clear withdraws all alternatives",
			header: "clear",
			want:   false,
		},
		{
			name:   "h3 with port-only authority (no host)",
			header: `h3=":8443"; ma=3600; persist=1`,
			want:   true,
		},
		{
			name: "h3 with cross-host alternative",
			// RFC 7838 §3 permits alt-authority to include a host.
			header: `h3="alt.example.com:443"; ma=600`,
			want:   true,
		},
		{
			name:   "lookalike protocol id",
			header: `h3x=":443"`,
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := altSvcAdvertisesH3(tc.header); got != tc.want {
				t.Errorf("altSvcAdvertisesH3(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
