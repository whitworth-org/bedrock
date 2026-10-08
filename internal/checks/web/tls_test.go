package web

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLSv1",
		tls.VersionTLS11: "TLSv1.1",
		tls.VersionTLS12: "TLSv1.2",
		tls.VersionTLS13: "TLSv1.3",
	}
	for v, want := range cases {
		if got := tlsVersionName(v); got != want {
			t.Errorf("tlsVersionName(%v) = %q, want %q", v, got, want)
		}
	}
}

func TestOpenSSLCipherName(t *testing.T) {
	cases := map[string]string{
		// Mapped suites
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":       "ECDHE-RSA-AES128-GCM-SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":     "ECDHE-ECDSA-AES256-GCM-SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-RSA-CHACHA20-POLY1305",
		// TLS 1.3 — pass through unchanged
		"TLS_AES_128_GCM_SHA256":       "TLS_AES_128_GCM_SHA256",
		"TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
		// Unknown — pass through
		"TLS_FOO_BAR_BAZ": "TLS_FOO_BAR_BAZ",
	}
	for in, want := range cases {
		if got := opensslCipherName(in); got != want {
			t.Errorf("opensslCipherName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProfileAccepts_Modern(t *testing.T) {
	cfg, err := loadTLSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	modern := cfg.Configurations["modern"]
	// TLS 1.3 + TLS_AES_128_GCM_SHA256 + ECDSA P-256 → matches modern.
	if !profileAccepts(modern, tls.VersionTLS13, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "ecdsa", 256) {
		t.Errorf("modern profile rejected TLS1.3 / AES128-GCM / EC256")
	}
	// TLS 1.2 must NOT match modern.
	if profileAccepts(modern, tls.VersionTLS12, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "rsa", 2048) {
		t.Errorf("modern profile accepted TLS 1.2 (should be 1.3 only)")
	}
	// RSA key < 2048 must fail.
	if profileAccepts(modern, tls.VersionTLS13, "TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "rsa", 1024) {
		t.Errorf("modern profile accepted RSA 1024")
	}
}

func TestProfileAccepts_Intermediate(t *testing.T) {
	cfg, err := loadTLSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	inter := cfg.Configurations["intermediate"]
	// TLS 1.2 + ECDHE-RSA-AES128-GCM-SHA256 + RSA 2048 → matches.
	if !profileAccepts(inter, tls.VersionTLS12, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "rsa", 2048) {
		t.Errorf("intermediate rejected TLS1.2/ECDHE-RSA-AES128-GCM/RSA2048")
	}
	// TLS 1.0 must not match.
	if profileAccepts(inter, tls.VersionTLS10, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "rsa", 2048) {
		t.Errorf("intermediate accepted TLS 1.0")
	}
}

func TestProfileAccepts_OldAcceptsLegacy(t *testing.T) {
	cfg, err := loadTLSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	old := cfg.Configurations["old"]
	// TLS 1.0 + AES128-SHA + RSA 2048 → matches old.
	if !profileAccepts(old, tls.VersionTLS10, "TLS_RSA_WITH_AES_128_CBC_SHA", "AES128-SHA", "rsa", 2048) {
		t.Errorf("old rejected TLS1.0/AES128-SHA/RSA2048 — should accept")
	}
}

// TestRunTLS_ProfilesAnUntrustedChain: the profile check grades what the
// server negotiates whatever its certificate, so a self-signed TLS 1.3
// server is profiled instead of failing the handshake; web.cert.* grades
// the chain.
func TestRunTLS_ProfilesAnUntrustedChain(t *testing.T) {
	env := tlsTestEnv(t)
	srv := startTLSServer(t, http.NotFoundHandler(), nil, false)
	setPort(t, &tlsStatePort, portOf(srv.Listener.Addr()))

	out := runTLS(context.Background(), env)
	version := findResult(t, out, "web.tls.version.127.0.0.1")
	if version.Status != report.Pass ||
		!strings.HasPrefix(version.Evidence, "negotiated TLSv1.3, cipher ") {
		t.Errorf("version = %s %q, want PASS for TLS 1.3", version.Status, version.Evidence)
	}
	profile := findResult(t, out, "web.tls.profile.127.0.0.1")
	if profile.Status != report.Pass ||
		!strings.HasPrefix(profile.Evidence, `matched "modern" profile`) {
		t.Errorf("profile = %s %q, want the modern profile", profile.Status, profile.Evidence)
	}
}

// TestRunTLS_LegacyServerProfiledWithOneDial: one handshake with a TLS 1.0
// floor profiles a server that speaks only TLS 1.0; nothing is retried.
func TestRunTLS_LegacyServerProfiledWithOneDial(t *testing.T) {
	env := tlsTestEnv(t)
	port, accepts := serveTLS(t, &tls.Config{
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		Certificates: []tls.Certificate{serverCert(t, newTestPKI(t), loopbackLeaf())},
	})
	setPort(t, &tlsStatePort, port)

	out := runTLS(context.Background(), env)
	version := findResult(t, out, "web.tls.version.127.0.0.1")
	if version.Status != report.Fail || !strings.HasPrefix(version.Evidence, "negotiated TLSv1, ") {
		t.Errorf("version = %s %q, want FAIL for TLS 1.0", version.Status, version.Evidence)
	}
	profile := findResult(t, out, "web.tls.profile.127.0.0.1")
	if profile.Status != report.Warn ||
		!strings.HasPrefix(profile.Evidence, `matched "old" profile`) {
		t.Errorf("profile = %s %q, want WARN for the old profile", profile.Status, profile.Evidence)
	}
	if n := accepts.Load(); n != 1 {
		t.Errorf("profiling made %d connections, want 1", n)
	}
}

// TestRunTLS_ResultsPerHost: the apex and www each get their own handshake
// and their own result IDs, whether a handshake succeeds or fails.
func TestRunTLS_ResultsPerHost(t *testing.T) {
	refused := &tlsHandshake{err: errors.New("TLS handshake with www.127.0.0.1:443 failed: " +
		"connection refused")}
	cases := []struct {
		name string
		port func(t *testing.T) string
		want map[string]report.Status
	}{
		{"apex succeeds", func(t *testing.T) string {
			return portOf(startTLSServer(t, http.NotFoundHandler(), nil, false).Listener.Addr())
		}, map[string]report.Status{
			"web.tls.version.127.0.0.1": report.Pass, "web.tls.profile.127.0.0.1": report.Pass,
			"web.tls.profile.www.127.0.0.1": report.Fail,
		}},
		{"both fail", closedPort, map[string]report.Status{
			"web.tls.profile.127.0.0.1": report.Fail, "web.tls.profile.www.127.0.0.1": report.Fail,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := activeLoopbackEnv(t)
			env.DNS = probe.NewDNS(wwwResolver(t, "127.0.0.1"), time.Second)
			setPort(t, &tlsStatePort, tc.port(t))
			// www.127.0.0.1 exists only in the fake zone, so its handshake is
			// seeded rather than dialed.
			env.CachePut(tlsStateKey("www.127.0.0.1"), refused)

			out := runTLS(context.Background(), env)
			if err := report.CheckUniqueIDs(out); err != nil {
				t.Error(err)
			}
			if len(out) != len(tc.want) {
				t.Errorf("got %d results, want %d: %+v", len(out), len(tc.want), out)
			}
			for _, r := range out {
				if want, ok := tc.want[r.ID]; !ok || r.Status != want {
					t.Errorf("%s = %s %q, want %s", r.ID, r.Status, r.Evidence, want)
				}
			}
		})
	}
}

// wwwResolver serves DNS on a 127.0.0.1 UDP port until the test ends,
// answering an A query for www.<target> with 127.0.0.1 and every other
// query with no records, and returns its address.
func wwwResolver(t *testing.T, target string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback UDP: %v", err)
	}
	www := mdns.Fqdn("www." + target)
	answer := mdns.HandlerFunc(func(w mdns.ResponseWriter, q *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(q)
		if len(q.Question) == 1 && q.Question[0].Name == www && q.Question[0].Qtype == mdns.TypeA {
			m.Answer = []mdns.RR{&mdns.A{
				Hdr: mdns.RR_Header{Name: www, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 1),
			}}
		}
		_ = w.WriteMsg(m)
	})
	started := make(chan struct{})
	srv := &mdns.Server{
		PacketConn: pc, Handler: answer, NotifyStartedFunc: func() { close(started) },
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS server did not start within 2s")
	}
	return pc.LocalAddr().String()
}
