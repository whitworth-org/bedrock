package web

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestClassifyHTTP2ALPN(t *testing.T) {
	cases := []struct {
		name       string
		negotiated string
		wantStatus report.Status
		wantEvSub  string // substring expected in evidence
		wantRemSub string // substring expected in remediation ("" → must be empty)
		emptyRemed bool
	}{
		{
			name:       "h2 passes",
			negotiated: "h2",
			wantStatus: report.Pass,
			wantEvSub:  "HTTP/2 negotiated via ALPN",
			emptyRemed: true,
		},
		{
			name:       "http/1.1 warns",
			negotiated: "http/1.1",
			wantStatus: report.Warn,
			wantEvSub:  "only supports HTTP/1.1",
			wantRemSub: "enable HTTP/2",
		},
		{
			name:       "empty ALPN warns",
			negotiated: "",
			wantStatus: report.Warn,
			wantEvSub:  "no ALPN protocol negotiated",
			wantRemSub: "enable HTTP/2",
		},
		{
			name:       "unexpected ALPN warns",
			negotiated: "spdy/3.1",
			wantStatus: report.Warn,
			wantEvSub:  "unexpected ALPN protocol negotiated (spdy/3.1)",
			wantRemSub: "enable HTTP/2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStatus, gotEv, gotRem := classifyHTTP2ALPN(tc.negotiated)
			if gotStatus != tc.wantStatus {
				t.Errorf("status = %v, want %v", gotStatus, tc.wantStatus)
			}
			if !strings.Contains(gotEv, tc.wantEvSub) {
				t.Errorf("evidence = %q, want to contain %q", gotEv, tc.wantEvSub)
			}
			if tc.emptyRemed {
				if gotRem != "" {
					t.Errorf("remediation = %q, want empty", gotRem)
				}
			} else if !strings.Contains(gotRem, tc.wantRemSub) {
				t.Errorf("remediation = %q, want to contain %q", gotRem, tc.wantRemSub)
			}
		})
	}
}

// TestHTTP2CheckRegistered confirms the check landed in the registry's WWW
// category. Registration happens through checkutil.Wrap in this file's
// init(), so we look the entry up by id rather than instantiating the old
// empty-struct type.
func TestHTTP2CheckRegistered(t *testing.T) {
	found := false
	for _, c := range registry.All() {
		if c.ID() == "web.http2" {
			found = true
			if c.Category() != category {
				t.Errorf("Category() = %q, want %q", c.Category(), category)
			}
			break
		}
	}
	if !found {
		t.Errorf("web.http2 not registered")
	}
}

// TestHTTP2_ProbeOutcomes runs the ALPN check against loopback servers.
// Certificates are web.cert's business, so a self-signed h2 server passes; a
// reset or a refused SSRF dial is inconclusive; a refused connection and a
// failed handshake FAIL.
func TestHTTP2_ProbeOutcomes(t *testing.T) {
	t.Run("self-signed h2 server", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		srv := startTLSServer(t, http.NotFoundHandler(), &tls.Config{}, true)
		setPort(t, &http2Port, portOf(srv.Listener.Addr()))
		r := runHTTP2(context.Background(), env)[0]
		if r.Status != report.Pass || r.Evidence != "HTTP/2 negotiated via ALPN (h2)" {
			t.Errorf("got %s %q, want PASS for h2", r.Status, r.Evidence)
		}
	})
	t.Run("reset after accept", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		setPort(t, &http2Port, portOf(resetListener(t)))
		assertInconclusive(t, runHTTP2(context.Background(), env)[0], resetText())
	})
	t.Run("refused port", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		env.Timeout = refusedDialTimeout
		port := closedPort(t)
		setPort(t, &http2Port, port)
		assertHTTP2Fail(t, runHTTP2(context.Background(), env)[0],
			"TCP dial to 127.0.0.1:"+port+" failed: ", http2DialRemediation("127.0.0.1:"+port))
	})
	t.Run("plain HTTP listener", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		srv := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(srv.Close)
		port := portOf(srv.Listener.Addr())
		setPort(t, &http2Port, port)
		assertHTTP2Fail(t, runHTTP2(context.Background(), env)[0],
			"TLS handshake to 127.0.0.1:"+port+" failed: ", http2HandshakeRemediation("127.0.0.1"))
	})
	t.Run("loopback without override", func(t *testing.T) {
		env := activeLoopbackEnv(t)
		t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
		addr, accepted := tarpitListener(t)
		setPort(t, &http2Port, portOf(addr))
		assertInconclusive(t, runHTTP2(context.Background(), env)[0],
			"ssrf dial: refusing 127.0.0.1")
		if n := accepted.Load(); n != 0 {
			t.Errorf("the denylist let %d connections through", n)
		}
	})
}

// TestHTTP2_CancelReturnsPromptly: cancelling the scan interrupts the
// handshake, and the interrupted probe is inconclusive, not a FAIL.
func TestHTTP2_CancelReturnsPromptly(t *testing.T) {
	env := activeLoopbackEnv(t)
	env.Timeout = 5 * time.Second
	addr, _ := tarpitListener(t)
	setPort(t, &http2Port, portOf(addr))

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	r := runHTTP2(ctx, env)[0]
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("returned %v after the cancel, want promptly", elapsed)
	}
	assertInconclusive(t, r, "context canceled")
}

func assertHTTP2Fail(t *testing.T, r report.Result, evidencePrefix, remediation string) {
	t.Helper()
	if r.Status != report.Fail || !strings.HasPrefix(r.Evidence, evidencePrefix) ||
		r.Remediation != remediation {
		t.Errorf("got %s %q (remediation %q), want FAIL %q... (remediation %q)",
			r.Status, r.Evidence, r.Remediation, evidencePrefix, remediation)
	}
}
