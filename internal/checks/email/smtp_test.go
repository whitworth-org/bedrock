package email

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/textproto"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// smtpScript plays the server side of one SMTP session; r reads from c.
type smtpScript func(c net.Conn, r *bufio.Reader)

// smtpServer is a scripted SMTP server on 127.0.0.1, which tests reach as
// the MX host localhost through the fake resolver and the smtpPort seam.
type smtpServer struct {
	accepted atomic.Int32
	mu       sync.Mutex
	conns    []net.Conn
	wg       sync.WaitGroup
}

// startSMTP runs script for every connection until the test ends and
// points smtpPort at the server.
func startSMTP(t *testing.T, script smtpScript) *smtpServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	setSMTPPort(t, ln.Addr())
	s := &smtpServer{}
	s.wg.Go(func() { s.serve(ln, script) })
	t.Cleanup(func() {
		_ = ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
	return s
}

func (s *smtpServer) serve(ln net.Listener, script smtpScript) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.accepted.Add(1)
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		s.wg.Go(func() {
			defer func() { _ = conn.Close() }()
			script(conn, bufio.NewReader(conn))
		})
	}
}

// setSMTPPort points the STARTTLS probe at addr's port until the test ends.
func setSMTPPort(t *testing.T, addr net.Addr) {
	t.Helper()
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}
	old := smtpPort
	smtpPort = port
	t.Cleanup(func() { smtpPort = old })
}

// send writes each line to c with a CRLF and reports whether all of them
// were written.
func send(c net.Conn, lines ...string) bool {
	for _, line := range lines {
		if _, err := io.WriteString(c, line+"\r\n"); err != nil {
			return false
		}
	}
	return true
}

// received reads one command line from r and reports whether it starts
// with verb.
func received(r *bufio.Reader, verb string) bool {
	line, err := r.ReadString('\n')
	return err == nil && strings.HasPrefix(strings.ToUpper(line), verb)
}

// starttlsScript answers the plaintext phase of a session that offers
// STARTTLS and then runs tlsStep on c, pausing before each step.
func starttlsScript(pause time.Duration, tlsStep func(c net.Conn)) smtpScript {
	return func(c net.Conn, r *bufio.Reader) {
		time.Sleep(pause)
		if !send(c, "220 mx.test ESMTP") || !received(r, "EHLO") {
			return
		}
		time.Sleep(pause)
		if !send(c, "250-mx.test", "250-PIPELINING", "250 STARTTLS") || !received(r, "STARTTLS") {
			return
		}
		time.Sleep(pause)
		if send(c, "220 2.0.0 ready to start TLS") {
			time.Sleep(pause)
			tlsStep(c)
		}
	}
}

// serveTLS returns a TLS step that completes the handshake with cert.
func serveTLS(cert tls.Certificate) func(net.Conn) {
	return func(c net.Conn) {
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		_ = tls.Server(c, cfg).Handshake()
	}
}

// localhostCert returns a self-signed certificate for localhost and a pool
// that trusts it.
func localhostCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

// setSMTPRootCAs makes the STARTTLS probe trust roots until the test ends.
func setSMTPRootCAs(t *testing.T, roots *x509.CertPool) {
	t.Helper()
	old := smtpRootCAs
	smtpRootCAs = roots
	t.Cleanup(func() { smtpRootCAs = old })
}

// starttlsEnv returns an active Env for example.com, whose MX records are
// mxs, with timeout as --timeout.
func starttlsEnv(t *testing.T, timeout time.Duration, mxs ...string) *probe.Env {
	t.Helper()
	zone := cannedZone{mx: map[string][]string{"example.com": mxs}}
	return probe.NewEnv("example.com", timeout, true, startCannedDNS(t, zone))
}

// starttlsResult runs the STARTTLS check for example.com, whose one MX is
// localhost, and returns its one result.
func starttlsResult(t *testing.T, ctx context.Context, timeout time.Duration) report.Result {
	t.Helper()
	res := runSTARTTLS(ctx, starttlsEnv(t, timeout, "10 localhost."))
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(res), res)
	}
	return res[0]
}

// TestRunSTARTTLS_EachStepHasItsOwnTimeout: every protocol step gets the
// full --timeout, so an MX that answers each step slowly but in time passes,
// although the session as a whole takes longer than one timeout.
func TestRunSTARTTLS_EachStepHasItsOwnTimeout(t *testing.T) {
	cert, roots := localhostCert(t)
	setSMTPRootCAs(t, roots)
	startSMTP(t, starttlsScript(600*time.Millisecond, serveTLS(cert)))
	r := starttlsResult(t, context.Background(), time.Second)
	want := "STARTTLS advertised, handshake ok (TLS 1.3)"
	if r.Status != report.Pass || r.Evidence != want {
		t.Errorf("%s = %s %q, want PASS %q", r.ID, r.Status, r.Evidence, want)
	}
}

// TestRunSTARTTLS_HostHasABudget: an MX that answers every step slowly but
// in time cannot hold the check for more than starttlsBudget timeouts in
// all; a probe that runs out of budget is inconclusive.
func TestRunSTARTTLS_HostHasABudget(t *testing.T) {
	cert, roots := localhostCert(t)
	setSMTPRootCAs(t, roots)
	startSMTP(t, starttlsScript(500*time.Millisecond, serveTLS(cert)))
	const timeout = 600 * time.Millisecond
	start := time.Now()
	r := starttlsResult(t, context.Background(), timeout)
	elapsed := time.Since(start)
	assertInconclusive(t, r, "STARTTLS advertised but TLS handshake to localhost failed: "+
		"probe did not finish within 1.8s")
	if limit := starttlsBudget*timeout + 300*time.Millisecond; elapsed > limit {
		t.Errorf("the check took %s, want at most %s", elapsed, limit)
	}
}

// TestRunSTARTTLS_UntrustedCertificateWarns: the MX offers STARTTLS, which
// is what the check measures, but its certificate does not verify.
func TestRunSTARTTLS_UntrustedCertificateWarns(t *testing.T) {
	cert, _ := localhostCert(t)
	startSMTP(t, starttlsScript(0, serveTLS(cert)))
	r := starttlsResult(t, context.Background(), time.Second)
	want := "STARTTLS advertised but TLS handshake to localhost failed: "
	if r.Status != report.Warn || !strings.HasPrefix(r.Evidence, want) {
		t.Errorf("%s = %s %q, want WARN %q...", r.ID, r.Status, r.Evidence, want)
	}
}

// TestRunSTARTTLS_HandshakeStallIsInconclusive: an MX that accepts STARTTLS
// and never answers the ClientHello times out on the handshake step.
func TestRunSTARTTLS_HandshakeStallIsInconclusive(t *testing.T) {
	startSMTP(t, starttlsScript(0, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }))
	assertInconclusive(t, starttlsResult(t, context.Background(), time.Second),
		"STARTTLS advertised but TLS handshake to localhost failed", "i/o timeout")
}

// TestRunSTARTTLS_StallAfterBannerIsInconclusive: an MX that never answers
// EHLO times out on that step, which says nothing about STARTTLS.
func TestRunSTARTTLS_StallAfterBannerIsInconclusive(t *testing.T) {
	startSMTP(t, func(c net.Conn, r *bufio.Reader) {
		if send(c, "220 mx.test ESMTP") {
			_, _ = io.Copy(io.Discard, r)
		}
	})
	r := starttlsResult(t, context.Background(), time.Second)
	assertInconclusive(t, r, "EHLO failed at localhost", "i/o timeout")
	if strings.Contains(r.Evidence, "127.0.0.1") {
		t.Errorf("evidence %q names a socket address", r.Evidence)
	}
}

// TestRunSTARTTLS_RejectingBannerFails: a 554 banner is the MX's answer.
func TestRunSTARTTLS_RejectingBannerFails(t *testing.T) {
	startSMTP(t, func(c net.Conn, _ *bufio.Reader) { send(c, "554 5.7.1 no thanks") })
	r := starttlsResult(t, context.Background(), time.Second)
	want := "no 220 banner from localhost: " +
		(&textproto.Error{Code: 554, Msg: "5.7.1 no thanks"}).Error()
	if r.Status != report.Fail || r.Evidence != want ||
		r.Remediation != starttlsRemediation("localhost") {
		t.Errorf("%s = %s %q (remediation %q), want FAIL %q with the STARTTLS remediation",
			r.ID, r.Status, r.Evidence, r.Remediation, want)
	}
}

// TestRunSTARTTLS_RejectedStartFails: an MX that advertises STARTTLS and
// then answers the command with 454 has refused TLS, which FAILs.
func TestRunSTARTTLS_RejectedStartFails(t *testing.T) {
	const reply = "4.7.0 TLS not available due to temporary reason"
	startSMTP(t, func(c net.Conn, r *bufio.Reader) {
		if send(c, "220 mx.test ESMTP") && received(r, "EHLO") &&
			send(c, "250-mx.test", "250 STARTTLS") && received(r, "STARTTLS") {
			send(c, "454 "+reply)
		}
	})
	r := starttlsResult(t, context.Background(), time.Second)
	want := "STARTTLS not accepted by localhost: " +
		(&textproto.Error{Code: 454, Msg: reply}).Error()
	if r.Status != report.Fail || r.Evidence != want ||
		r.Remediation != starttlsRemediation("localhost") {
		t.Errorf("%s = %s %q (remediation %q), want FAIL %q with the STARTTLS remediation",
			r.ID, r.Status, r.Evidence, r.Remediation, want)
	}
}

// TestSMTPSession_HangUpAfterBanner: an MX that hangs up after its banner
// leaves EHLO unsent, an I/O failure that is not the MX's answer.
func TestSMTPSession_HangUpAfterBanner(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		_, _ = io.WriteString(server, "220 mx.test ESMTP\r\n")
		_ = server.Close()
	}()
	s := &smtpSession{
		conn: client, r: bufio.NewReaderSize(client, maxReplyLineBytes), timeout: time.Second,
	}
	err := s.negotiate(context.Background(), "mx.test")
	if !errors.Is(err, io.ErrClosedPipe) || serverAnswered(err) ||
		!strings.HasPrefix(err.Error(), "EHLO failed at mx.test: ") {
		t.Errorf("negotiate = %v, want an EHLO write failure that the MX did not answer", err)
	}
}

// TestRunSTARTTLS_NotAdvertisedFails: an EHLO reply without STARTTLS FAILs.
func TestRunSTARTTLS_NotAdvertisedFails(t *testing.T) {
	startSMTP(t, func(c net.Conn, r *bufio.Reader) {
		if send(c, "220 mx.test ESMTP") && received(r, "EHLO") {
			send(c, "250-mx.test", "250 PIPELINING")
		}
	})
	r := starttlsResult(t, context.Background(), time.Second)
	want := "EHLO response from localhost did not advertise STARTTLS"
	if r.Status != report.Fail || r.Evidence != want || r.Remediation == "" {
		t.Errorf("%s = %s %q (remediation %q), want FAIL %q with a remediation",
			r.ID, r.Status, r.Evidence, r.Remediation, want)
	}
}

// TestRunSTARTTLS_EndlessReplyFails: an EHLO reply that never ends is cut
// off at 100 lines and graded as the MX's answer, long before --timeout.
func TestRunSTARTTLS_EndlessReplyFails(t *testing.T) {
	startSMTP(t, func(c net.Conn, r *bufio.Reader) {
		if send(c, "220 mx.test ESMTP") && received(r, "EHLO") {
			for send(c, "250-PIPELINING") {
			}
		}
	})
	r := starttlsResult(t, context.Background(), 10*time.Second)
	want := "EHLO failed at localhost: reply longer than 100 lines"
	if r.Status != report.Fail || r.Evidence != want {
		t.Errorf("%s = %s %q, want FAIL %q", r.ID, r.Status, r.Evidence, want)
	}
}

// TestRunSTARTTLS_OverlongLineFails: a reply line one octet over the 512
// that RFC 5321 §4.5.3.1.5 allows is cut off and graded as the MX's answer.
func TestRunSTARTTLS_OverlongLineFails(t *testing.T) {
	startSMTP(t, func(c net.Conn, r *bufio.Reader) {
		if send(c, "220 "+strings.Repeat("a", 507)) {
			_, _ = io.Copy(io.Discard, r)
		}
	})
	r := starttlsResult(t, context.Background(), time.Second)
	want := "no 220 banner from localhost: reply line longer than 512 bytes"
	if r.Status != report.Fail || r.Evidence != want {
		t.Errorf("%s = %s %q, want FAIL %q", r.ID, r.Status, r.Evidence, want)
	}
}

// TestRunSTARTTLS_CancelClosesConnection: cancelling the scan closes the
// connection at once, so the probe neither waits out --timeout nor leaves
// the session open.
func TestRunSTARTTLS_CancelClosesConnection(t *testing.T) {
	gotEHLO, closed := make(chan struct{}), make(chan struct{})
	startSMTP(t, func(c net.Conn, r *bufio.Reader) {
		defer close(closed)
		if send(c, "220 mx.test ESMTP") && received(r, "EHLO") {
			close(gotEHLO)
			_, _ = io.Copy(io.Discard, r)
		}
	})
	env := starttlsEnv(t, time.Minute, "10 localhost.")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan []report.Result, 1)
	go func() { done <- runSTARTTLS(ctx, env) }()

	within(t, gotEHLO, 10*time.Second, "EHLO")
	cancel()
	within(t, closed, 2*time.Second, "connection close after the cancel")
	res := within(t, done, 2*time.Second, "probe result after the cancel")
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(res), res)
	}
	assertInconclusive(t, res[0], "EHLO failed at localhost", "context canceled")
}

// within returns what ch yields, or the zero value once ch is closed, and
// fails the test when neither happens within d.
func within[T any](t *testing.T, ch <-chan T, d time.Duration, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(d):
		t.Fatalf("no %s within %s", what, d)
	}
	var zero T
	return zero
}

// TestRunSTARTTLS_DuplicateMXHosts: MX records that differ only in letter
// case and preference name one host, which is probed once.
func TestRunSTARTTLS_DuplicateMXHosts(t *testing.T) {
	srv := startSMTP(t, func(c net.Conn, _ *bufio.Reader) { send(c, "554 5.7.1 no thanks") })
	env := starttlsEnv(t, time.Second, "10 LOCALHOST.", "20 localhost.")
	res := runSTARTTLS(context.Background(), env)
	if err := report.CheckUniqueIDs(res); err != nil {
		t.Error(err)
	}
	want := []string{"email.smtp.starttls.localhost"}
	if got := resultIDs(res); !slices.Equal(got, want) {
		t.Errorf("result IDs = %q, want %q", got, want)
	}
	if n := srv.accepted.Load(); n != 1 {
		t.Errorf("the MX accepted %d connections, want 1", n)
	}
}

// TestRunSTARTTLS_CapsMXHosts: of 15 MX hosts the 10 most preferred are
// probed and the other 5 are named in one INFO result.
func TestRunSTARTTLS_CapsMXHosts(t *testing.T) {
	var mxs []string
	for i := 1; i <= 15; i++ {
		mxs = append(mxs, fmt.Sprintf("%d 127.0.0.%d.", i, i))
	}
	env := starttlsEnv(t, time.Second, mxs...)
	// Without the override every dial is refused before it connects.
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
	res := runSTARTTLS(context.Background(), env)
	if len(res) != 11 {
		t.Fatalf("want 10 host results and 1 skipped-host result, got %d: %q",
			len(res), resultIDs(res))
	}
	skipped, _ := findResult(res, "email.smtp.starttls")
	want := "probed the 10 most preferred MX hosts; not probed: " +
		"127.0.0.11, 127.0.0.12, 127.0.0.13, 127.0.0.14, 127.0.0.15"
	if skipped.Status != report.Info || skipped.Evidence != want {
		t.Errorf("email.smtp.starttls = %s %q, want INFO %q", skipped.Status, skipped.Evidence,
			want)
	}
}

// TestRunSTARTTLS_RefusedPortFails: a refused connection is the MX's answer,
// which FAILs with the STARTTLS remediation.
func TestRunSTARTTLS_RefusedPortFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	setSMTPPort(t, ln.Addr())
	_ = ln.Close()
	// Windows takes about 2s to report a refused loopback connection.
	r := starttlsResult(t, context.Background(), 10*time.Second)
	want := "dial " + net.JoinHostPort("localhost", smtpPort) + " failed: "
	if r.Status != report.Fail || !strings.HasPrefix(r.Evidence, want) ||
		!strings.Contains(r.Evidence, "refused") ||
		r.Remediation != starttlsRemediation("localhost") {
		t.Errorf("%s = %s %q (remediation %q), want FAIL %q... naming the refusal, with "+
			"the STARTTLS remediation", r.ID, r.Status, r.Evidence, r.Remediation, want)
	}
}

// TestRunSTARTTLS_DialHonoursSSRFDenylist: without the operator override
// the probe does not connect to a loopback MX, and the result is
// inconclusive.
func TestRunSTARTTLS_DialHonoursSSRFDenylist(t *testing.T) {
	srv := startSMTP(t, func(c net.Conn, _ *bufio.Reader) { send(c, "554 5.7.1 no thanks") })
	env := starttlsEnv(t, time.Second, "10 localhost.")
	t.Setenv("BEDROCK_ALLOW_PRIVATE_RESOLVER", "")
	res := runSTARTTLS(context.Background(), env)
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d: %+v", len(res), res)
	}
	assertInconclusive(t, res[0], "ssrf dial: refusing")
	if strings.Contains(res[0].Evidence, "TCP/25") {
		t.Errorf("evidence %q blames TCP/25 for an SSRF refusal", res[0].Evidence)
	}
	if n := srv.accepted.Load(); n != 0 {
		t.Errorf("the MX accepted %d connections, want 0", n)
	}
}

// TestDialFailed grades the ways a connection to an MX can fail: only a
// refused connect and a name that does not exist FAIL, and only a reset,
// unreachable or timed-out connect blames TCP/25.
func TestDialFailed(t *testing.T) {
	connectErr := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", err)}
	}
	scan := context.Background()
	ended, cancel := context.WithCancel(scan)
	cancel()
	blocked := &probe.BlockedAddrError{Addr: netip.MustParseAddr("10.0.0.1"), Reason: "private"}
	cases := []struct {
		name  string
		ctx   context.Context
		err   error
		want  report.Status
		tcp25 bool // the evidence says TCP/25 may be blocked
	}{
		{"refused", scan, connectErr(syscall.ECONNREFUSED), report.Fail, false},
		// 10061 is WSAECONNREFUSED, the errno of a refused connect on Windows.
		{"refused on Windows", scan, connectErr(syscall.Errno(10061)), report.Fail, false},
		{"reset", scan, connectErr(syscall.ECONNRESET), wantInconclusive, true},
		{"timed out", scan, connectErr(os.ErrDeadlineExceeded), wantInconclusive, true},
		{"SSRF refusal", scan, blocked, wantInconclusive, false},
		{"lookup timed out", scan, &net.DNSError{Err: "i/o timeout", IsTimeout: true},
			wantInconclusive, false},
		{"no such host", scan, &net.DNSError{Err: "no such host", IsNotFound: true},
			report.Fail, false},
		{"scan ended", ended, connectErr(context.Canceled), wantInconclusive, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := dialFailed(tc.ctx, report.Result{}, "mx.example.com", tc.err)
			note := strings.Contains(r.Evidence, "outbound TCP/25 may be blocked")
			remediated := r.Remediation != ""
			if r.Status != tc.want || note != tc.tcp25 || remediated != (r.Status == report.Fail) {
				t.Errorf("got %s %q (remediation %q), want %s with TCP/25 note %t",
					r.Status, r.Evidence, r.Remediation, tc.want, tc.tcp25)
			}
		})
	}
}

func TestReadReply(t *testing.T) {
	line512 := "250 " + strings.Repeat("a", 506) + "\r\n"
	cases := []struct {
		name      string
		in        string
		wantCode  int
		wantLines []string
		wantErr   string
	}{
		{"one line", "220 mx.test ESMTP\r\n", 220, []string{"mx.test ESMTP"}, ""},
		{"several lines", "250-mx.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n", 250,
			[]string{"mx.test", "PIPELINING", "STARTTLS"}, ""},
		{"code alone", "250\r\n", 250, []string{""}, ""},
		{"bare LF", "250 ok\n", 250, []string{"ok"}, ""},
		{"512-octet line", line512, 250, []string{strings.Repeat("a", 506)}, ""},
		{"513-octet line", "250 a" + line512[4:], 0, nil, "reply line longer than 512 bytes"},
		{"100 lines", strings.Repeat("250-a\r\n", 99) + "250 a\r\n", 250,
			slices.Repeat([]string{"a"}, 100), ""},
		{"101 lines", strings.Repeat("250-a\r\n", 100) + "250 a\r\n", 0, nil,
			"reply longer than 100 lines"},
		{"code changes", "250-a\r\n550 b\r\n", 0, nil, `malformed reply line "550 b"`},
		{"not SMTP", "HTTP/1.1 400 Bad Request\r\n", 0, nil,
			`malformed reply line "HTTP/1.1 400 Bad Request"`},
		{"code out of range", "199 x\r\n", 0, nil, `malformed reply line "199 x"`},
		{"control bytes", "2\x1b[0m\r\n", 0, nil, `malformed reply line "2�[0m"`},
		{"cut short", "250-a\r\n", 0, nil, "EOF"},
		{"nothing", "", 0, nil, "EOF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReaderSize(strings.NewReader(tc.in), maxReplyLineBytes)
			code, lines, err := readReply(r)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if code != tc.wantCode || !slices.Equal(lines, tc.wantLines) || gotErr != tc.wantErr {
				t.Errorf("readReply = %d %q %q, want %d %q %q",
					code, lines, gotErr, tc.wantCode, tc.wantLines, tc.wantErr)
			}
		})
	}
}
