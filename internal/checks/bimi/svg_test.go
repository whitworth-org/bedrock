package bimi

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/registry"
	"github.com/whitworth-org/bedrock/internal/report"
)

const validSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 64 64">
  <title>Example</title>
  <rect x="0" y="0" width="64" height="64" fill="#0033aa"/>
  <circle cx="32" cy="32" r="20" fill="#ffffff"/>
</svg>`

const scriptSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 64 64">
  <script><![CDATA[ alert(1) ]]></script>
  <rect x="0" y="0" width="64" height="64"/>
</svg>`

const wrongAspectSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 100 50">
  <rect x="0" y="0" width="100" height="50"/>
</svg>`

const eventHandlerSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 64 64">
  <rect x="0" y="0" width="64" height="64" onclick="alert(1)"/>
</svg>`

const externalImageSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 64 64">
  <image href="https://evil.example/logo.png" width="64" height="64"/>
</svg>`

const missingBaseProfileSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect x="0" y="0" width="64" height="64"/>
</svg>`

const wrongRootSVG = `<?xml version="1.0" encoding="UTF-8"?>
<html><body>not an SVG</body></html>`

func TestValidateTinyPS_Valid(t *testing.T) {
	v := ValidateTinyPS([]byte(validSVG))
	if v.fatalError != "" {
		t.Errorf("unexpected fatal: %s", v.fatalError)
	}
	if len(v.profileFails) != 0 {
		t.Errorf("unexpected profile fails: %v", v.profileFails)
	}
}

func TestValidateTinyPS_RejectsScript(t *testing.T) {
	v := ValidateTinyPS([]byte(scriptSVG))
	if v.fatalError != "" {
		t.Fatalf("unexpected fatal: %s", v.fatalError)
	}
	found := false
	for _, p := range v.profileFails {
		if strings.Contains(p, "<script>") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected <script> to be flagged; got: %v", v.profileFails)
	}
}

func TestValidateTinyPS_RejectsEventHandler(t *testing.T) {
	v := ValidateTinyPS([]byte(eventHandlerSVG))
	if v.fatalError != "" {
		t.Fatalf("unexpected fatal: %s", v.fatalError)
	}
	found := false
	for _, p := range v.profileFails {
		if strings.Contains(p, "onclick") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected onclick to be flagged; got: %v", v.profileFails)
	}
}

func TestValidateTinyPS_RejectsExternalImage(t *testing.T) {
	v := ValidateTinyPS([]byte(externalImageSVG))
	if v.fatalError != "" {
		t.Fatalf("unexpected fatal: %s", v.fatalError)
	}
	// Two violations expected: <image> is disallowed, AND its href is external.
	disallowedHit := false
	hrefHit := false
	for _, p := range v.profileFails {
		if strings.Contains(p, "<image>") {
			disallowedHit = true
		}
		if strings.Contains(p, "external href") {
			hrefHit = true
		}
	}
	if !disallowedHit {
		t.Errorf("expected <image> to be flagged; got: %v", v.profileFails)
	}
	if !hrefHit {
		t.Errorf("expected external href to be flagged; got: %v", v.profileFails)
	}
}

func TestValidateTinyPS_RequiresBaseProfile(t *testing.T) {
	v := ValidateTinyPS([]byte(missingBaseProfileSVG))
	if v.fatalError != "" {
		t.Fatalf("unexpected fatal: %s", v.fatalError)
	}
	found := false
	for _, p := range v.profileFails {
		if strings.Contains(p, "baseProfile") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected baseProfile to be flagged; got: %v", v.profileFails)
	}
}

func TestValidateTinyPS_WrongRoot(t *testing.T) {
	v := ValidateTinyPS([]byte(wrongRootSVG))
	if v.fatalError == "" {
		t.Fatal("expected fatal error for non-SVG root")
	}
}

func TestExtractViewBox_Square(t *testing.T) {
	w, h, raw, err := extractViewBox([]byte(validSVG))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w != 64 || h != 64 {
		t.Errorf("got w=%v h=%v want 64,64 (raw=%q)", w, h, raw)
	}
}

func TestExtractViewBox_NonSquare(t *testing.T) {
	w, h, _, err := extractViewBox([]byte(wrongAspectSVG))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w == h {
		t.Errorf("expected non-square aspect, got %v:%v", w, h)
	}
}

func TestExtractViewBox_Missing(t *testing.T) {
	const noViewBox = `<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps"><rect/></svg>`
	_, _, _, err := extractViewBox([]byte(noViewBox))
	if err == nil {
		t.Fatal("expected error for missing viewBox")
	}
}

func TestIsExternalRef(t *testing.T) {
	cases := map[string]bool{
		"":                 false,
		"#frag":            false,
		"#":                false,
		"https://x/y":      true,
		"http://x":         true,
		"data:image/png;,": true,
		"/foo":             true,
		"foo.svg":          true,
	}
	for in, want := range cases {
		if got := isExternalRef(in); got != want {
			t.Errorf("isExternalRef(%q)=%v want %v", in, got, want)
		}
	}
}

// logoEnv returns an Env for example.test whose BIMI record names logoURL.
func logoEnv(t *testing.T, logoURL string, timeout time.Duration) *probe.Env {
	t.Helper()
	return newZoneEnv(t, "example.test", bimiZone(logoURL, "https://localhost/vmc.pem"), timeout)
}

// TestFetchChecksRefuseNonHTTPSURLs: a plain-http l= or a= is reported once,
// by bimi.txt, and never fetched.
func TestFetchChecksRefuseNonHTTPSURLs(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = io.WriteString(w, validSVG)
	}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split test server address: %v", err)
	}
	base := "http://localhost:" + port
	env := newZoneEnv(t, "example.test", bimiZone(base+"/logo.svg", base+"/vmc.pem"), 2*time.Second)
	cases := []struct {
		check registry.Check
		want  string
	}{
		{svgFetchCheck{}, `l= URL not fetched: scheme "http" is not https (see bimi.txt)`},
		{vmcFetchCheck{}, `a= URL not fetched: scheme "http" is not https (see bimi.txt)`},
	}
	for _, tc := range cases {
		r := runOne(t, tc.check, env)
		if r.Status != report.NotApplicable || r.Evidence != tc.want {
			t.Errorf("%s = %s %q, want N/A %q", tc.check.ID(), r.Status, r.Evidence, tc.want)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the plain-http server received %d requests, want 0", n)
	}
}

func TestSVGFetchGrades(t *testing.T) {
	other := newSite(t, map[string]siteFile{"/logo.svg": {"image/svg+xml", []byte(validSVG)}})
	s := newSite(t, map[string]siteFile{
		"/valid.svg": {"image/svg+xml; charset=utf-8", []byte(validSVG)},
		"/empty.svg": {"image/svg+xml", nil},
		"/huge.svg":  {"image/svg+xml", make([]byte, 1<<20+1)},
		"/page.html": {"text/html", []byte("<html></html>")},
		"/odd.svg":   {"text/" + strings.Repeat("x", 10_000), []byte(validSVG)},
	})
	redirect := serveTLS(t, trustedCA(t), http.RedirectHandler(other.base+"/logo.svg",
		http.StatusMovedPermanently))
	cases := []struct {
		url        string
		wantStatus report.Status
		wantIn     string
	}{
		{s.base + "/valid.svg", report.Pass, "HTTP 200 image/svg+xml, "},
		{redirect + "/logo.svg", report.Pass, "HTTP 200 image/svg+xml, "},
		{s.base + "/empty.svg", report.Fail, "failed: empty body"},
		{s.base + "/huge.svg", report.Fail, "failed: body exceeds the 1 MiB fetch cap"},
		{s.base + "/missing.svg", report.Fail, "failed: HTTP 404"},
		{s.base + "/page.html", report.Fail, `Content-Type="text/html" (want image/svg+xml)`},
		{s.base + "/odd.svg", report.Fail, `Content-Type="text/xxx`},
	}
	for _, tc := range cases {
		r := runOne(t, svgFetchCheck{}, logoEnv(t, tc.url, 2*time.Second))
		if r.Status != tc.wantStatus || !strings.Contains(r.Evidence, tc.wantIn) ||
			len(r.Evidence) > 400 {
			t.Errorf("%s: got %s %.400q, want %s with %q", tc.url, r.Status, r.Evidence,
				tc.wantStatus, tc.wantIn)
		}
	}
}

// TestSVGFetchStalledServerIsInconclusive: a server that never answers
// leaves the logo unknown, not failing.
func TestSVGFetchStalledServerIsInconclusive(t *testing.T) {
	r := runOne(t, svgFetchCheck{}, logoEnv(t, stallingURL(t), 500*time.Millisecond))
	if r.Status != report.Warn || !strings.HasPrefix(r.Evidence, "could not determine: ") {
		t.Errorf("got %s %q, want Inconclusive", r.Status, r.Evidence)
	}
}

// TestSVGFetchResetConnectionIsInconclusive: a server that resets the
// connection leaves the logo unknown, not failing.
func TestSVGFetchResetConnectionIsInconclusive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on a loopback TCP port: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Read(make([]byte, 1))
			_ = conn.(*net.TCPConn).SetLinger(0) // close with a reset
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener address %q: %v", ln.Addr(), err)
	}
	logoURL := "https://localhost:" + port + "/logo.svg"
	r := runOne(t, svgFetchCheck{}, logoEnv(t, logoURL, 2*time.Second))
	if r.Status != report.Warn || !strings.HasPrefix(r.Evidence, "could not determine: ") {
		t.Errorf("got %s %q, want Inconclusive", r.Status, r.Evidence)
	}
}

// TestSVGFetchCanceledScanIsInconclusive: a scan canceled during the fetch
// leaves the logo unknown, not failing.
func TestSVGFetchCanceledScanIsInconclusive(t *testing.T) {
	env := logoEnv(t, stallingURL(t), 5*time.Second)
	if ensureRecord(context.Background(), env) == nil {
		t.Fatal("the test zone's BIMI record did not parse")
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	rs := svgFetchCheck{}.Run(ctx, env)
	if len(rs) != 1 || rs[0].Status != report.Warn ||
		!strings.HasPrefix(rs[0].Evidence, "could not determine: ") {
		t.Errorf("got %+v, want one Inconclusive result", rs)
	}
}

// TestSVGFetchUntrustedCertificateFails: the logo comes only over verified
// TLS, so a certificate nothing trusts fails the fetch, naming the cause.
func TestSVGFetchUntrustedCertificateFails(t *testing.T) {
	serve := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = io.WriteString(w, validSVG)
	}
	base := serveTLS(t, untrustedCA(t), http.HandlerFunc(serve))
	r := runOne(t, svgFetchCheck{}, logoEnv(t, base+"/logo.svg", 2*time.Second))
	const cause = "certificate signed by unknown authority"
	if r.Status != report.Fail || !strings.Contains(r.Evidence, cause) {
		t.Errorf("got %s %q, want FAIL naming the certificate", r.Status, r.Evidence)
	}
	for _, c := range []registry.Check{svgProfileCheck{}, svgAspectCheck{}} {
		env := logoEnv(t, base+"/logo.svg", 2*time.Second)
		if r := runOne(t, c, env); r.Status != report.NotApplicable {
			t.Errorf("%s = %s %q, want N/A", c.ID(), r.Status, r.Evidence)
		}
	}
}

// TestSVGProfileBoundsViolations: 500 forbidden attributes give one result
// listing ten of them and counting the rest.
func TestSVGProfileBoundsViolations(t *testing.T) {
	flood := `<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 64 64">` +
		`<rect` + strings.Repeat(` onclick=""`, 500) + `/></svg>`
	s := newSite(t, map[string]siteFile{"/logo.svg": {"image/svg+xml", []byte(flood)}})
	r := runOne(t, svgProfileCheck{}, logoEnv(t, s.base+"/logo.svg", 2*time.Second))
	if r.Status != report.Fail {
		t.Fatalf("got %s %q, want FAIL", r.Status, r.Evidence)
	}
	if n := strings.Count(r.Evidence, "event-handler attribute onclick on <rect>"); n != 10 {
		t.Errorf("evidence lists %d violations, want 10: %q", n, r.Evidence)
	}
	if !strings.HasSuffix(r.Evidence, "; and 490 more") {
		t.Errorf("evidence %q does not count the 490 unlisted violations", r.Evidence)
	}
}

func TestValidateTinyPSFlagsURLAttributes(t *testing.T) {
	attrs := []string{"marker-start", "marker-mid", "marker-end", "cursor", "color-profile"}
	for _, attr := range attrs {
		svg := `<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 1 1">` +
			`<path d="M0 0" ` + attr + `="url(https://evil.example/m.svg#a)"/></svg>`
		v := ValidateTinyPS([]byte(svg))
		want := "attribute " + attr + " on <path> contains dangerous token url("
		if len(v.profileFails) != 1 || !strings.HasPrefix(v.profileFails[0], want) {
			t.Errorf("%s: profile fails %q, want one starting %q", attr, v.profileFails, want)
		}
	}
}

// TestSVGEvidenceClipsDocumentValues: values echoed from the logo are
// clipped, so a hostile document cannot flood the report.
func TestSVGEvidenceClipsDocumentValues(t *testing.T) {
	const open = `<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps"`
	long, gap := strings.Repeat("x", 100_000), strings.Repeat(" ", 100_000)
	docs := map[string]string{
		"attribute": open + `><rect fill="url(` + long + `)"/></svg>`,
		"handler":   open + `><rect on` + long + `=""/></svg>`,
		"href":      open + `><use href="https://` + long + `"/></svg>`,
		"encoding":  `<?xml version="1.0" encoding="` + long + `"?>` + open + `/>`,
		"element":   open + `><` + long + `/></svg>`,
		"root":      `<` + long + `/>`,
		"pi":        `<?` + long + ` ?>` + open + `/>`,
		"syntax":    open + `><` + long + `></svg>`,
		"viewBox":   open + ` viewBox="` + long + `"/>`,
		"profile":   `<svg xmlns="http://www.w3.org/2000/svg" baseProfile="` + long + `"/>`,
		"numbers":   open + ` viewBox="0 0 ` + long + ` 1"/>`,
		"negative":  open + ` viewBox="0 0 -` + strings.Repeat("0", 100_000) + ` 1"/>`,
		"aspect":    open + ` viewBox="0 0 100` + gap + `50"/>`,
		"square":    open + ` viewBox="0 0 64` + gap + `64"/>`,
	}
	files := map[string]siteFile{}
	for name, doc := range docs {
		files["/"+name+".svg"] = siteFile{"image/svg+xml", []byte(doc)}
	}
	s := newSite(t, files)
	for name := range docs {
		for _, c := range []registry.Check{svgProfileCheck{}, svgAspectCheck{}} {
			r := runOne(t, c, logoEnv(t, s.base+"/"+name+".svg", 2*time.Second))
			if len(r.Evidence) > 400 {
				t.Errorf("%s on %s: %d-byte evidence %.80q",
					c.ID(), name, len(r.Evidence), r.Evidence)
			}
		}
	}
}

// TestSVGChecksReadDeclaredEncodings: a logo whose XML declaration names
// ISO-8859-1 or US-ASCII (apple.com's does) is graded on its content; any
// other encoding leaves both checks undetermined rather than failing.
func TestSVGChecksReadDeclaredEncodings(t *testing.T) {
	body := strings.TrimPrefix(validSVG, `<?xml version="1.0" encoding="UTF-8"?>`)
	latin1 := strings.Replace(body, "Example", "Caf\xe9", 1) // é in ISO-8859-1
	const unsupported = `could not determine: unsupported SVG encoding "windows-1252" ` +
		`(bedrock reads UTF-8, US-ASCII and ISO-8859-1)`
	cases := []struct {
		encoding, body string
		want           report.Status
		evidence       map[string]string // by check ID
	}{
		{"iso-8859-1", latin1, report.Pass, nil},
		{"Latin1", latin1, report.Pass, nil},
		{"us-ascii", body, report.Pass, nil},
		{"windows-1252", latin1, report.Warn, map[string]string{
			"bimi.svg.profile": unsupported, "bimi.svg.aspect": unsupported,
		}},
	}
	files := map[string]siteFile{}
	for _, tc := range cases {
		doc := `<?xml version="1.0" encoding="` + tc.encoding + `"?>` + tc.body
		files["/"+tc.encoding+".svg"] = siteFile{"image/svg+xml", []byte(doc)}
	}
	s := newSite(t, files)
	for _, tc := range cases {
		for _, c := range []registry.Check{svgProfileCheck{}, svgAspectCheck{}} {
			r := runOne(t, c, logoEnv(t, s.base+"/"+tc.encoding+".svg", 2*time.Second))
			want, ok := tc.evidence[c.ID()]
			if r.Status != tc.want || (ok && r.Evidence != want) || r.Remediation != "" {
				t.Errorf("%s with encoding %s: got %s %q (remediation %q), want %s %q",
					c.ID(), tc.encoding, r.Status, r.Evidence, r.Remediation, tc.want, want)
			}
		}
	}
}

// TestValidateTinyPSKeepsViolationsBeforeEncoding: an XML declaration after
// a violation does not turn the failure into an undetermined result.
func TestValidateTinyPSKeepsViolationsBeforeEncoding(t *testing.T) {
	const doc = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">` +
		`<?xml version="1.0" encoding="windows-1252"?></svg>`
	v := ValidateTinyPS([]byte(doc))
	if v.undecodable != nil || !strings.HasPrefix(v.fatalError, "XML parse error: ") ||
		len(v.profileFails) != 1 {
		t.Errorf("got undecodable %v, fatal %q, fails %q; want a parse error and the "+
			"missing baseProfile", v.undecodable, v.fatalError, v.profileFails)
	}
}

// TestSVGCharsetReaderReportsReadErrors: a failing source surfaces as the
// decoder's error instead of an empty document.
func TestSVGCharsetReaderReportsReadErrors(t *testing.T) {
	errRead := errors.New("connection reset")
	_, err := svgCharsetReader("iso-8859-1", iotest.ErrReader(errRead))
	if !errors.Is(err, errRead) {
		t.Errorf("svgCharsetReader error = %v, want %v", err, errRead)
	}
}
