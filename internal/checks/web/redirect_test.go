package web

import (
	"net/url"
	"testing"

	"github.com/whitworth-org/bedrock/internal/probe"
)

func TestSameApexOrWWW(t *testing.T) {
	cases := []struct {
		start, end string
		want       bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{"www.example.com", "example.com", true},
		{"www.example.com", "www.example.com", true},
		{"example.com", "evil.com", false},
		{"example.com", "Example.com:443", true},
		{"sub.example.com", "example.com", false},
		{"example.com", "www.example.com.", true}, // trailing dot tolerated
	}
	for _, tc := range cases {
		got := sameApexOrWWW(tc.start, tc.end)
		if got != tc.want {
			t.Errorf("sameApexOrWWW(%q,%q) = %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestAnalyzeRedirectChain_HappyPath(t *testing.T) {
	final, _ := url.Parse("https://example.com/")
	resp := &probe.Response{
		Status:     200,
		URL:        final,
		RedirectCh: []*url.URL{mustURL("http://example.com/"), final},
	}
	v := analyzeRedirectChain("example.com", resp)
	if v.err != nil {
		t.Fatalf("expected no error, got %v", v.err)
	}
	if !v.permanent {
		t.Errorf("expected permanent=true")
	}
}

func TestAnalyzeRedirectChain_FinalNotHTTPS(t *testing.T) {
	final, _ := url.Parse("http://example.com/")
	resp := &probe.Response{
		Status:     200,
		URL:        final,
		RedirectCh: []*url.URL{final},
	}
	v := analyzeRedirectChain("example.com", resp)
	if v.err == nil {
		t.Fatalf("expected error for non-HTTPS final URL")
	}
}

func TestAnalyzeRedirectChain_DifferentHost(t *testing.T) {
	final, _ := url.Parse("https://other.com/")
	resp := &probe.Response{
		Status:     200,
		URL:        final,
		RedirectCh: []*url.URL{mustURL("http://example.com/"), final},
	}
	v := analyzeRedirectChain("example.com", resp)
	if v.err == nil {
		t.Fatalf("expected error for cross-host redirect")
	}
}

func TestAnalyzeRedirectChain_TooManyHops(t *testing.T) {
	final, _ := url.Parse("https://example.com/x")
	chain := []*url.URL{mustURL("http://example.com/")}
	for i := 0; i < 10; i++ {
		chain = append(chain, mustURL("https://example.com/"))
	}
	chain = append(chain, final)
	resp := &probe.Response{Status: 200, URL: final, RedirectCh: chain}
	v := analyzeRedirectChain("example.com", resp)
	if v.err == nil {
		t.Fatalf("expected error for chain >8 hops")
	}
}

func TestAnalyzeRedirectChain_FinalErrorStatus(t *testing.T) {
	final, _ := url.Parse("https://example.com/")
	resp := &probe.Response{
		Status:     500,
		URL:        final,
		RedirectCh: []*url.URL{mustURL("http://example.com/"), final},
	}
	v := analyzeRedirectChain("example.com", resp)
	if v.err == nil {
		t.Fatalf("expected error for final 5xx")
	}
}

func mustURL(s string) *url.URL {
	u, err := parseRedirectURL(s)
	if err != nil {
		panic(err)
	}
	return u
}
