package web

import (
	"strings"
	"testing"

	"bedrock/internal/report"
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
// category — registry.Register is called via init(), and the check's
// Category() must match the package's `category` constant.
func TestHTTP2CheckRegistered(t *testing.T) {
	c := http2Check{}
	if c.ID() != "web.http2" {
		t.Errorf("ID() = %q, want %q", c.ID(), "web.http2")
	}
	if c.Category() != category {
		t.Errorf("Category() = %q, want %q", c.Category(), category)
	}
}
