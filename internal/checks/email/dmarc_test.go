package email

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

func TestParseDMARC(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    *DMARC
		wantErr bool
	}{
		{
			name: "RFC 9989 example",
			raw:  "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com",
			want: &DMARC{
				Policy: "none", SubdomainPolicy: "none", NPPolicy: "none", NPExplicit: false,
				Pct: 100, PctPresent: false, Adkim: "r", Aspf: "r", TestMode: "n", PSD: "u",
				Rua: []string{"mailto:dmarc-feedback@example.com"},
			},
		},
		{
			name: "strict alignment + reject",
			raw:  "v=DMARC1; p=reject; sp=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:a@x.com,mailto:b@x.com; ruf=mailto:c@x.com",
			want: &DMARC{
				Policy: "reject", SubdomainPolicy: "quarantine", NPPolicy: "quarantine", NPExplicit: false,
				Pct: 100, PctPresent: true, Adkim: "s", Aspf: "s", TestMode: "n", PSD: "u",
				Rua: []string{"mailto:a@x.com", "mailto:b@x.com"},
				Ruf: []string{"mailto:c@x.com"},
			},
		},
		{
			name: "np explicit reject overrides inherited sp",
			raw:  "v=DMARC1; p=quarantine; np=reject",
			want: &DMARC{
				Policy: "quarantine", SubdomainPolicy: "quarantine", NPPolicy: "reject", NPExplicit: true,
				Pct: 100, Adkim: "r", Aspf: "r", TestMode: "n", PSD: "u",
			},
		},
		{
			name: "np inherits sp",
			raw:  "v=DMARC1; p=reject; sp=quarantine",
			want: &DMARC{
				Policy: "reject", SubdomainPolicy: "quarantine", NPPolicy: "quarantine", NPExplicit: false,
				Pct: 100, Adkim: "r", Aspf: "r", TestMode: "n", PSD: "u",
			},
		},
		{
			name: "np inherits p via sp",
			raw:  "v=DMARC1; p=reject",
			want: &DMARC{
				Policy: "reject", SubdomainPolicy: "reject", NPPolicy: "reject", NPExplicit: false,
				Pct: 100, Adkim: "r", Aspf: "r", TestMode: "n", PSD: "u",
			},
		},
		{
			name: "test mode + psd + fo",
			raw:  "v=DMARC1; p=reject; t=y; psd=y; fo=1:d:s",
			want: &DMARC{
				Policy: "reject", SubdomainPolicy: "reject", NPPolicy: "reject", NPExplicit: false,
				Pct: 100, Adkim: "r", Aspf: "r", TestMode: "y", PSD: "y", Fo: "1:d:s",
			},
		},
		{
			name: "deprecated pct present",
			raw:  "v=DMARC1; p=reject; pct=50",
			want: &DMARC{
				Policy: "reject", SubdomainPolicy: "reject", NPPolicy: "reject", NPExplicit: false,
				Pct: 50, PctPresent: true, Adkim: "r", Aspf: "r", TestMode: "n", PSD: "u",
			},
		},
		{name: "missing v", raw: "p=reject", wantErr: true},
		{name: "missing p", raw: "v=DMARC1; rua=mailto:r@x.com", wantErr: true},
		{name: "invalid p", raw: "v=DMARC1; p=invalid", wantErr: true},
		{name: "invalid pct", raw: "v=DMARC1; p=none; pct=200", wantErr: true},
		{name: "invalid adkim", raw: "v=DMARC1; p=none; adkim=x", wantErr: true},
		{name: "invalid np", raw: "v=DMARC1; p=none; np=foo", wantErr: true},
		{name: "invalid psd", raw: "v=DMARC1; p=none; psd=x", wantErr: true},
		{name: "invalid t", raw: "v=DMARC1; p=none; t=maybe", wantErr: true},
		{name: "invalid fo", raw: "v=DMARC1; p=none; fo=9", wantErr: true},
		{name: "duplicate np", raw: "v=DMARC1; p=none; np=reject; np=none", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDMARC(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error; got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDMARC: %v", err)
			}
			if got.Policy != tc.want.Policy {
				t.Errorf("Policy = %q, want %q", got.Policy, tc.want.Policy)
			}
			if got.SubdomainPolicy != tc.want.SubdomainPolicy {
				t.Errorf("SubdomainPolicy = %q, want %q", got.SubdomainPolicy, tc.want.SubdomainPolicy)
			}
			if got.NPPolicy != tc.want.NPPolicy {
				t.Errorf("NPPolicy = %q, want %q", got.NPPolicy, tc.want.NPPolicy)
			}
			if got.NPExplicit != tc.want.NPExplicit {
				t.Errorf("NPExplicit = %v, want %v", got.NPExplicit, tc.want.NPExplicit)
			}
			if got.Pct != tc.want.Pct {
				t.Errorf("Pct = %d, want %d", got.Pct, tc.want.Pct)
			}
			if got.PctPresent != tc.want.PctPresent {
				t.Errorf("PctPresent = %v, want %v", got.PctPresent, tc.want.PctPresent)
			}
			if got.Adkim != tc.want.Adkim {
				t.Errorf("Adkim = %q, want %q", got.Adkim, tc.want.Adkim)
			}
			if got.Aspf != tc.want.Aspf {
				t.Errorf("Aspf = %q, want %q", got.Aspf, tc.want.Aspf)
			}
			if got.TestMode != tc.want.TestMode {
				t.Errorf("TestMode = %q, want %q", got.TestMode, tc.want.TestMode)
			}
			if got.PSD != tc.want.PSD {
				t.Errorf("PSD = %q, want %q", got.PSD, tc.want.PSD)
			}
			if got.Fo != tc.want.Fo {
				t.Errorf("Fo = %q, want %q", got.Fo, tc.want.Fo)
			}
			if !reflect.DeepEqual(got.Rua, tc.want.Rua) {
				t.Errorf("Rua = %v, want %v", got.Rua, tc.want.Rua)
			}
			if !reflect.DeepEqual(got.Ruf, tc.want.Ruf) {
				t.Errorf("Ruf = %v, want %v", got.Ruf, tc.want.Ruf)
			}
		})
	}
}

func TestRunDMARCNonExistentPolicy(t *testing.T) {
	const id = "email.dmarc.np"
	cases := []struct {
		name       string
		setup      func(env *probe.Env)
		wantStatus report.Status
		wantRemed  bool
	}{
		{
			// A nil sentinel short-circuits ensureDMARC's CacheGet so this stays
			// hermetic (no live lookup); the real NXDOMAIN path is covered by the
			// integration golden (testdata/golden/empty.json).
			name:       "no usable DMARC record",
			setup:      func(env *probe.Env) { env.CachePut(probe.CacheKeyDMARC, nil) },
			wantStatus: report.NotApplicable,
		},
		{
			name:       "unrecognized cache shape",
			setup:      func(env *probe.Env) { env.CachePut(probe.CacheKeyDMARC, "not a *DMARC") },
			wantStatus: report.Info,
		},
		{
			name: "np reject explicit",
			setup: func(env *probe.Env) {
				env.CachePut(probe.CacheKeyDMARC, &DMARC{Policy: "reject", SubdomainPolicy: "reject", NPPolicy: "reject", NPExplicit: true})
			},
			wantStatus: report.Pass,
		},
		{
			name: "np quarantine inherited",
			setup: func(env *probe.Env) {
				env.CachePut(probe.CacheKeyDMARC, &DMARC{Policy: "reject", SubdomainPolicy: "quarantine", NPPolicy: "quarantine"})
			},
			wantStatus: report.Warn,
			wantRemed:  true,
		},
		{
			name: "np none inherited",
			setup: func(env *probe.Env) {
				env.CachePut(probe.CacheKeyDMARC, &DMARC{Policy: "none", SubdomainPolicy: "none", NPPolicy: "none"})
			},
			wantStatus: report.Warn,
			wantRemed:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := probe.NewEnv("example.com", time.Second, false, "")
			tc.setup(env)
			res := runDMARCNonExistentPolicy(context.Background(), env)
			if len(res) != 1 {
				t.Fatalf("want 1 result, got %d", len(res))
			}
			r := res[0]
			if r.ID != id {
				t.Errorf("ID = %q, want %q", r.ID, id)
			}
			if r.Status != tc.wantStatus {
				t.Errorf("Status = %s, want %s (evidence=%q)", r.Status, tc.wantStatus, r.Evidence)
			}
			if tc.wantRemed && r.Remediation == "" {
				t.Errorf("expected remediation snippet, got empty")
			}
			if !tc.wantRemed && r.Remediation != "" {
				t.Errorf("unexpected remediation: %q", r.Remediation)
			}
		})
	}
}
