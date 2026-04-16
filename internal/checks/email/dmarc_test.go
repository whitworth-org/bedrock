package email

import (
	"reflect"
	"testing"
)

func TestParseDMARC(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    *DMARC
		wantErr bool
	}{
		{
			name: "RFC 7489 example",
			raw:  "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com",
			want: &DMARC{
				Policy: "none", SubdomainPolicy: "none", Pct: 100, Adkim: "r", Aspf: "r",
				Rua: []string{"mailto:dmarc-feedback@example.com"},
			},
		},
		{
			name: "strict alignment + reject",
			raw:  "v=DMARC1; p=reject; sp=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:a@x.com,mailto:b@x.com; ruf=mailto:c@x.com",
			want: &DMARC{
				Policy: "reject", SubdomainPolicy: "quarantine", Pct: 100, Adkim: "s", Aspf: "s",
				Rua: []string{"mailto:a@x.com", "mailto:b@x.com"},
				Ruf: []string{"mailto:c@x.com"},
			},
		},
		{name: "missing v", raw: "p=reject", wantErr: true},
		{name: "missing p", raw: "v=DMARC1; rua=mailto:r@x.com", wantErr: true},
		{name: "invalid p", raw: "v=DMARC1; p=invalid", wantErr: true},
		{name: "invalid pct", raw: "v=DMARC1; p=none; pct=200", wantErr: true},
		{name: "invalid adkim", raw: "v=DMARC1; p=none; adkim=x", wantErr: true},
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
			if got.Pct != tc.want.Pct {
				t.Errorf("Pct = %d, want %d", got.Pct, tc.want.Pct)
			}
			if got.Adkim != tc.want.Adkim {
				t.Errorf("Adkim = %q, want %q", got.Adkim, tc.want.Adkim)
			}
			if got.Aspf != tc.want.Aspf {
				t.Errorf("Aspf = %q, want %q", got.Aspf, tc.want.Aspf)
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
