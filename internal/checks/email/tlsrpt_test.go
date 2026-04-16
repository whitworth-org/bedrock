package email

import (
	"reflect"
	"testing"
)

func TestParseTLSRPT(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{
			name: "RFC 8460 §3.1.1 mailto",
			raw:  "v=TLSRPTv1;rua=mailto:reports@example.com",
			want: []string{"mailto:reports@example.com"},
		},
		{
			name: "RFC 8460 §3.1.2 https",
			raw:  "v=TLSRPTv1; rua=https://reporting.example.com/v1/tlsrpt",
			want: []string{"https://reporting.example.com/v1/tlsrpt"},
		},
		{
			name: "multiple endpoints",
			raw:  "v=TLSRPTv1; rua=mailto:a@example.com,mailto:b@example.com",
			want: []string{"mailto:a@example.com", "mailto:b@example.com"},
		},
		{name: "missing rua", raw: "v=TLSRPTv1", wantErr: true},
		{name: "wrong version", raw: "v=TLSRPTv2; rua=mailto:r@x", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTLSRPT(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error; got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTLSRPT: %v", err)
			}
			if !reflect.DeepEqual(got.Rua, tc.want) {
				t.Errorf("Rua = %v, want %v", got.Rua, tc.want)
			}
		})
	}
}
