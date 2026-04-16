package email

import "testing"

func TestParseDKIM(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
		wantP   string
		wantK   string
	}{
		{
			name:  "minimal RFC 6376 §3.6.1 example",
			raw:   "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ",
			wantP: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ", wantK: "rsa",
		},
		{
			name:  "with k tag",
			raw:   "v=DKIM1; k=rsa; p=ABC==",
			wantP: "ABC==", wantK: "rsa",
		},
		{
			name:  "revoked key (empty p)",
			raw:   "v=DKIM1; p=",
			wantP: "", wantK: "rsa",
		},
		{
			name:  "extra spaces",
			raw:   "v=DKIM1 ; k = rsa ; p = ABC ",
			wantP: "ABC", wantK: "rsa",
		},
		{
			name:    "wrong version",
			raw:     "v=DKIM2; p=ABC",
			wantErr: true,
		},
		{
			name:    "malformed tag",
			raw:     "v=DKIM1; foo",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDKIM(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error; got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDKIM: %v", err)
			}
			if got.P != tc.wantP {
				t.Errorf("P = %q, want %q", got.P, tc.wantP)
			}
			if got.KeyType != tc.wantK {
				t.Errorf("KeyType = %q, want %q", got.KeyType, tc.wantK)
			}
		})
	}
}
