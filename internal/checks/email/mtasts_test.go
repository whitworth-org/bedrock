package email

import "testing"

func TestParseSTSPolicy(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
		mode    string
		maxAge  int
		mxLen   int
	}{
		{
			name:   "RFC 8461 example",
			body:   "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmax_age: 604800\n",
			mode:   "enforce",
			maxAge: 604800,
			mxLen:  2,
		},
		{
			name:   "CRLF line endings",
			body:   "version: STSv1\r\nmode: testing\r\nmx: mx.example.org\r\nmax_age: 86400\r\n",
			mode:   "testing",
			maxAge: 86400,
			mxLen:  1,
		},
		{name: "missing version", body: "mode: enforce\nmx: x\nmax_age: 1", wantErr: true},
		{name: "bad mode", body: "version: STSv1\nmode: yes\nmax_age: 1", wantErr: true},
		{name: "bad max_age", body: "version: STSv1\nmode: enforce\nmax_age: forever", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSTSPolicy(tc.body)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error; got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSTSPolicy: %v", err)
			}
			if got.Mode != tc.mode {
				t.Errorf("Mode = %q, want %q", got.Mode, tc.mode)
			}
			if got.MaxAge != tc.maxAge {
				t.Errorf("MaxAge = %d, want %d", got.MaxAge, tc.maxAge)
			}
			if len(got.MX) != tc.mxLen {
				t.Errorf("len(MX) = %d, want %d", len(got.MX), tc.mxLen)
			}
		})
	}
}

func TestExtractSTSID(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`v=STSv1; id=20160831085700Z;`, "20160831085700Z"},
		{`v=STSv1`, ""},
		{`v=STSv1; foo=bar`, ""},
		{`v=STSv1; ID=ABC`, "ABC"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			if got := extractSTSID(tc.raw); got != tc.want {
				t.Errorf("extractSTSID(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}
