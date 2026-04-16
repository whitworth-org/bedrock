package web

import "testing"

func TestParseHSTS(t *testing.T) {
	cases := []struct {
		raw  string
		want hstsParsed
	}{
		{
			raw:  "max-age=31536000; includeSubDomains; preload",
			want: hstsParsed{hasMaxAge: true, maxAge: 31536000, includeSubDomains: true, preload: true},
		},
		{
			raw:  "max-age=15552000",
			want: hstsParsed{hasMaxAge: true, maxAge: 15552000},
		},
		{
			// case-insensitive directive names (RFC 6797 §6.1)
			raw:  "MAX-AGE=600 ; INCLUDESUBDOMAINS",
			want: hstsParsed{hasMaxAge: true, maxAge: 600, includeSubDomains: true},
		},
		{
			raw:  "preload",
			want: hstsParsed{preload: true},
		},
		{
			// max-age value can be quoted
			raw:  `max-age="63072000"; includeSubDomains`,
			want: hstsParsed{hasMaxAge: true, maxAge: 63072000, includeSubDomains: true},
		},
		{
			// negative max-age is invalid
			raw:  "max-age=-1",
			want: hstsParsed{},
		},
	}
	for _, tc := range cases {
		got := parseHSTS(tc.raw)
		if got != tc.want {
			t.Errorf("parseHSTS(%q) = %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}
