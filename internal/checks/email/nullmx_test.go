package email

import (
	"testing"

	"github.com/rwhitworth/bedrock/internal/probe"
)

func TestIsNullMX(t *testing.T) {
	cases := []struct {
		name string
		in   []probe.MX
		want bool
	}{
		{name: "RFC 7505 form", in: []probe.MX{{Preference: 0, Host: "."}}, want: true},
		{name: "RFC 7505 with empty host (trim-suffix output)", in: []probe.MX{{Preference: 0, Host: ""}}, want: true},
		{name: "real MX", in: []probe.MX{{Preference: 10, Host: "mail.example.com"}}, want: false},
		{name: "two records (cannot be null MX)", in: []probe.MX{{Preference: 0, Host: "."}, {Preference: 10, Host: "x"}}, want: false},
		{name: "empty", in: nil, want: false},
		{name: "wrong preference", in: []probe.MX{{Preference: 10, Host: "."}}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNullMX(tc.in); got != tc.want {
				t.Errorf("isNullMX(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
