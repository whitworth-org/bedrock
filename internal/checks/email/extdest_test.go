package email

import (
	"reflect"
	"testing"
)

func TestDestHost(t *testing.T) {
	cases := []struct {
		uri, want string
	}{
		{"mailto:agg@monitor.example", "monitor.example"},
		{"mailto:agg@monitor.example!10m", "monitor.example"},
		{"MAILTO:Agg@Monitor.EXAMPLE", "monitor.example"},
		{"https://monitor.example/dmarc", "monitor.example"},
		{"https://monitor.example:8443/dmarc?x=1", "monitor.example"},
		{"https://monitor.example", "monitor.example"},
		{"mailto:no-at-sign", ""},
		{"mailto:trailing@", ""},
		{"ftp://monitor.example", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := destHost(tc.uri); got != tc.want {
			t.Errorf("destHost(%q) = %q, want %q", tc.uri, got, tc.want)
		}
	}
}

func TestReportDestHosts(t *testing.T) {
	p := &DMARC{
		Rua: []string{"mailto:a@one.example", "mailto:b@two.example", "mailto:c@one.example"},
		Ruf: []string{"mailto:d@two.example", "https://three.example/report"},
	}
	want := []string{"one.example", "two.example", "three.example"}
	if got := reportDestHosts(p); !reflect.DeepEqual(got, want) {
		t.Errorf("reportDestHosts = %v, want %v", got, want)
	}
	if got := reportDestHosts(&DMARC{}); got != nil {
		t.Errorf("reportDestHosts(empty) = %v, want nil", got)
	}
}

func TestIsInternalDest(t *testing.T) {
	cases := []struct {
		host, org string
		want      bool
	}{
		{"example.com", "example.com", true},
		{"dmarc.example.com", "example.com", true},
		{"badexample.com", "example.com", false},
		{"monitor.example", "example.com", false},
	}
	for _, tc := range cases {
		if got := isInternalDest(tc.host, tc.org); got != tc.want {
			t.Errorf("isInternalDest(%q, %q) = %v, want %v", tc.host, tc.org, got, tc.want)
		}
	}
}
