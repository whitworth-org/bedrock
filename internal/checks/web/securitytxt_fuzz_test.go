package web

import (
	"testing"
	"time"
)

// FuzzParseSecurityTxt asserts the security.txt parser and field evaluator
// never panic on arbitrary input — response bodies are attacker-controlled.
func FuzzParseSecurityTxt(f *testing.F) {
	f.Add("Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n")
	f.Add(secTxtClearsigned)
	f.Add("# only comments\n\n")
	f.Add("\uFEFFCONTACT: tel:+1-201-555-0123\r\nExpires: 2027-01-01T00:00:00+02:00\r\n")
	f.Fuzz(func(t *testing.T, body string) {
		st, err := parseSecurityTxt(body)
		if err != nil {
			return
		}
		if st == nil {
			t.Fatal("nil securityTxt with nil error")
		}
		evaluateSecTxt(st, "https://fuzz.invalid/.well-known/security.txt",
			time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	})
}
