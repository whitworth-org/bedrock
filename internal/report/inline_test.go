package report

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// longName is a 253-octet DNS name, the longest RFC 1035 allows.
var longName = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
	strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)

func TestInlineValue(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"plain name", "mail.example.com", "mail.example.com"},
		{"LF", "a\nb", "a�b"},
		{"CR", "a\rb", "a�b"},
		{"CRLF", "a\r\nb", "a��b"},
		{"ESC", "\x1b[31mred", "�[31mred"},
		{"leading TAB", "\tevil.example", "�evil.example"},
		{"NUL and DEL", "a\x00b\x7fc", "a�b�c"},
		{"C1 NEL and CSI", "a\u0085b\u009bc", "a�b�c"},
		{"multibyte kept", "bücher.example→★", "bücher.example→★"},
		{"253-octet name kept whole", longName, longName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InlineValue(tt.in); got != tt.want {
				t.Fatalf("InlineValue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestClipValue(t *testing.T) {
	sixtyFour := strings.Repeat("é", 64)
	tests := []struct {
		name, in, want string
	}{
		{"short value unchanged", "sid", "sid"},
		{"64 runes unchanged", sixtyFour, sixtyFour},
		{"65 runes clipped at 64", sixtyFour + "x", sixtyFour + "…"},
		{"controls replaced before the cut", "a\nb", "a�b"},
		{"controls replaced in a clipped value", strings.Repeat("\x01", 100),
			strings.Repeat("�", 64) + "…"},
		{"1 MiB clipped", strings.Repeat("x", 1<<20), strings.Repeat("x", 64) + "…"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClipValue(tt.in); got != tt.want {
				t.Fatalf("ClipValue(%.80q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCheckRemediation(t *testing.T) {
	accepted := []string{
		"",
		"X-Frame-Options: SAMEORIGIN",
		"; comment\nexample.com. IN NS ns1.example.com.\nexample.com. IN NS ns2.example.com.",
		"bücher.example. IN TXT \"v=spf1 -all\"",
	}
	for _, s := range accepted {
		if err := CheckRemediation(s); err != nil {
			t.Errorf("CheckRemediation(%q) = %v, want nil", s, err)
		}
	}
	rejected := map[string]string{
		"CR":  "line one\r\nline two",
		"ESC": "example.com\x1b[2J",
		"NUL": "example.com\x00",
		"TAB": "\texample.com. IN A 192.0.2.1",
		"DEL": "example.com\x7f",
		"C1":  "example.com\u0085",
	}
	for name, s := range rejected {
		if err := CheckRemediation(s); err == nil {
			t.Errorf("%s: CheckRemediation(%q) = nil, want an error", name, s)
		}
	}
}

func TestCheckUniqueIDs(t *testing.T) {
	unique := []Result{{ID: "web.cookies"}, {ID: "web.hsts"}, {ID: "dns.zone.soa"}}
	if err := CheckUniqueIDs(unique); err != nil {
		t.Fatalf("CheckUniqueIDs(unique) = %v, want nil", err)
	}
	if err := CheckUniqueIDs(nil); err != nil {
		t.Fatalf("CheckUniqueIDs(nil) = %v, want nil", err)
	}
	repeated := []Result{
		{ID: "web.cookie.sid"}, {ID: "web.hsts"}, {ID: "web.cookie.sid"},
		{ID: "web.cookie.a_b"}, {ID: "web.cookie.a_b"}, {ID: "web.cookie.sid"},
	}
	err := CheckUniqueIDs(repeated)
	if err == nil {
		t.Fatal("CheckUniqueIDs(repeated) = nil, want an error")
	}
	for _, want := range []string{`"web.cookie.sid" (3 results)`, `"web.cookie.a_b" (2 results)`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	if strings.Contains(err.Error(), "web.hsts") {
		t.Errorf("error %q names an ID that is not repeated", err)
	}
}

// FuzzInlineValue checks the properties remediation builders rely on: the
// output passes CheckRemediation, has no line break, and keeps one rune per
// input rune; ClipValue never returns more than 64 runes plus the ellipsis.
func FuzzInlineValue(f *testing.F) {
	seeds := []string{"", "example.com", "a\r\nb", "\tx", "\x1b[2J", "\u0085", "\xff\xfe"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := InlineValue(s)
		if err := CheckRemediation(got); err != nil {
			t.Fatalf("InlineValue(%q) = %q fails CheckRemediation: %v", s, got, err)
		}
		if strings.Contains(got, "\n") {
			t.Fatalf("InlineValue(%q) = %q contains LF", s, got)
		}
		if utf8.RuneCountInString(got) != utf8.RuneCountInString(s) {
			t.Fatalf("InlineValue(%q) = %q changed the rune count", s, got)
		}
		clipped := ClipValue(s)
		if n := utf8.RuneCountInString(clipped); n > clipRunes+1 {
			t.Fatalf("ClipValue(%q) has %d runes, want at most %d", s, n, clipRunes+1)
		}
		if utf8.RuneCountInString(s) <= clipRunes && clipped != got {
			t.Fatalf("ClipValue(%q) = %q, want InlineValue's %q for a short value", s, clipped, got)
		}
	})
}
