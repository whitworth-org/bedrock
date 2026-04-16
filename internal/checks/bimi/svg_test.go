package bimi

import (
	"strings"
	"testing"
)

const validSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 64 64">
  <title>Example</title>
  <rect x="0" y="0" width="64" height="64" fill="#0033aa"/>
  <circle cx="32" cy="32" r="20" fill="#ffffff"/>
</svg>`

const scriptSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 64 64">
  <script><![CDATA[ alert(1) ]]></script>
  <rect x="0" y="0" width="64" height="64"/>
</svg>`

const wrongAspectSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 100 50">
  <rect x="0" y="0" width="100" height="50"/>
</svg>`

const eventHandlerSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 64 64">
  <rect x="0" y="0" width="64" height="64" onclick="alert(1)"/>
</svg>`

const externalImageSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" viewBox="0 0 64 64">
  <image href="https://evil.example/logo.png" width="64" height="64"/>
</svg>`

const missingBaseProfileSVG = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect x="0" y="0" width="64" height="64"/>
</svg>`

const wrongRootSVG = `<?xml version="1.0" encoding="UTF-8"?>
<html><body>not an SVG</body></html>`

func TestValidateTinyPS_Valid(t *testing.T) {
	v := ValidateTinyPS([]byte(validSVG))
	if v.fatalError != "" {
		t.Errorf("unexpected fatal: %s", v.fatalError)
	}
	if len(v.profileFails) != 0 {
		t.Errorf("unexpected profile fails: %v", v.profileFails)
	}
}

func TestValidateTinyPS_RejectsScript(t *testing.T) {
	v := ValidateTinyPS([]byte(scriptSVG))
	if v.fatalError != "" {
		t.Fatalf("unexpected fatal: %s", v.fatalError)
	}
	found := false
	for _, p := range v.profileFails {
		if strings.Contains(p, "<script>") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected <script> to be flagged; got: %v", v.profileFails)
	}
}

func TestValidateTinyPS_RejectsEventHandler(t *testing.T) {
	v := ValidateTinyPS([]byte(eventHandlerSVG))
	if v.fatalError != "" {
		t.Fatalf("unexpected fatal: %s", v.fatalError)
	}
	found := false
	for _, p := range v.profileFails {
		if strings.Contains(p, "onclick") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected onclick to be flagged; got: %v", v.profileFails)
	}
}

func TestValidateTinyPS_RejectsExternalImage(t *testing.T) {
	v := ValidateTinyPS([]byte(externalImageSVG))
	if v.fatalError != "" {
		t.Fatalf("unexpected fatal: %s", v.fatalError)
	}
	// Two violations expected: <image> is disallowed, AND its href is external.
	disallowedHit := false
	hrefHit := false
	for _, p := range v.profileFails {
		if strings.Contains(p, "<image>") {
			disallowedHit = true
		}
		if strings.Contains(p, "external href") {
			hrefHit = true
		}
	}
	if !disallowedHit {
		t.Errorf("expected <image> to be flagged; got: %v", v.profileFails)
	}
	if !hrefHit {
		t.Errorf("expected external href to be flagged; got: %v", v.profileFails)
	}
}

func TestValidateTinyPS_RequiresBaseProfile(t *testing.T) {
	v := ValidateTinyPS([]byte(missingBaseProfileSVG))
	if v.fatalError != "" {
		t.Fatalf("unexpected fatal: %s", v.fatalError)
	}
	found := false
	for _, p := range v.profileFails {
		if strings.Contains(p, "baseProfile") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected baseProfile to be flagged; got: %v", v.profileFails)
	}
}

func TestValidateTinyPS_WrongRoot(t *testing.T) {
	v := ValidateTinyPS([]byte(wrongRootSVG))
	if v.fatalError == "" {
		t.Fatal("expected fatal error for non-SVG root")
	}
}

func TestExtractViewBox_Square(t *testing.T) {
	w, h, raw, err := extractViewBox([]byte(validSVG))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w != 64 || h != 64 {
		t.Errorf("got w=%v h=%v want 64,64 (raw=%q)", w, h, raw)
	}
}

func TestExtractViewBox_NonSquare(t *testing.T) {
	w, h, _, err := extractViewBox([]byte(wrongAspectSVG))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w == h {
		t.Errorf("expected non-square aspect, got %v:%v", w, h)
	}
}

func TestExtractViewBox_Missing(t *testing.T) {
	const noViewBox = `<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps"><rect/></svg>`
	_, _, _, err := extractViewBox([]byte(noViewBox))
	if err == nil {
		t.Fatal("expected error for missing viewBox")
	}
}

func TestIsExternalRef(t *testing.T) {
	cases := map[string]bool{
		"":                 false,
		"#frag":            false,
		"#":                false,
		"https://x/y":      true,
		"http://x":         true,
		"data:image/png;,": true,
		"/foo":             true,
		"foo.svg":          true,
	}
	for in, want := range cases {
		if got := isExternalRef(in); got != want {
			t.Errorf("isExternalRef(%q)=%v want %v", in, got, want)
		}
	}
}
