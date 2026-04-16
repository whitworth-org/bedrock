package web

import "testing"

func TestFindMixedContent(t *testing.T) {
	body := `<html>
  <head>
    <link rel="stylesheet" href="https://example.com/style.css">
    <link rel="alternate" href="http://insecure.example.com/feed.xml">
    <script src="http://cdn.example.com/lib.js"></script>
    <meta xmlns="http://www.w3.org/1999/xhtml">
    <a href="#anchor">anchor</a>
    <img src='http://insecure.example.com/img.png'>
    <img src="http://www.w3.org/identifier/foo.png">
  </head>
</html>`
	hits := findMixedContent(body)
	if len(hits) == 0 {
		t.Fatalf("expected mixed-content hits, got none")
	}
	// Must include the script and the link, must NOT include w3.org
	expected := map[string]bool{
		"http://insecure.example.com/feed.xml": false,
		"http://cdn.example.com/lib.js":        false,
		"http://insecure.example.com/img.png":  false,
	}
	for _, h := range hits {
		if _, ok := expected[h]; ok {
			expected[h] = true
		}
	}
	for u, found := range expected {
		if !found {
			t.Errorf("expected hit for %q, missing", u)
		}
	}
	for _, h := range hits {
		if isSafeMixedContentURL(h) {
			t.Errorf("safe URL %q leaked into hits", h)
		}
	}
}

func TestFindMixedContent_NoHits(t *testing.T) {
	body := `<a href="https://safe.example.com/">x</a><script src="https://cdn.example.com/lib.js"></script>`
	hits := findMixedContent(body)
	if len(hits) != 0 {
		t.Errorf("expected 0 hits, got %v", hits)
	}
}

func TestFindMixedContent_Cap(t *testing.T) {
	body := ""
	for i := 0; i < 20; i++ {
		body += `<img src="http://x.example.com/` + string(rune('a'+i)) + `.png">`
	}
	hits := findMixedContent(body)
	if len(hits) != 5 {
		t.Errorf("expected cap of 5 hits, got %d", len(hits))
	}
}
