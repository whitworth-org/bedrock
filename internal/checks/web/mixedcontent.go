package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"bedrock/internal/probe"
	"bedrock/internal/report"
)

// mixedContentCheck does a lightweight scan of the HTTPS root body for
// http:// occurrences inside src= or href=. This is heuristic only — a real
// mixed-content audit needs a full DOM/CSS/JS evaluator. We Warn (never
// Fail) and cap at a handful of examples.
type mixedContentCheck struct{}

func (mixedContentCheck) ID() string       { return "web.mixedcontent" }
func (mixedContentCheck) Category() string { return category }

func (mixedContentCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	if !env.Active {
		return []report.Result{{
			ID: "web.mixedcontent", Category: category,
			Title:    "Mixed-content scan",
			Status:   report.NotApplicable,
			Evidence: "active probing disabled (--no-active)",
			RFCRefs:  []string{"W3C Mixed Content"},
		}}
	}
	resp := getHTTPSRoot(ctx, env)
	if resp == nil || len(resp.Body) == 0 {
		return []report.Result{{
			ID: "web.mixedcontent", Category: category,
			Title:    "Mixed-content scan",
			Status:   report.Info,
			Evidence: "no HTTPS root body to scan",
			RFCRefs:  []string{"W3C Mixed Content"},
		}}
	}
	hits := findMixedContent(string(resp.Body))
	if len(hits) == 0 {
		return []report.Result{{
			ID: "web.mixedcontent", Category: category,
			Title:    "Mixed-content scan",
			Status:   report.Pass,
			Evidence: "no http:// resources found in src= or href= attributes (heuristic, body capped at 1 MiB)",
			RFCRefs:  []string{"W3C Mixed Content"},
		}}
	}
	return []report.Result{{
		ID: "web.mixedcontent", Category: category,
		Title:    "Mixed-content scan",
		Status:   report.Warn,
		Evidence: fmt.Sprintf("%d possible http:// references (heuristic): %s", len(hits), strings.Join(hits, ", ")),
		RFCRefs:  []string{"W3C Mixed Content"},
	}}
}

// mixedContentSrcHref matches http:// inside src= or href= attribute values.
// Anchor-only links and well-known XML/RDF/XSL namespace URLs (which are
// identifiers, not loaded resources) are excluded by safeMixedContentURL.
var mixedContentSrcHref = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']?(http://[^"' >]+)`)

// safeMixedContentExclusions lists URL prefixes that are known to be
// identifier-only (XML namespaces, XSL stylesheets) rather than fetched
// resources. Suppressing them keeps the false-positive rate manageable on
// typical sites that include xmlns="http://www.w3.org/...".
var safeMixedContentExclusions = []string{
	"http://www.w3.org/",
	"http://purl.org/",
	"http://xmlns.com/",
	"http://schemas.openxmlformats.org/",
	"http://schema.org/", // schema.org allows http for its identifier vocab
	"http://ogp.me/",
}

func findMixedContent(body string) []string {
	matches := mixedContentSrcHref.FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		u := m[1]
		if isSafeMixedContentURL(u) {
			continue
		}
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func isSafeMixedContentURL(u string) bool {
	for _, p := range safeMixedContentExclusions {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}
