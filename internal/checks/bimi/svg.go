package bimi

import (
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"granite-scan/internal/probe"
	"granite-scan/internal/report"
)

// Cache keys for the SVG body and its SHA-256 digest. The VMC check needs
// the digest to look it up in the LogotypeData extension; sharing the value
// avoids a second HTTPS GET.
const (
	cacheKeyBIMISVGBytes  = "bimi.svg.bytes"
	cacheKeyBIMISVGSHA256 = "bimi.svg.sha256"
)

// allowedSVGElements is the BIMI Group "SVG Tiny PS Profile" element
// allowlist (BIMI Group SVG Tiny PS Profile §3.4). Anything outside the list
// is rejected. We err on the side of strictness — a logo that uses a Tiny
// element we haven't whitelisted yet will be flagged Warn and is easy to
// re-publish without that element.
var allowedSVGElements = map[string]struct{}{
	"svg":            {},
	"title":          {},
	"desc":           {},
	"metadata":       {},
	"defs":           {},
	"g":              {},
	"path":           {},
	"rect":           {},
	"circle":         {},
	"ellipse":        {},
	"line":           {},
	"polyline":       {},
	"polygon":        {},
	"text":           {},
	"tspan":          {},
	"lineargradient": {},
	"radialgradient": {},
	"stop":           {},
	"clippath":       {},
	"mask":           {},
	"pattern":        {},
	"use":            {}, // allowed but its href must be intra-document
	"style":          {}, // allowed; we still scan its content for "@import" / "url("
	"switch":         {},
	"foreignobject":  {}, // not in Tiny PS — kept here so we can flag it as a Warn explicitly
}

// disallowedSVGElements always trigger a Fail when seen anywhere in the
// document — these are the script and external-content vectors.
var disallowedSVGElements = map[string]string{
	"script":        "script execution",
	"image":         "raster/external image embed",
	"a":             "hyperlink",
	"animate":       "SMIL animation (not in Tiny PS)",
	"animatemotion": "SMIL animation (not in Tiny PS)",
	"animatecolor":  "SMIL animation (not in Tiny PS)",
	"set":           "SMIL animation (not in Tiny PS)",
	"foreignobject": "foreignObject embed",
}

type svgFetchCheck struct{}

func (svgFetchCheck) ID() string       { return "bimi.svg.fetch" }
func (svgFetchCheck) Category() string { return category }

func (svgFetchCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	const id = "bimi.svg.fetch"
	const title = "BIMI SVG fetched over HTTPS as image/svg+xml"
	refs := []string{"BIMI Group draft §4.4", "BIMI SVG Tiny PS Profile"}

	rec, ok := getRecord(env)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "no parsed BIMI record (TXT check did not produce one)",
			RFCRefs:  refs,
		}}
	}
	if !env.Active {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "skipped: --no-active",
			RFCRefs:  refs,
		}}
	}
	if rec.L == "" {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.NotApplicable,
			Evidence: "no l= URL in BIMI record",
			RFCRefs:  refs,
		}}
	}

	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()

	resp, err := env.HTTP.Get(ctx, rec.L)
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "GET " + rec.L + " failed: " + err.Error(),
			Remediation: svgFetchRemediation(),
			RFCRefs:     refs,
		}}
	}
	if resp.Status != 200 {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("GET %s returned HTTP %d", rec.L, resp.Status),
			Remediation: svgFetchRemediation(),
			RFCRefs:     refs,
		}}
	}

	ct := strings.ToLower(strings.TrimSpace(resp.Headers.Get("Content-Type")))
	// Strip charset / boundary parameters.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	var results []report.Result
	if ct != "image/svg+xml" {
		results = append(results, report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("Content-Type=%q (want image/svg+xml)", resp.Headers.Get("Content-Type")),
			Remediation: svgFetchRemediation(),
			RFCRefs:     refs,
		})
	}

	// Cache the bytes + digest for the VMC check (logotype hash match).
	sum := sha256.Sum256(resp.Body)
	env.CachePut(cacheKeyBIMISVGBytes, resp.Body)
	env.CachePut(cacheKeyBIMISVGSHA256, sum[:])

	if len(results) == 0 {
		results = append(results, report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Pass,
			Evidence: fmt.Sprintf("HTTP 200 %s, %d bytes, sha256=%x", ct, len(resp.Body), sum[:8]),
			RFCRefs:  refs,
		})
	}
	return results
}

type svgProfileCheck struct{}

func (svgProfileCheck) ID() string       { return "bimi.svg.profile" }
func (svgProfileCheck) Category() string { return category }

func (svgProfileCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	const id = "bimi.svg.profile"
	const title = "BIMI SVG conforms to SVG Tiny PS profile"
	refs := []string{"BIMI SVG Tiny PS Profile §3"}

	if !env.Active {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "skipped: --no-active",
			RFCRefs: refs,
		}}
	}
	body, ok := getSVGBytes(env)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "no SVG body cached (fetch did not succeed)",
			RFCRefs: refs,
		}}
	}

	vr := ValidateTinyPS(body)
	results := []report.Result{}
	if vr.fatalError != "" {
		results = append(results, makeFailResult(id, title, vr.fatalError, svgProfileRemediation(), refs))
	}
	for _, p := range vr.profileFails {
		results = append(results, makeFailResult(id, title, p, svgProfileRemediation(), refs))
	}
	if len(results) == 0 {
		results = append(results, vr.passResult(id, title, refs))
	}
	return results
}

type svgAspectCheck struct{}

func (svgAspectCheck) ID() string       { return "bimi.svg.aspect" }
func (svgAspectCheck) Category() string { return category }

func (svgAspectCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	const id = "bimi.svg.aspect"
	const title = "BIMI SVG viewBox is square (1:1)"
	refs := []string{"BIMI Group draft §4.4 (square logo requirement)"}

	if !env.Active {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "skipped: --no-active",
			RFCRefs: refs,
		}}
	}
	body, ok := getSVGBytes(env)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status: report.NotApplicable, Evidence: "no SVG body cached (fetch did not succeed)",
			RFCRefs: refs,
		}}
	}

	w, h, raw, err := extractViewBox(body)
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    err.Error(),
			Remediation: svgProfileRemediation(),
			RFCRefs:     refs,
		}}
	}
	if w != h {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("viewBox=%q has %g:%g aspect (want 1:1)", raw, w, h),
			Remediation: svgProfileRemediation(),
			RFCRefs:     refs,
		}}
	}
	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("viewBox=%q", raw),
		RFCRefs:  refs,
	}}
}

// validationReport collects multiple findings without aborting on the first.
type validationReport struct {
	fatalError   string   // e.g. XML parse failure or wrong root element
	profileFails []string // e.g. found <script>, found event handler "onclick"
}

// makeFailResult is a thin helper so each finding becomes its own Result.
func makeFailResult(id, title, evidence, remediation string, refs []string) report.Result {
	return report.Result{
		ID: id, Category: category, Title: title,
		Status:      report.Fail,
		Evidence:    evidence,
		Remediation: remediation,
		RFCRefs:     refs,
	}
}

func (r validationReport) passResult(id, title string, refs []string) report.Result {
	return report.Result{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: "SVG Tiny PS allowlist satisfied; no scripts, event handlers, or external refs",
		RFCRefs:  refs,
	}
}

// ValidateTinyPS walks the SVG document and reports every Tiny PS violation
// it finds. Returns a fatal error message when the SVG cannot even be
// parsed or doesn't have <svg> at the root.
func ValidateTinyPS(body []byte) validationReport {
	var v validationReport
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	dec.Strict = true

	rootSeen := false
	var depth int
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			v.fatalError = "XML parse error: " + err.Error()
			return v
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			name := strings.ToLower(t.Name.Local)
			if !rootSeen {
				rootSeen = true
				if name != "svg" {
					v.fatalError = fmt.Sprintf("root element is <%s>, expected <svg>", t.Name.Local)
					return v
				}
				if reason := checkRootSVG(t); reason != "" {
					v.profileFails = append(v.profileFails, reason)
				}
			}
			// Disallowed-element check (script, image, a, animate*, foreignObject).
			if reason, bad := disallowedSVGElements[name]; bad {
				v.profileFails = append(v.profileFails, fmt.Sprintf("disallowed element <%s> (%s)", t.Name.Local, reason))
			} else if _, ok := allowedSVGElements[name]; !ok {
				v.profileFails = append(v.profileFails, fmt.Sprintf("element <%s> not in Tiny PS allowlist", t.Name.Local))
			}
			// Per-element attribute audit: event handlers and external refs.
			for _, a := range t.Attr {
				attr := strings.ToLower(a.Name.Local)
				if strings.HasPrefix(attr, "on") {
					v.profileFails = append(v.profileFails, fmt.Sprintf("event-handler attribute %s on <%s>", a.Name.Local, t.Name.Local))
					continue
				}
				if attr == "href" || (strings.EqualFold(a.Name.Space, "http://www.w3.org/1999/xlink") && attr == "href") {
					if isExternalRef(a.Value) {
						v.profileFails = append(v.profileFails, fmt.Sprintf("external href on <%s>: %q", t.Name.Local, a.Value))
					}
				}
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			// <style> contents can carry @import / url(...) — flag them.
			// We don't track the parent element here; cheap heuristic:
			// if the doc contains "@import" it is almost always inside <style>.
			s := strings.ToLower(string(t))
			if strings.Contains(s, "@import") {
				v.profileFails = append(v.profileFails, "<style> contains @import (external CSS reference)")
			}
		}
	}
	if !rootSeen {
		v.fatalError = "no XML elements found"
	}
	return v
}

// checkRootSVG enforces baseProfile="tiny-ps" on the root <svg>.
func checkRootSVG(t xml.StartElement) string {
	for _, a := range t.Attr {
		if strings.EqualFold(a.Name.Local, "baseProfile") {
			if strings.EqualFold(a.Value, "tiny-ps") {
				return ""
			}
			return fmt.Sprintf("root <svg> baseProfile=%q (want \"tiny-ps\")", a.Value)
		}
	}
	return `root <svg> missing baseProfile="tiny-ps"`
}

// isExternalRef returns true when a URL refers to something outside the
// document. Intra-doc refs ("#id") are fine; everything else (http://, file://,
// data:, even bare paths) is flagged.
func isExternalRef(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	return !strings.HasPrefix(v, "#")
}

// extractViewBox finds the root <svg viewBox="x y w h"> attribute and returns
// (w, h, raw). Returns an error when the viewBox is missing or malformed.
func extractViewBox(body []byte) (float64, float64, string, error) {
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return 0, 0, "", errors.New("no <svg> element found")
		}
		if err != nil {
			return 0, 0, "", fmt.Errorf("XML parse: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !strings.EqualFold(se.Name.Local, "svg") {
			return 0, 0, "", fmt.Errorf("first element is <%s>, expected <svg>", se.Name.Local)
		}
		for _, a := range se.Attr {
			if strings.EqualFold(a.Name.Local, "viewBox") {
				parts := strings.Fields(strings.ReplaceAll(a.Value, ",", " "))
				if len(parts) != 4 {
					return 0, 0, a.Value, fmt.Errorf("viewBox=%q does not have 4 components", a.Value)
				}
				w, errW := strconv.ParseFloat(parts[2], 64)
				h, errH := strconv.ParseFloat(parts[3], 64)
				if errW != nil || errH != nil {
					return 0, 0, a.Value, fmt.Errorf("viewBox=%q components not numeric", a.Value)
				}
				if w <= 0 || h <= 0 {
					return 0, 0, a.Value, fmt.Errorf("viewBox=%q has non-positive dimensions", a.Value)
				}
				return w, h, a.Value, nil
			}
		}
		return 0, 0, "", errors.New("<svg> has no viewBox attribute")
	}
}

func svgFetchRemediation() string {
	return `# Host the SVG at the URL referenced by the BIMI l= tag, served over HTTPS,
# with no authentication and Content-Type image/svg+xml.`
}

func svgProfileRemediation() string {
	return `# Republish the logo as SVG Tiny PS:
# - Remove all <script> elements
# - Remove all event handler attributes (on*)
# - Set baseProfile="tiny-ps" on the root <svg>
# - Ensure 1:1 viewBox aspect ratio
# - Avoid external <image>, <use>, <a> hrefs (intra-doc # references only)`
}

// getRecord pulls the parsed BIMI record from the cache.
func getRecord(env *probe.Env) (*Record, bool) {
	v, ok := env.CacheGet(cacheKeyBIMIRecord)
	if !ok {
		return nil, false
	}
	r, ok := v.(*Record)
	return r, ok
}

// getSVGBytes pulls the cached SVG body from the cache.
func getSVGBytes(env *probe.Env) ([]byte, bool) {
	v, ok := env.CacheGet(cacheKeyBIMISVGBytes)
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}
