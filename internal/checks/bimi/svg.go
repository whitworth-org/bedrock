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

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// Cache keys for the SVG body and its SHA-256 digest. The VMC check needs
// the digest to look it up in the LogotypeData extension; sharing the value
// avoids a second HTTPS GET.
const (
	cacheKeyBIMISVGBytes  = "bimi.svg.bytes"
	cacheKeyBIMISVGSHA256 = "bimi.svg.sha256"
)

// Resource-exhaustion guards for SVG parsing. A legitimate BIMI logo is
// small (a few KB) and simple (a few hundred tokens, shallow nesting). These
// caps ensure the validator is bounded regardless of what a remote operator
// publishes.
const (
	// maxSVGBytes is the largest body we will accept before giving up on
	// validation. BIMI Group does not normatively pin a byte limit but
	// mailbox providers in practice reject logos over ~32 KB; 1 MiB is a
	// comfortable upper bound that still fences off malicious fetches.
	maxSVGBytes = 1 << 20 // 1 MiB

	// maxSVGTokens caps how many XML tokens we are willing to walk. Chosen
	// high enough for any plausibly-complex logo but low enough that a
	// pathological document cannot pin the parser.
	maxSVGTokens = 4096

	// maxSVGDepth bounds nesting depth. SVG Tiny PS logos are shallow in
	// practice; 32 is generous.
	maxSVGDepth = 32
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
	// Return early on Content-Type mismatch without caching anything — if
	// the server is serving the wrong media type we do NOT want downstream
	// profile/aspect/logotype checks to run over what might be HTML or
	// arbitrary bytes. Downstream checks keying off the cache will correctly
	// degrade to N/A.
	if ct != "image/svg+xml" {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("Content-Type=%q (want image/svg+xml)", resp.Headers.Get("Content-Type")),
			Remediation: svgFetchRemediation(),
			RFCRefs:     refs,
		}}
	}

	// Oversize body guard — 1 MiB is already ~30× any plausible BIMI logo.
	// We refuse to cache or validate past this point so the parser is not
	// fed an arbitrarily large buffer.
	if len(resp.Body) > maxSVGBytes {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    fmt.Sprintf("SVG body %d bytes exceeds cap %d", len(resp.Body), maxSVGBytes),
			Remediation: svgFetchRemediation(),
			RFCRefs:     refs,
		}}
	}

	// Cache the bytes + digest for the VMC check (logotype hash match).
	sum := sha256.Sum256(resp.Body)
	env.CachePut(cacheKeyBIMISVGBytes, resp.Body)
	env.CachePut(cacheKeyBIMISVGSHA256, sum[:])

	return []report.Result{{
		ID: id, Category: category, Title: title,
		Status:   report.Pass,
		Evidence: fmt.Sprintf("HTTP 200 %s, %d bytes, sha256=%x", ct, len(resp.Body), sum[:8]),
		RFCRefs:  refs,
	}}
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

// urlBearingAttrs lists the attributes whose values may carry a URL. Beyond
// plain href, SVG paints and filter references can also smuggle external
// resources via url(…) (e.g. fill="url(http://evil/x)"); BIMI Tiny PS forbids
// external fetches, so every one of these is scanned for dangerous schemes.
var urlBearingAttrs = map[string]struct{}{
	"href":      {},
	"fill":      {},
	"stroke":    {},
	"filter":    {},
	"mask":      {},
	"clip-path": {},
	"style":     {},
	"begin":     {},
}

// dangerousAttrValueSubstrings is the set of case-insensitive substrings we
// reject anywhere inside a url-bearing attribute value. `url(` catches CSS
// external resource references; the scheme tokens catch the classic
// script/data/file exfiltration vectors. `http:` / `https:` are here because
// the Tiny PS profile mandates that any URL reference inside the SVG be an
// intra-document fragment (`#id`) — absolute references are never valid.
var dangerousAttrValueSubstrings = []string{
	"url(",
	"@import",
	"javascript:",
	"data:",
	"file:",
	"vbscript:",
	"http:",
	"https:",
}

// ValidateTinyPS walks the SVG document and reports every Tiny PS violation
// it finds. Returns a fatal error message when the SVG cannot even be
// parsed, exceeds a resource cap, or doesn't have <svg> at the root.
//
// The parser fails closed on:
//   - xml.Directive   — DOCTYPE/ENTITY/NOTATION (billion-laughs, DTD injection)
//   - xml.ProcInst    — processing instructions other than the initial
//     <?xml ...?> prolog (Go's decoder does NOT surface that one)
//   - more than maxSVGTokens tokens or more than maxSVGDepth nesting
func ValidateTinyPS(body []byte) validationReport {
	var v validationReport
	// Resource caps: refuse oversized bodies before we even spin the decoder.
	if len(body) > maxSVGBytes {
		v.fatalError = fmt.Sprintf("SVG body %d bytes exceeds cap %d", len(body), maxSVGBytes)
		return v
	}
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	dec.Strict = true

	rootSeen := false
	var depth, tokenCount int
	// Accumulate every chunk of CharData between <style> open/close into a
	// single buffer. The XML decoder can hand us style text in multiple
	// pieces (CDATA splits, whitespace chunks); scanning each chunk alone
	// misses cross-chunk `@import` / `url(` smuggling. We keep a stack of
	// open-element names to know when we are inside <style>.
	var elemStack []string
	var styleBuf strings.Builder
	inStyle := false

	for {
		tokenCount++
		if tokenCount > maxSVGTokens {
			v.fatalError = fmt.Sprintf("SVG exceeds token cap %d", maxSVGTokens)
			return v
		}
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			v.fatalError = "XML parse error: " + err.Error()
			return v
		}
		switch t := tok.(type) {
		case xml.Directive:
			// DOCTYPE / ENTITY declarations are the billion-laughs and DTD
			// injection vectors. BIMI Tiny PS has no legitimate use for them;
			// reject as a profile failure rather than aborting, so the
			// operator sees the full list of issues.
			v.profileFails = append(v.profileFails, "XML directive (DOCTYPE/ENTITY) is not allowed in SVG Tiny PS")
		case xml.ProcInst:
			// Processing instructions are rejected, with one exception: the
			// XML declaration <?xml version="…"?>. Go's decoder surfaces
			// the XML prolog as a ProcInst with target "xml", so we allow
			// exactly that target and flag anything else.
			if strings.EqualFold(t.Target, "xml") {
				break
			}
			v.profileFails = append(v.profileFails, fmt.Sprintf("XML processing instruction <?%s ...?> is not allowed", t.Target))
		case xml.StartElement:
			depth++
			if depth > maxSVGDepth {
				v.fatalError = fmt.Sprintf("SVG exceeds depth cap %d", maxSVGDepth)
				return v
			}
			name := strings.ToLower(t.Name.Local)
			elemStack = append(elemStack, name)
			if name == "style" {
				inStyle = true
				styleBuf.Reset()
			}
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
			// Per-element attribute audit.
			for _, a := range t.Attr {
				attr := strings.ToLower(a.Name.Local)
				if strings.HasPrefix(attr, "on") {
					v.profileFails = append(v.profileFails, fmt.Sprintf("event-handler attribute %s on <%s>", a.Name.Local, t.Name.Local))
					continue
				}
				// href / xlink:href / any *:href variant — classic external ref vector.
				isHrefLike := attr == "href" ||
					(strings.EqualFold(a.Name.Space, "http://www.w3.org/1999/xlink") && attr == "href")
				if isHrefLike {
					if isExternalRef(a.Value) {
						v.profileFails = append(v.profileFails, fmt.Sprintf("external href on <%s>: %q", t.Name.Local, a.Value))
					}
				}
				// URL-bearing attributes (fill, stroke, filter, mask, clip-path,
				// style, begin, any href-like) get their value scanned for
				// the dangerous-substring list. This catches fill="url(http://…)"
				// or style="background:url(data:…)" payloads.
				if _, urlBearing := urlBearingAttrs[attr]; urlBearing || isHrefLike {
					if reason := scanDangerousAttrValue(a.Value); reason != "" {
						v.profileFails = append(v.profileFails,
							fmt.Sprintf("attribute %s on <%s> contains %s: %q",
								a.Name.Local, t.Name.Local, reason, a.Value))
					}
				}
			}
		case xml.EndElement:
			depth--
			if len(elemStack) > 0 {
				top := elemStack[len(elemStack)-1]
				elemStack = elemStack[:len(elemStack)-1]
				if top == "style" && inStyle {
					// End of <style>: run the accumulated buffer through
					// the same dangerous-substring scanner so chunk-split
					// payloads cannot hide. styleBuf is already lower-cased.
					if reason := scanDangerousStyleBody(styleBuf.String()); reason != "" {
						v.profileFails = append(v.profileFails, fmt.Sprintf("<style> contains %s", reason))
					}
					styleBuf.Reset()
					inStyle = false
				}
			}
		case xml.CharData:
			if inStyle {
				// Lower-case once as we go so the final scan is cheap.
				styleBuf.WriteString(strings.ToLower(string(t)))
			}
		}
	}
	if !rootSeen {
		v.fatalError = "no XML elements found"
	}
	return v
}

// scanDangerousAttrValue returns a short description of the first
// dangerous substring found in an attribute value, or "" when the value is
// clean. Self-fragment references (#id) are explicitly permitted and skip
// the scan. Comparison is case-insensitive.
func scanDangerousAttrValue(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	// Intra-document fragment references are allowed.
	if strings.HasPrefix(v, "#") {
		return ""
	}
	lower := strings.ToLower(v)
	for _, sub := range dangerousAttrValueSubstrings {
		if strings.Contains(lower, sub) {
			return "dangerous token " + sub
		}
	}
	return ""
}

// scanDangerousStyleBody returns a short description of the first dangerous
// token in accumulated <style> CharData, or "" when clean. The body is
// already lower-cased by the caller. We also catch CSS escape sequences
// like `@\69mport` (backslash-hex import) by stripping CSS backslash
// escapes before the substring scan.
func scanDangerousStyleBody(body string) string {
	if body == "" {
		return ""
	}
	// Collapse CSS backslash escapes. An `\69` (hex for 'i') becomes 'i';
	// `\00020` becomes space. This is a best-effort approximation that
	// defeats naive substring obfuscation without pulling in a full CSS
	// tokenizer.
	stripped := stripCSSEscapes(body)
	for _, sub := range dangerousAttrValueSubstrings {
		if strings.Contains(stripped, sub) {
			return "dangerous token " + sub
		}
	}
	return ""
}

// stripCSSEscapes replaces CSS backslash escape sequences with their
// decoded characters so substring scanners can't be bypassed by
// `@\69mport`-style tricks. Unknown or truncated escapes are dropped.
func stripCSSEscapes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}
		// consume up to 6 hex digits per CSS spec
		j := i + 1
		hexEnd := j
		for hexEnd < len(s) && hexEnd-j < 6 && isHexDigit(s[hexEnd]) {
			hexEnd++
		}
		if hexEnd > j {
			var r rune
			for k := j; k < hexEnd; k++ {
				r = r*16 + rune(hexValue(s[k]))
			}
			b.WriteRune(r)
			i = hexEnd
			// Optional trailing whitespace after a hex escape is swallowed.
			if i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\f') {
				i++
			}
			continue
		}
		// Non-hex escape: drop backslash, take next char literally.
		if j < len(s) {
			b.WriteByte(s[j])
			i = j + 1
			continue
		}
		// Trailing lone backslash — drop.
		i++
	}
	return b.String()
}

// isHexDigit reports whether c is an ASCII hex digit.
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// hexValue returns the numeric value of an ASCII hex digit.
func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return 0
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
