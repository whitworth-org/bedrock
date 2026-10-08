package bimi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/whitworth-org/bedrock/internal/checks/checkutil"
	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// Cache key of the l= logo fetch (*outcome[[]byte]), which ensureSVG alone
// stores.
const cacheKeyBIMISVG = "bimi.svg"

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
	return ensureSVG(ctx, env).results(svgFetchBase())
}

func svgFetchBase() report.Result {
	return report.Result{
		ID: "bimi.svg.fetch", Category: category,
		Title:   "BIMI SVG fetched over HTTPS as image/svg+xml",
		RFCRefs: []string{"BIMI Group draft §4.4", "BIMI SVG Tiny PS Profile"},
	}
}

// ensureSVG fetches the l= logo at most once per scan however many checks
// ask (see probe.Shared) and returns the bimi.svg.fetch outcome, whose
// product is the body only when the fetch passed.
func ensureSVG(ctx context.Context, env *probe.Env) *outcome[[]byte] {
	return probe.Shared(env, cacheKeyBIMISVG, func() *outcome[[]byte] { return fetchSVG(ctx, env) })
}

// fetchSVG fetches the logo the BIMI record names. It refuses an l= URL
// that bimi.txt rejects before connecting, and it caches nothing that did
// not arrive whole as image/svg+xml over verified HTTPS: the profile,
// aspect and logotype checks parse and hash what it returns.
func fetchSVG(ctx context.Context, env *probe.Env) *outcome[[]byte] {
	res := svgFetchBase()
	rec := ensureRecord(ctx, env)
	if skip := svgSkipReason(rec, env.Active); skip != "" {
		res.Status = report.NotApplicable
		res.Evidence = skip
		return &outcome[[]byte]{result: res}
	}
	res.Status = report.Fail
	res.Remediation = svgFetchRemediation()

	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	resp, err := getVerified(ctx, env, rec.L)
	if err != nil {
		return &outcome[[]byte]{result: fetchFailed(ctx, res, rec.L, err)}
	}
	ct := resp.Headers.Get("Content-Type")
	if mediaType(ct) != "image/svg+xml" {
		res.Evidence = fmt.Sprintf("Content-Type=%q (want image/svg+xml)", report.ClipValue(ct))
		return &outcome[[]byte]{result: res}
	}
	sum := sha256.Sum256(resp.Body)
	res.Status = report.Pass
	res.Evidence = fmt.Sprintf("HTTP 200 %s, %d bytes, sha256=%x",
		mediaType(ct), len(resp.Body), sum[:8])
	res.Remediation = ""
	return &outcome[[]byte]{result: res, product: resp.Body}
}

// svgSkipReason returns why the logo in rec is not fetched, or "" when it
// is. An l= URL that bimi.txt rejects is N/A here so that one problem
// counts as one FAIL.
func svgSkipReason(rec *Record, active bool) string {
	switch {
	case rec == nil:
		return "no parsed BIMI record (TXT check did not produce one)"
	case !active:
		return "skipped: --no-active"
	case rec.L == "":
		return "no l= URL in BIMI record"
	}
	if err := httpsURL(rec.L); err != nil {
		return "l= URL not fetched: " + err.Error() + " (see bimi.txt)"
	}
	return ""
}

// mediaType returns the lower-cased media type of a Content-Type value,
// without its parameters.
func mediaType(contentType string) string {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

type svgProfileCheck struct{}

func (svgProfileCheck) ID() string       { return "bimi.svg.profile" }
func (svgProfileCheck) Category() string { return category }

func (svgProfileCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	res := report.Result{
		ID: "bimi.svg.profile", Category: category,
		Title:   "BIMI SVG conforms to SVG Tiny PS profile",
		RFCRefs: []string{"BIMI SVG Tiny PS Profile §3"},
	}
	if !env.Active {
		res.Status, res.Evidence = report.NotApplicable, "skipped: --no-active"
		return []report.Result{res}
	}
	body := ensureSVG(ctx, env).value()
	if body == nil {
		res.Status = report.NotApplicable
		res.Evidence = "no SVG body cached (fetch did not succeed)"
		return []report.Result{res}
	}
	vr := ValidateTinyPS(body)
	if vr.undecodable != nil {
		return []report.Result{checkutil.Inconclusive(res, vr.undecodable)}
	}
	if vr.ok() {
		res.Status = report.Pass
		res.Evidence = "SVG Tiny PS allowlist satisfied; " +
			"no scripts, event handlers, or external refs"
		return []report.Result{res}
	}
	res.Status = report.Fail
	res.Evidence = vr.evidence()
	res.Remediation = svgProfileRemediation()
	return []report.Result{res}
}

type svgAspectCheck struct{}

func (svgAspectCheck) ID() string       { return "bimi.svg.aspect" }
func (svgAspectCheck) Category() string { return category }

func (svgAspectCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	res := report.Result{
		ID: "bimi.svg.aspect", Category: category,
		Title:   "BIMI SVG viewBox is square (1:1)",
		RFCRefs: []string{"BIMI Group draft §4.4 (square logo requirement)"},
	}
	if !env.Active {
		res.Status, res.Evidence = report.NotApplicable, "skipped: --no-active"
		return []report.Result{res}
	}
	body := ensureSVG(ctx, env).value()
	if body == nil {
		res.Status = report.NotApplicable
		res.Evidence = "no SVG body cached (fetch did not succeed)"
		return []report.Result{res}
	}
	w, h, raw, err := extractViewBox(body)
	var encErr *encodingError
	switch {
	case errors.As(err, &encErr):
		return []report.Result{checkutil.Inconclusive(res, encErr)}
	case err != nil:
		res.Status, res.Evidence = report.Fail, err.Error()
	case w != h:
		res.Status = report.Fail
		res.Evidence = fmt.Sprintf("viewBox=%q has %g:%g aspect (want 1:1)",
			report.ClipValue(raw), w, h)
	default:
		res.Status, res.Evidence = report.Pass, fmt.Sprintf("viewBox=%q", report.ClipValue(raw))
		return []report.Result{res}
	}
	res.Remediation = svgProfileRemediation()
	return []report.Result{res}
}

// validationReport collects Tiny PS violations without aborting on the
// first. It keeps checkutil.MaxListed of them, since a hostile logo can
// repeat one bad attribute thousands of times in a single element, which
// the token cap does not bound. Every value it quotes from the document is
// clipped.
type validationReport struct {
	fatalError   string         // e.g. XML parse failure or wrong root element
	profileFails []string       // the first checkutil.MaxListed violations
	unlisted     int            // violations found beyond profileFails
	undecodable  *encodingError // set when the declared encoding stopped the walk
}

// addFail records one violation, formatting it only while fewer than
// checkutil.MaxListed are listed and counting it otherwise.
func (r *validationReport) addFail(format string, args ...any) {
	if len(r.profileFails) == checkutil.MaxListed {
		r.unlisted++
		return
	}
	r.profileFails = append(r.profileFails, fmt.Sprintf(format, args...))
}

// ok reports whether the document passed: decoded, with no fatal error and
// no violation.
func (r validationReport) ok() bool {
	return r.undecodable == nil && r.fatalError == "" && len(r.profileFails) == 0
}

// setDecodeError records why the decoder stopped. A declared encoding the
// validator cannot read leaves the logo's conformance unknown, unless a
// violation was already found.
func (r *validationReport) setDecodeError(err error) {
	var encErr *encodingError
	if errors.As(err, &encErr) && len(r.profileFails) == 0 {
		r.undecodable = encErr
		return
	}
	r.fatalError = "XML parse error: " + report.ClipValue(err.Error())
}

// evidence lists the fatal error, then each listed violation, then how many
// more were found.
func (r validationReport) evidence() string {
	items := r.profileFails
	if r.fatalError != "" {
		items = append([]string{r.fatalError}, items...)
	}
	out := strings.Join(items, "; ")
	if r.unlisted > 0 {
		out += fmt.Sprintf("; and %d more", r.unlisted)
	}
	return out
}

// urlBearingAttrs lists the attributes whose values may carry a URL. Beyond
// plain href, SVG paints, markers, cursors and filter references can also
// smuggle external resources via url(…) (e.g. fill="url(http://evil/x)");
// BIMI Tiny PS forbids external fetches, so every one of these is scanned
// for dangerous schemes.
var urlBearingAttrs = map[string]struct{}{
	"href":          {},
	"fill":          {},
	"stroke":        {},
	"filter":        {},
	"mask":          {},
	"clip-path":     {},
	"style":         {},
	"begin":         {},
	"marker-start":  {},
	"marker-mid":    {},
	"marker-end":    {},
	"cursor":        {},
	"color-profile": {},
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
// it finds, listing at most checkutil.MaxListed of them. Returns a fatal
// error message when the SVG cannot even be parsed, exceeds a resource cap,
// or doesn't have <svg> at the root.
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
	dec := newSVGDecoder(body)

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
			v.setDecodeError(err)
			return v
		}
		switch t := tok.(type) {
		case xml.Directive:
			// DOCTYPE / ENTITY declarations are the billion-laughs and DTD
			// injection vectors. BIMI Tiny PS has no legitimate use for them;
			// reject as a profile failure rather than aborting, so the
			// operator sees the full list of issues.
			v.addFail("XML directive (DOCTYPE/ENTITY) is not allowed in SVG Tiny PS")
		case xml.ProcInst:
			// Processing instructions are rejected, with one exception: the
			// XML declaration <?xml version="…"?>. Go's decoder surfaces
			// the XML prolog as a ProcInst with target "xml", so we allow
			// exactly that target and flag anything else.
			if strings.EqualFold(t.Target, "xml") {
				break
			}
			v.addFail("XML processing instruction <?%s ...?> is not allowed",
				report.ClipValue(t.Target))
		case xml.StartElement:
			depth++
			if depth > maxSVGDepth {
				v.fatalError = fmt.Sprintf("SVG exceeds depth cap %d", maxSVGDepth)
				return v
			}
			name := strings.ToLower(t.Name.Local)
			elem := report.ClipValue(t.Name.Local)
			elemStack = append(elemStack, name)
			if name == "style" {
				inStyle = true
				styleBuf.Reset()
			}
			if !rootSeen {
				rootSeen = true
				if name != "svg" {
					v.fatalError = fmt.Sprintf("root element is <%s>, expected <svg>", elem)
					return v
				}
				if reason := checkRootSVG(t); reason != "" {
					v.addFail("%s", reason)
				}
			}
			v.auditElement(name, elem, t.Attr)
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
						v.addFail("<style> contains %s", reason)
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

// auditElement records the violations of one element: a disallowed or
// unlisted name, then each attribute's. name is lower-cased; elem is the
// clipped original spelling quoted in evidence.
func (r *validationReport) auditElement(name, elem string, attrs []xml.Attr) {
	if reason, bad := disallowedSVGElements[name]; bad {
		r.addFail("disallowed element <%s> (%s)", elem, reason)
	} else if _, ok := allowedSVGElements[name]; !ok {
		r.addFail("element <%s> not in Tiny PS allowlist", elem)
	}
	for _, a := range attrs {
		r.auditAttr(elem, a)
	}
}

// auditAttr records the violations of one attribute on <elem>: an event
// handler, an external href (in any namespace, xlink:href included), or a
// dangerous token in a URL-bearing value such as fill="url(http://…)".
func (r *validationReport) auditAttr(elem string, a xml.Attr) {
	attr := strings.ToLower(a.Name.Local)
	if strings.HasPrefix(attr, "on") {
		r.addFail("event-handler attribute %s on <%s>", report.ClipValue(a.Name.Local), elem)
		return
	}
	if attr == "href" && isExternalRef(a.Value) {
		r.addFail("external href on <%s>: %q", elem, report.ClipValue(a.Value))
	}
	if _, urlBearing := urlBearingAttrs[attr]; !urlBearing {
		return
	}
	if reason := scanDangerousAttrValue(a.Value); reason != "" {
		r.addFail("attribute %s on <%s> contains %s: %q",
			report.ClipValue(a.Name.Local), elem, reason, report.ClipValue(a.Value))
	}
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
			return fmt.Sprintf("root <svg> baseProfile=%q (want \"tiny-ps\")",
				report.ClipValue(a.Value))
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
	dec := newSVGDecoder(body)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return 0, 0, "", errors.New("no <svg> element found")
		}
		if err != nil {
			return 0, 0, "", xmlParseError(err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !strings.EqualFold(se.Name.Local, "svg") {
			return 0, 0, "", fmt.Errorf("first element is <%s>, expected <svg>",
				report.ClipValue(se.Name.Local))
		}
		for _, a := range se.Attr {
			if strings.EqualFold(a.Name.Local, "viewBox") {
				parts := strings.Fields(strings.ReplaceAll(a.Value, ",", " "))
				shown := report.ClipValue(a.Value)
				if len(parts) != 4 {
					return 0, 0, a.Value, fmt.Errorf("viewBox=%q does not have 4 components", shown)
				}
				w, errW := strconv.ParseFloat(parts[2], 64)
				h, errH := strconv.ParseFloat(parts[3], 64)
				if errW != nil || errH != nil {
					return 0, 0, a.Value, fmt.Errorf("viewBox=%q components not numeric", shown)
				}
				if w <= 0 || h <= 0 {
					return 0, 0, a.Value,
						fmt.Errorf("viewBox=%q has non-positive dimensions", shown)
				}
				return w, h, a.Value, nil
			}
		}
		return 0, 0, "", errors.New("<svg> has no viewBox attribute")
	}
}

// xmlParseError is extractViewBox's error when decoding stops early: an
// unsupported declared encoding as is, any other error clipped.
func xmlParseError(err error) error {
	var encErr *encodingError
	if errors.As(err, &encErr) {
		return encErr
	}
	return errors.New("XML parse: " + report.ClipValue(err.Error()))
}

// newSVGDecoder returns a strict decoder for body that also reads the
// encodings svgCharsetReader supports.
func newSVGDecoder(body []byte) *xml.Decoder {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.CharsetReader = svgCharsetReader
	return dec
}

// encodingError reports an XML declaration naming an encoding the validator
// cannot read, which leaves the logo's conformance unknown rather than wrong.
type encodingError struct{ label string }

func (e *encodingError) Error() string {
	return fmt.Sprintf("unsupported SVG encoding %q "+
		"(bedrock reads UTF-8, US-ASCII and ISO-8859-1)", report.ClipValue(e.label))
}

// svgCharsetReader is the decoder's CharsetReader, which encoding/xml calls
// for any declared encoding other than "utf-8". ISO-8859-1 maps each byte to
// the code point of the same value; US-ASCII is read as that superset.
func svgCharsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "utf8":
		return input, nil
	case "us-ascii", "ascii", "iso-8859-1", "iso8859-1", "iso_8859-1", "latin1", "l1":
		raw, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 0, len(raw))
		for _, b := range raw {
			out = utf8.AppendRune(out, rune(b))
		}
		return bytes.NewReader(out), nil
	}
	return nil, &encodingError{label: label}
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
