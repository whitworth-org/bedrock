package bimi

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// dmarcView is the minimal projection of the email package's DMARC struct
// the BIMI Gmail-gate consumes. We read the value back from env.cache via
// reflection rather than importing email/* directly — sibling check
// packages don't compile lock-step during parallel development, and the
// reflection-based read keeps this check buildable in isolation.
type dmarcView struct {
	Policy   string // "p" tag: none | quarantine | reject
	Pct      int
	Adkim    string // "s" or "r"
	Aspf     string // "s" or "r"
	TestMode string // "t" tag: y | n (RFC 9989 §4.7)
	Raw      string
}

type gmailGateCheck struct{}

func (gmailGateCheck) ID() string       { return "bimi.gmail.dmarc" }
func (gmailGateCheck) Category() string { return category }

func (gmailGateCheck) Run(_ context.Context, env *probe.Env) []report.Result {
	const id = "bimi.gmail.dmarc"
	const title = "BIMI Gmail gate: DMARC quarantine|reject enforced, strict alignment"
	refs := []string{"Gmail BIMI requirements", "RFC 9989 §4.7"}

	v, ok := env.CacheGet(probe.CacheKeyDMARC)
	if !ok {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Info,
			Evidence:    "DMARC not parsed (no entry at " + probe.CacheKeyDMARC + ")",
			Remediation: dmarcRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
	if v == nil {
		// Email check ran but found no DMARC; still a Fail for Gmail BIMI.
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    "no DMARC record at _dmarc." + env.Target,
			Remediation: dmarcRemediation(env.Target),
			RFCRefs:     refs,
		}}
	}
	dv, err := readDMARC(v)
	if err != nil {
		return []report.Result{{
			ID: id, Category: category, Title: title,
			Status:   report.Info,
			Evidence: "DMARC cache value not introspectable: " + err.Error(),
			RFCRefs:  refs,
		}}
	}

	results := gateFailures(dv, env.Target, id, title, refs)
	if len(results) == 0 {
		results = append(results, report.Result{
			ID: id, Category: category, Title: title,
			Status:   report.Pass,
			Evidence: fmt.Sprintf("p=%s adkim=%s aspf=%s t=%s", dv.Policy, dv.Adkim, dv.Aspf, testModeOrN(dv.TestMode)),
			RFCRefs:  refs,
		})
	}
	return results
}

// gateFailures evaluates each Gmail BIMI requirement against the DMARC view
// and returns one Fail per unmet gate (empty when all pass).
func gateFailures(dv dmarcView, target, id, title string, refs []string) []report.Result {
	fail := func(evidence string) report.Result {
		return report.Result{
			ID: id, Category: category, Title: title,
			Status:      report.Fail,
			Evidence:    evidence,
			Remediation: dmarcRemediation(target),
			RFCRefs:     refs,
		}
	}

	var results []report.Result
	policy := strings.ToLower(strings.TrimSpace(dv.Policy))
	if policy != "quarantine" && policy != "reject" {
		results = append(results, fail(fmt.Sprintf("DMARC p=%q (need quarantine or reject)", dv.Policy)))
	}
	if dv.Pct != 100 {
		results = append(results, fail(fmt.Sprintf(
			"DMARC pct=%d — pct is retired in RFC 9989, but legacy receivers still sample at "+
				"pct<100, undercutting the full enforcement Gmail requires; remove the tag", dv.Pct)))
	}
	if strings.EqualFold(strings.TrimSpace(dv.TestMode), "y") {
		results = append(results, fail(
			"DMARC t=y — RFC 9989 test mode steps the effective policy down one level "+
				"(reject→quarantine→none), undercutting the enforcement Gmail requires; set t=n or "+
				"remove the tag"))
	}
	if !strings.EqualFold(strings.TrimSpace(dv.Adkim), "s") {
		results = append(results, fail(fmt.Sprintf("DMARC adkim=%q (need s for strict DKIM alignment)", dv.Adkim)))
	}
	if !strings.EqualFold(strings.TrimSpace(dv.Aspf), "s") {
		results = append(results, fail(fmt.Sprintf("DMARC aspf=%q (need s for strict SPF alignment)", dv.Aspf)))
	}
	return results
}

// testModeOrN renders an absent t= tag as its RFC 9989 default.
func testModeOrN(t string) string {
	if strings.TrimSpace(t) == "" {
		return "n"
	}
	return t
}

// readDMARC pulls the fields the gate cares about out of any value shaped
// like the email package's *DMARC. Accepts pointer-or-value, ignores
// missing fields, treats Pct == 0 (zero value) as "100" only if there is no
// Pct field present at all (defensive).
func readDMARC(v any) (dmarcView, error) {
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return dmarcView{}, fmt.Errorf("nil DMARC value")
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return dmarcView{}, fmt.Errorf("expected struct, got %s", rv.Kind())
	}
	out := dmarcView{}
	if f := rv.FieldByName("Policy"); f.IsValid() && f.Kind() == reflect.String {
		out.Policy = f.String()
	}
	if f := rv.FieldByName("Adkim"); f.IsValid() && f.Kind() == reflect.String {
		out.Adkim = f.String()
	}
	if f := rv.FieldByName("Aspf"); f.IsValid() && f.Kind() == reflect.String {
		out.Aspf = f.String()
	}
	if f := rv.FieldByName("TestMode"); f.IsValid() && f.Kind() == reflect.String {
		out.TestMode = f.String()
	}
	if f := rv.FieldByName("Raw"); f.IsValid() && f.Kind() == reflect.String {
		out.Raw = f.String()
	}
	if f := rv.FieldByName("Pct"); f.IsValid() {
		switch f.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			out.Pct = int(f.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			out.Pct = int(f.Uint())
		}
	} else {
		// No Pct field at all: assume the DMARC default of 100 so the pct
		// gate never fires on a struct that never carried the tag.
		out.Pct = 100
	}
	return out, nil
}

func dmarcRemediation(domain string) string {
	return fmt.Sprintf(
		`_dmarc.%s. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@%s; adkim=s; aspf=s"`,
		domain, domain,
	)
}
