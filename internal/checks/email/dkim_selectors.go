package email

import (
	"strings"

	"granite-scan/internal/probe"
)

// commonSelectors is the union of selectors used by major ESPs. The list is
// long because DNS lookup of a non-existent selector is cheap and the false
// positive cost is zero; missing a selector means we silently miss a DKIM
// publication and downgrade the check unnecessarily.
//
// The list is intentionally limited to selectors whose full label is known
// in advance. ESPs that derive selectors from a per-tenant identifier (e.g.
// HubSpot's "hs1-<id>-<domain>" pattern) are out of reach for blind probing
// and are handled — when possible — via espSelectors() once SPF includes
// reveal which provider is in use.
//
// Future work: NSEC walking could discover additional selectors on
// NSEC-signed (not NSEC3) zones. Skipped for now — it adds complexity
// disproportionate to the win on the small fraction of zones that opt in.
var commonSelectors = dedupSelectors([]string{
	// Generic
	"default", "dkim", "mail", "selector1", "selector2",
	"key1", "key2", "k1", "k2", "k3",
	"mx", "s1", "s2",

	// Google Workspace
	"google", "google2",

	// Sendgrid
	"smtpapi",

	// Mailgun / Mailo
	"mg", "mailo",

	// Postmark
	"pm",

	// SparkPost (versioned per-tenant; common values seen in the wild)
	"scph0823", "scph1023", "scph0124",

	// Amazon SES
	"amazonses",

	// Salesforce / Marketing Cloud / Pardot / ExactTarget
	"mfsv01", "mfsv02", "mfsv03", "mfsv04", "mfsv05",
	"200608", "et",

	// Zendesk
	"zendesk1", "zendesk2",

	// Klaviyo
	"klaviyo", "k1klaviyo",

	// Mandrill / Mailchimp transactional
	"mte1", "mte2", "mandrill",

	// Drip / ActiveCampaign / ConvertKit
	"drip", "ac1", "ac2", "convertkit",

	// Brevo (formerly Sendinblue)
	"brevo",

	// Hosting providers
	"ovh", "hetzner",
})

// espSelectors returns extra selectors to probe based on observed SPF
// includes. When the SPF cache is empty (e.g. SPF check has not run, or the
// domain has no SPF record), it returns nil and the caller falls back to the
// generic list.
func espSelectors(env *probe.Env) []string {
	if env == nil {
		return nil
	}
	raw, ok := env.CacheGet(probe.CacheKeySPF)
	if !ok {
		return nil
	}
	spf, ok := raw.(*SPF)
	if !ok || spf == nil {
		return nil
	}
	text := strings.ToLower(spf.Raw)

	var extra []string
	add := func(sels ...string) { extra = append(extra, sels...) }

	// Each include is checked independently — a domain can use multiple
	// providers, and we want to probe selectors for all of them.
	if strings.Contains(text, "_spf.salesforce.com") ||
		strings.Contains(text, "_spf.exacttarget.com") ||
		strings.Contains(text, "_spf.pardot.com") {
		add("mfsv01", "mfsv02", "mfsv03", "mfsv04", "mfsv05", "et", "200608")
	}
	if strings.Contains(text, "_spf.google.com") {
		add("google", "google2")
	}
	if strings.Contains(text, "spf.protection.outlook.com") {
		add("selector1", "selector2")
	}
	if strings.Contains(text, "mailgun.org") {
		add("mg", "mailo", "k1")
	}
	if strings.Contains(text, "sendgrid.net") {
		add("s1", "s2", "smtpapi")
	}
	if strings.Contains(text, "amazonses.com") {
		add("amazonses")
	}
	if strings.Contains(text, "spf.mandrillapp.com") {
		add("mte1", "mte2", "mandrill")
	}
	if strings.Contains(text, "_spf.mailchimpapp.net") ||
		strings.Contains(text, "servers.mcsv.net") {
		add("k1", "k2", "k3")
	}
	if strings.Contains(text, "spf.mtasv.net") {
		// Postmark
		add("pm")
	}
	if strings.Contains(text, "sparkpostmail.com") {
		add("scph0823", "scph1023", "scph0124")
	}
	if strings.Contains(text, "_spf.klaviyo.com") {
		add("klaviyo", "k1klaviyo")
	}
	if strings.Contains(text, "_spf.brevo.com") ||
		strings.Contains(text, "spf.sendinblue.com") {
		add("brevo")
	}
	if strings.Contains(text, "_spf.zendesk.com") {
		add("zendesk1", "zendesk2")
	}
	return extra
}

// selectorList returns the deduplicated, ordered list of DKIM selectors to
// probe for env.Target. Common selectors come first (stable order), followed
// by ESP-specific extras inferred from SPF includes.
func selectorList(env *probe.Env) []string {
	seen := make(map[string]struct{}, len(commonSelectors)+8)
	out := make([]string, 0, len(commonSelectors)+8)
	for _, s := range commonSelectors {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range espSelectors(env) {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// dedupSelectors strips duplicates while preserving first-seen order. Used at
// package init so commonSelectors is canonical.
func dedupSelectors(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
