package email

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/whitworth-org/bedrock/internal/probe"
	"github.com/whitworth-org/bedrock/internal/report"
)

// googleWorkspaceMXCheck detects domains that still point their MX RRset at
// Google Workspace's legacy multi-host ASPMX layout
// (ASPMX.L.GOOGLE.COM + ALT1..ALT4) and nudges the operator toward the
// consolidated single-host form (SMTP.GOOGLE.COM). The check is intentionally
// quiet: it emits nothing unless the legacy form is in active use. Non-Google
// mail providers, domains already on the new single-MX form, and domains
// without MX records produce no output at all.
type googleWorkspaceMXCheck struct{}

func (googleWorkspaceMXCheck) ID() string       { return "email.google_workspace_mx" }
func (googleWorkspaceMXCheck) Category() string { return category }

// legacyASPMXHosts lists the exact Google Workspace ASPMX hostnames that
// constitute the legacy (multi-record) configuration. Any MX pointing at one
// of these hosts implies the domain is still on the older setup, even if
// only a subset of the records are present.
var legacyASPMXHosts = map[string]struct{}{
	"aspmx.l.google.com":      {},
	"alt1.aspmx.l.google.com": {},
	"alt2.aspmx.l.google.com": {},
	"alt3.aspmx.l.google.com": {},
	"alt4.aspmx.l.google.com": {},
}

// newSingleMXHost is the target of the current Google Workspace
// recommendation: one MX pointing at SMTP.GOOGLE.COM.
const newSingleMXHost = "smtp.google.com"

// googleWorkspaceMigrationURL is the canonical admin-help article that
// describes the MX migration. Referenced in the Evidence line so operators
// can click through to the first-party instructions.
const googleWorkspaceMigrationURL = "https://knowledge.workspace.google.com/admin/domains/set-up-mx-records-for-google-workspace"

// Run inspects the cached (or freshly fetched) MX set. If — and only if —
// the domain uses Google Workspace via legacy ASPMX records, emit a single
// INFO result pointing at the migration guide. The check produces no
// results in all other cases (no MX, non-Google MX, or already-new
// single-host form) so the report stays uncluttered.
func (googleWorkspaceMXCheck) Run(ctx context.Context, env *probe.Env) []report.Result {
	mxs := lookupMXCached(ctx, env)
	if len(mxs) == 0 {
		return nil
	}

	var (
		legacyHits []string
		hasNew     bool
	)
	seen := map[string]struct{}{}
	for _, mx := range mxs {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(mx.Host)), ".")
		if host == "" {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		if _, ok := legacyASPMXHosts[host]; ok {
			legacyHits = append(legacyHits, host)
			continue
		}
		if host == newSingleMXHost {
			hasNew = true
		}
	}

	// Nothing to say: either not Google Workspace at all, or already on the
	// single-MX form with zero legacy residue.
	if len(legacyHits) == 0 {
		return nil
	}

	sort.Strings(legacyHits)
	evidence := "Google Workspace legacy MX in use: " + strings.Join(legacyHits, ", ")
	if hasNew {
		evidence += "; mixed with new " + newSingleMXHost + " (migration partially complete)"
	}
	evidence += ". Update MX records to use the new single MX record for Google Workspace. See: " + googleWorkspaceMigrationURL

	return []report.Result{{
		ID:       "email.google_workspace_mx",
		Category: category,
		Title:    "Google Workspace MX layout (migration available)",
		Status:   report.Info,
		Evidence: evidence,
		RFCRefs:  []string{"RFC 1035 §3.3.9", "RFC 5321 §5.1"},
	}}
}

// lookupMXCached reads the MX slice out of env.Cache when a previous check
// (nullMXCheck) has already populated it; falls back to a direct resolver
// call otherwise. Errors are swallowed — if we cannot get MX records the
// check simply emits nothing, exactly as when there are no records at all.
func lookupMXCached(ctx context.Context, env *probe.Env) []probe.MX {
	if v, ok := env.CacheGet(probe.CacheKeyMX); ok {
		if mxs, ok := v.([]probe.MX); ok {
			return mxs
		}
	}
	ctx, cancel := env.WithTimeout(ctx)
	defer cancel()
	mxs, err := env.DNS.LookupMX(ctx, env.Target)
	if err != nil && !errors.Is(err, probe.ErrNXDOMAIN) {
		return nil
	}
	return mxs
}
