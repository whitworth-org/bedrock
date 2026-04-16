// Source patterns adapted from ProjectDiscovery's subfinder
// (MIT, https://github.com/projectdiscovery/subfinder).
//
// We deliberately use only the four simplest key-free passive sources here —
// each one a single GET against a public endpoint with a small parser.

package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"bedrock/internal/report"
)

// userAgent is shared across all sources. Kept consistent with the
// project-wide HTTP client identity in probe/http.go so operators see one
// User-Agent string in their access logs.
const userAgent = "bedrock/0.1 (+https://example.invalid/)"

// source is the minimal interface every passive enumeration backend
// satisfies. Each implementation does a single GET, parses the body, and
// returns a slice of candidate hostnames (raw — caller will lowercase,
// trim, and scope-filter).
type source interface {
	Name() string
	Discover(ctx context.Context, domain string, client *http.Client) ([]string, error)
}

// enumerate runs every source concurrently against the target domain,
// dedups results (lowercased, trailing-dot stripped), and filters to the
// in-scope set (apex or *.apex). Per-source errors become Info results
// rather than aborting the whole enumeration — discovery is best-effort.
func enumerate(ctx context.Context, domain string, timeout time.Duration) ([]string, []report.Result) {
	// Per-source HTTP timeout. The plan calls for 15s; we honor that as a
	// hard floor independent of env.Timeout (env.Timeout is tuned for DNS,
	// which is much faster than these archive APIs).
	const perSourceTimeout = 15 * time.Second
	client := &http.Client{Timeout: perSourceTimeout}

	sources := []source{
		hackertargetSource{},
		anubisSource{},
		threatcrowdSource{},
		waybackSource{},
	}

	var (
		mu    sync.Mutex
		seen  = map[string]struct{}{}
		notes []report.Result
		wg    sync.WaitGroup
	)

	suffix := "." + domain

	for _, s := range sources {
		wg.Add(1)
		go func(s source) {
			defer wg.Done()
			hosts, err := s.Discover(ctx, domain, client)
			if err != nil {
				mu.Lock()
				notes = append(notes, report.Result{
					ID:       "subdomain.source." + s.Name(),
					Category: category,
					Title:    "Source: " + s.Name(),
					Status:   report.Info,
					Evidence: err.Error(),
				})
				mu.Unlock()
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, h := range hosts {
				h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(h, ".")))
				if h == "" {
					continue
				}
				// Scope filter: keep only in-bailiwick names. We accept the
				// apex itself (some sources echo it back) and any host
				// whose name ends with ".<apex>".
				if h != domain && !strings.HasSuffix(h, suffix) {
					continue
				}
				seen[h] = struct{}{}
			}
		}(s)
	}
	wg.Wait()

	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out, notes
}

// httpGet issues a User-Agent-tagged GET and returns the body (capped at
// 4 MiB to avoid blowing memory on a misbehaving source). Status codes
// outside 2xx are turned into errors so the caller logs an Info note.
func httpGet(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	const maxBody = 4 << 20 // 4 MiB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

// hackertargetSource queries https://api.hackertarget.com/hostsearch/.
// Response shape: newline-delimited "subdomain.example.com,IP" lines.
type hackertargetSource struct{}

func (hackertargetSource) Name() string { return "hackertarget" }

func (hackertargetSource) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	body, err := httpGet(ctx, client, fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain)))
	if err != nil {
		return nil, fmt.Errorf("hackertarget: %w", err)
	}
	return parseHackertarget(string(body)), nil
}

// parseHackertarget extracts the leading hostname from each "host,ip" line.
// Skips empty lines and the well-known "API count exceeded" sentinel that
// the service returns as a single line on rate-limit.
func parseHackertarget(body string) []string {
	out := make([]string, 0, 16)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "api count exceeded") {
			continue
		}
		if i := strings.IndexByte(line, ','); i > 0 {
			out = append(out, line[:i])
		} else {
			// Some entries may not have an IP suffix; keep the raw token.
			out = append(out, line)
		}
	}
	return out
}

// anubisSource queries https://jonlu.ca/anubis/subdomains/<domain>.
// Response shape: JSON array of strings.
type anubisSource struct{}

func (anubisSource) Name() string { return "anubis" }

func (anubisSource) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	body, err := httpGet(ctx, client, fmt.Sprintf("https://jonlu.ca/anubis/subdomains/%s", url.PathEscape(domain)))
	if err != nil {
		return nil, fmt.Errorf("anubis: %w", err)
	}
	return parseAnubis(body)
}

func parseAnubis(body []byte) ([]string, error) {
	var hosts []string
	if err := json.Unmarshal(body, &hosts); err != nil {
		return nil, fmt.Errorf("anubis: parse json: %w", err)
	}
	return hosts, nil
}

// threatcrowdSource queries http://ci-www.threatcrowd.org/searchApi/v2/.
// Response shape: {"response_code":"1","subdomains":[...]}.
type threatcrowdSource struct{}

func (threatcrowdSource) Name() string { return "threatcrowd" }

func (threatcrowdSource) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	body, err := httpGet(ctx, client, fmt.Sprintf("http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", url.QueryEscape(domain)))
	if err != nil {
		return nil, fmt.Errorf("threatcrowd: %w", err)
	}
	return parseThreatcrowd(body)
}

// threatcrowdResponse is the subset of fields we care about.
type threatcrowdResponse struct {
	ResponseCode string   `json:"response_code"`
	Subdomains   []string `json:"subdomains"`
}

func parseThreatcrowd(body []byte) ([]string, error) {
	var r threatcrowdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("threatcrowd: parse json: %w", err)
	}
	return r.Subdomains, nil
}

// waybackSource queries the Internet Archive's CDX index for any URL
// matching *.<domain>/*. We extract the hostname from each URL and rely
// on the caller to scope-filter.
type waybackSource struct{}

func (waybackSource) Name() string { return "wayback" }

func (waybackSource) Discover(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	target := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=txt&fl=original&collapse=urlkey", url.QueryEscape(domain))
	body, err := httpGet(ctx, client, target)
	if err != nil {
		return nil, fmt.Errorf("wayback: %w", err)
	}
	return parseWayback(string(body), domain), nil
}

// parseWayback turns the CDX plaintext body into a list of hostnames.
// Each line is a URL; we URL-decode it (Wayback percent-encodes the path
// portion), parse it, and pull the Hostname. Lines that don't parse as
// URLs or whose hostname doesn't end with ".<domain>" are dropped.
func parseWayback(body, domain string) []string {
	out := make([]string, 0, 16)
	suffix := "." + strings.ToLower(domain)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if decoded, err := url.QueryUnescape(line); err == nil {
			line = decoded
		}
		// CDX may return lines without a scheme; url.Parse needs one.
		if !strings.Contains(line, "://") {
			line = "http://" + line
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
		}
		if host != strings.ToLower(domain) && !strings.HasSuffix(host, suffix) {
			continue
		}
		out = append(out, host)
	}
	return out
}
