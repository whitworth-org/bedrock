package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Config mirrors the flag set; supplied either via --config <path> or the
// flag-only call site. Flag values override config values when both are set.
type Config struct {
	NoColor        bool     `json:"no_color,omitempty"`
	NoActive       bool     `json:"no_active,omitempty"`
	Resolver       string   `json:"resolver,omitempty"`
	Resolvers      []string `json:"resolvers,omitempty"`
	Timeout        string   `json:"timeout,omitempty"`
	Only           []string `json:"only,omitempty"`
	Exclude        []string `json:"exclude,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	IDs            []string `json:"ids,omitempty"`
	Subdomains     bool     `json:"subdomains,omitempty"`
	EnableRBL      bool     `json:"enable_rbl,omitempty"`
	Baseline       string   `json:"baseline,omitempty"`
	RegressionOnly bool     `json:"regression_only,omitempty"`
	EnableCT       bool     `json:"enable_ct,omitempty"`
}

// LoadConfig reads a JSON config file from path. An empty path returns the
// zero value with no error so callers can unconditionally call this.
// The file size is limited to 1 MiB and unknown fields are rejected.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return &Config{}, nil
	}
	// Errors from os.Open and Read are *PathError, which names the path.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	defer func() {
		_ = f.Close() // File close error is informational only in this read-only context
	}()

	// Limit file size to 1 MiB to prevent memory exhaustion
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var c Config
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Ensure there's no second JSON value following the first
	var dummy interface{}
	if err := decoder.Decode(&dummy); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		return nil, fmt.Errorf("config %s contains multiple JSON values", path)
	}

	return &c, nil
}

// Duration parses the config's Timeout string, falling back to def when empty.
func (c *Config) Duration(def time.Duration) (time.Duration, error) {
	if c == nil || c.Timeout == "" {
		return def, nil
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 0, fmt.Errorf("parse timeout %q: %w", c.Timeout, err)
	}
	return d, nil
}
