package cli

import (
	"encoding/json"
	"fmt"
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
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return &Config{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
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
