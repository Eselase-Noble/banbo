// Package config loads banbo settings from a JSON file (~/.banbo/config.json)
// and environment variables. Environment variables win so secrets never need to
// live on disk. Using JSON keeps the MVP dependency-free (no YAML library).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds user-tunable settings, chiefly the Claude API credentials used
// for optional finding enrichment.
type Config struct {
	// APIKey is the Anthropic API key. If empty, AI enrichment is skipped and
	// the scanner falls back to its built-in static remediation guidance.
	APIKey string `json:"api_key"`
	// Model is the Claude model used for enrichment.
	Model string `json:"model"`
}

// DefaultModel is used when none is configured.
const DefaultModel = "claude-opus-4-8"

// Path returns the location of the config file (~/.banbo/config.json).
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".banbo", "config.json"), nil
}

// Load reads the config file if present, then overlays environment variables.
// A missing file is not an error — defaults plus env vars are returned.
func Load() (Config, error) {
	c := Config{Model: DefaultModel}

	if p, err := Path(); err == nil {
		if data, rerr := os.ReadFile(p); rerr == nil {
			_ = json.Unmarshal(data, &c) // ignore malformed file; env can still supply values
		}
	}

	// Environment overrides. Support the standard Anthropic variable too.
	if v := os.Getenv("BANBO_API_KEY"); v != "" {
		c.APIKey = v
	} else if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" && c.APIKey == "" {
		c.APIKey = v
	}
	if v := os.Getenv("BANBO_MODEL"); v != "" {
		c.Model = v
	}
	if c.Model == "" {
		c.Model = DefaultModel
	}
	return c, nil
}

// AIEnabled reports whether enrichment can run (an API key is available).
func (c Config) AIEnabled() bool { return c.APIKey != "" }
