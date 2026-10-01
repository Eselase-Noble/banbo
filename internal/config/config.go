// Package config loads banbo settings from a JSON file (~/.banbo/config.json)
// and environment variables. Environment variables win so secrets never need to
// live on disk. Using JSON keeps the MVP dependency-free (no YAML library).
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config holds user-tunable settings, chiefly the API credentials used for
// optional finding enrichment. Claude is preferred; OpenAI is a drop-in
// fallback so banbo works with whichever key the user has.
type Config struct {
	// APIKey is the Anthropic (Claude) API key. If empty, Claude enrichment is
	// skipped and banbo falls back to OpenAI (if set) or built-in guidance.
	APIKey string `json:"api_key"`
	// Model is the Claude model used for enrichment.
	Model string `json:"model"`
	// OpenAIKey is the OpenAI API key, used when no Claude key is configured.
	OpenAIKey string `json:"openai_api_key"`
	// OpenAIModel is the OpenAI chat model used for enrichment.
	OpenAIModel string `json:"openai_model"`
}

// DefaultModel is the Claude model used when none is configured.
const DefaultModel = "claude-opus-4-8"

// DefaultOpenAIModel is the OpenAI model used when none is configured.
const DefaultOpenAIModel = "gpt-4o-mini"

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
	c := Config{Model: DefaultModel, OpenAIModel: DefaultOpenAIModel}

	if p, err := Path(); err == nil {
		if data, rerr := os.ReadFile(p); rerr == nil {
			_ = json.Unmarshal(data, &c) // ignore malformed file; env can still supply values
		}
	}

	// Environment overrides. Support the standard provider variables too.
	if v := os.Getenv("BANBO_API_KEY"); v != "" {
		c.APIKey = v
	} else if v := os.Getenv("ANTHROPIC_API_KEY"); v != "" && c.APIKey == "" {
		c.APIKey = v
	}
	if v := os.Getenv("BANBO_MODEL"); v != "" {
		c.Model = v
	}
	if v := os.Getenv("BANBO_OPENAI_API_KEY"); v != "" {
		c.OpenAIKey = v
	} else if v := os.Getenv("OPENAI_API_KEY"); v != "" && c.OpenAIKey == "" {
		c.OpenAIKey = v
	}
	if v := os.Getenv("BANBO_OPENAI_MODEL"); v != "" {
		c.OpenAIModel = v
	} else if v := os.Getenv("OPENAI_MODEL"); v != "" {
		c.OpenAIModel = v
	}
	if c.Model == "" {
		c.Model = DefaultModel
	}
	if c.OpenAIModel == "" {
		c.OpenAIModel = DefaultOpenAIModel
	}
	return c, nil
}

// HasClaude reports whether an Anthropic/Claude API key is configured.
func (c Config) HasClaude() bool { return c.APIKey != "" }

// HasOpenAI reports whether an OpenAI API key is configured.
func (c Config) HasOpenAI() bool { return c.OpenAIKey != "" }

// Provider returns the name of the active AI provider ("claude", "openai", or
// "" when none is configured). Claude is preferred when both are set.
func (c Config) Provider() string {
	switch {
	case c.HasClaude():
		return "claude"
	case c.HasOpenAI():
		return "openai"
	default:
		return ""
	}
}

// AIEnabled reports whether enrichment can run (any provider key is available).
func (c Config) AIEnabled() bool { return c.HasClaude() || c.HasOpenAI() }
