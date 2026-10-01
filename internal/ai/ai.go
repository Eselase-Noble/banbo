// Package ai optionally enriches findings using the Claude API: it turns each
// terse finding into a plain-English explanation, a business-impact sentence,
// and concrete step-by-step remediation. It is strictly optional — when no API
// key is configured, callers simply skip it and the report falls back to the
// static Description/Remediation baked into each finding.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Eselase-Noble/banbo/internal/config"
	"github.com/Eselase-Noble/banbo/internal/findings"
)

const (
	endpoint       = "https://api.anthropic.com/v1/messages"
	openAIEndpoint = "https://api.openai.com/v1/chat/completions"
	apiVersion     = "2023-06-01"
	maxEnrich      = 25 // cap findings sent to the model to control cost/latency
	requestTimeout = 60 * time.Second
)

// Enrich mutates up to maxEnrich of the highest-severity findings in place,
// adding AI explanation/impact/remediation. It returns the number enriched and
// any error. Callers should treat errors as non-fatal.
func Enrich(ctx context.Context, cfg config.Config, fs []findings.Finding) (int, error) {
	if !cfg.AIEnabled() || len(fs) == 0 {
		return 0, nil
	}

	// Select the most important findings (fs is already severity-sorted after
	// Dedupe, but we don't rely on that here).
	idx := make([]int, len(fs))
	for i := range fs {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return fs[idx[a]].Severity > fs[idx[b]].Severity })
	if len(idx) > maxEnrich {
		idx = idx[:maxEnrich]
	}

	type item struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Layer    string `json:"layer"`
		Severity string `json:"severity"`
		Asset    string `json:"asset"`
		Evidence string `json:"evidence"`
	}
	items := make([]item, 0, len(idx))
	for _, i := range idx {
		f := fs[i]
		items = append(items, item{f.ID, f.Title, string(f.Layer), f.Severity.String(), f.Asset, f.Evidence})
	}
	payload, _ := json.MarshalIndent(items, "", "  ")

	prompt := fmt.Sprintf(`You are a senior security engineer helping a Ghanaian organization understand a vulnerability scan.

For EACH finding below, write:
- "explanation": 1-2 plain-English sentences a non-technical manager can understand.
- "business_impact": one sentence on the concrete risk to the organization (fraud, data breach, downtime, regulatory exposure under the Bank of Ghana Cyber Directive or Data Protection Act 2012).
- "remediation": specific, ordered, actionable steps to fix it.

Return ONLY a JSON array, no prose, no markdown fences. Each element:
{"id": "<finding id>", "explanation": "...", "business_impact": "...", "remediation": "..."}

Findings:
%s`, string(payload))

	text, err := complete(ctx, cfg, prompt)
	if err != nil {
		return 0, err
	}

	var enriched []struct {
		ID             string `json:"id"`
		Explanation    string `json:"explanation"`
		BusinessImpact string `json:"business_impact"`
		Remediation    string `json:"remediation"`
	}
	if err := json.Unmarshal([]byte(extractJSON(text)), &enriched); err != nil {
		return 0, fmt.Errorf("could not parse AI response: %w", err)
	}

	byID := make(map[string]int, len(fs))
	for i := range fs {
		byID[fs[i].ID] = i
	}
	count := 0
	for _, e := range enriched {
		if i, ok := byID[e.ID]; ok {
			fs[i].AIExplanation = strings.TrimSpace(e.Explanation)
			fs[i].BusinessImpact = strings.TrimSpace(e.BusinessImpact)
			if r := strings.TrimSpace(e.Remediation); r != "" {
				fs[i].AIRemediation = r
			}
			count++
		}
	}
	return count, nil
}

// callClaude issues a single Messages API request and returns the text content.
func callClaude(ctx context.Context, cfg config.Config, prompt string) (string, error) {
	reqBody := map[string]any{
		"model":      cfg.Model,
		"max_tokens": 4000,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	}
	buf, _ := json.Marshal(reqBody)

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", cfg.APIKey)
	req.Header.Set("anthropic-version", apiVersion)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("claude API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, c := range parsed.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	return sb.String(), nil
}

// complete runs a single text completion against the configured provider,
// preferring Claude and falling back to OpenAI. If Claude is configured but the
// request fails and OpenAI is also configured, it retries on OpenAI so a
// transient Claude outage still yields enrichment.
func complete(ctx context.Context, cfg config.Config, prompt string) (string, error) {
	if cfg.HasClaude() {
		text, err := callClaude(ctx, cfg, prompt)
		if err == nil {
			return text, nil
		}
		if !cfg.HasOpenAI() {
			return "", err
		}
		// fall through to OpenAI
	}
	if cfg.HasOpenAI() {
		return callOpenAI(ctx, cfg, prompt)
	}
	return "", fmt.Errorf("no AI provider configured")
}

// callOpenAI issues a single Chat Completions request and returns the text
// content. It speaks the raw HTTP API to keep banbo dependency-light.
func callOpenAI(ctx context.Context, cfg config.Config, prompt string) (string, error) {
	reqBody := map[string]any{
		"model":      cfg.OpenAIModel,
		"max_tokens": 4000,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
	}
	buf, _ := json.Marshal(reqBody)

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIEndpoint, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+cfg.OpenAIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("openai API returned no choices")
	}
	return parsed.Choices[0].Message.Content, nil
}

// extractJSON pulls the JSON array out of a model response, tolerating stray
// markdown fences or surrounding prose.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}
