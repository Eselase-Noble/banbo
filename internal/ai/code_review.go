package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Eselase-Noble/banbo/internal/config"
	"github.com/Eselase-Noble/banbo/internal/findings"
)

const (
	maxFileChars  = 12000 // per-file content cap sent to the model
	reviewWorkers = 4     // concurrent review requests
)

// CodeFile is a single file submitted for AI review.
type CodeFile struct {
	Path    string
	Content string
}

// reviewExts limits AI review to source files worth the tokens.
var reviewExts = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true,
	".go": true, ".py": true, ".rb": true, ".php": true, ".java": true, ".cs": true,
	".c": true, ".cpp": true, ".h": true, ".rs": true, ".sh": true, ".sql": true,
}

// ReviewCode asks Claude to review up to maxFiles source files for security and
// quality issues, returning normalized findings. It is a no-op (0 findings) when
// AI is not configured. Errors on individual files are skipped, not fatal.
func ReviewCode(ctx context.Context, cfg config.Config, files []CodeFile, maxFiles int) (int, []findings.Finding, error) {
	if !cfg.AIEnabled() {
		return 0, nil, nil
	}

	// Select reviewable files up to the cap.
	var selected []CodeFile
	for _, f := range files {
		if reviewExts[strings.ToLower(filepath.Ext(f.Path))] {
			selected = append(selected, f)
			if len(selected) >= maxFiles {
				break
			}
		}
	}
	if len(selected) == 0 {
		return 0, nil, nil
	}

	var (
		mu  sync.Mutex
		out []findings.Finding
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, reviewWorkers)

	for _, f := range selected {
		wg.Add(1)
		go func(f CodeFile) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			fs := reviewOne(ctx, cfg, f)
			if len(fs) > 0 {
				mu.Lock()
				out = append(out, fs...)
				mu.Unlock()
			}
		}(f)
	}
	wg.Wait()

	return len(selected), findings.Dedupe(out), nil
}

// reviewOne reviews a single file and parses the model's JSON response.
func reviewOne(ctx context.Context, cfg config.Config, f CodeFile) []findings.Finding {
	content := f.Content
	if len(content) > maxFileChars {
		content = content[:maxFileChars] + "\n/* …truncated for review… */"
	}

	prompt := fmt.Sprintf(`You are a senior application security engineer reviewing one source file for a Ghanaian organization. Identify REAL security vulnerabilities and serious code-quality issues (injection, auth/authorization flaws, secrets, unsafe deserialization, SSRF, path traversal, missing input validation, race conditions, etc.). Ignore trivial style nits.

Return ONLY a JSON array (no prose, no markdown fences). Each element:
{"line": <int>, "severity": "critical|high|medium|low|info", "title": "<short>", "explanation": "<1-2 sentences>", "remediation": "<concrete fix>"}
If there is nothing material, return [].

File: %s
Content:
%s`, f.Path, content)

	text, err := callClaude(ctx, cfg, prompt)
	if err != nil {
		return nil
	}

	var items []struct {
		Line        int    `json:"line"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Explanation string `json:"explanation"`
		Remediation string `json:"remediation"`
	}
	if err := json.Unmarshal([]byte(extractJSON(text)), &items); err != nil {
		return nil
	}

	out := make([]findings.Finding, 0, len(items))
	for _, it := range items {
		asset := f.Path
		if it.Line > 0 {
			asset = fmt.Sprintf("%s:%d", f.Path, it.Line)
		}
		out = append(out, findings.Finding{
			ID:            "ai-code-review",
			Title:         strings.TrimSpace(it.Title),
			Layer:         findings.LayerCode,
			Severity:      parseSeverity(it.Severity),
			Asset:         asset,
			AIExplanation: strings.TrimSpace(it.Explanation),
			AIRemediation: strings.TrimSpace(it.Remediation),
		})
	}
	return out
}

func parseSeverity(s string) findings.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return findings.SeverityCritical
	case "high":
		return findings.SeverityHigh
	case "medium":
		return findings.SeverityMedium
	case "low":
		return findings.SeverityLow
	default:
		return findings.SeverityInfo
	}
}
