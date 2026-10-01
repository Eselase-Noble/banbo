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

// Advise asks the configured AI provider to review source files for software
// engineering quality — not security — and returns actionable recommendations
// across data structures & algorithms, performance/complexity, idiomatic design,
// maintainability & tests, and system design & patterns. It mirrors ReviewCode's
// concurrency and file selection, and is a no-op when AI is not configured.
func Advise(ctx context.Context, cfg config.Config, files []CodeFile, maxFiles int, projectContext string) (int, []findings.Finding, error) {
	if !cfg.AIEnabled() {
		return 0, nil, nil
	}

	var selected []CodeFile
	for _, f := range files {
		if !reviewExts[strings.ToLower(filepath.Ext(f.Path))] {
			continue
		}
		selected = append(selected, f)
		if maxFiles > 0 && len(selected) >= maxFiles {
			break
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
			fs := adviseOne(ctx, cfg, f, projectContext)
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

// adviseOne reviews a single file for engineering-quality improvements.
func adviseOne(ctx context.Context, cfg config.Config, f CodeFile, projectContext string) []findings.Finding {
	content := f.Content
	if len(content) > maxFileChars {
		content = content[:maxFileChars] + "\n/* …truncated for review… */"
	}

	ctxLine := ""
	if projectContext != "" {
		ctxLine = "Project context: " + projectContext + "\n\n"
	}

	prompt := fmt.Sprintf(`You are a principal software engineer and architect doing a constructive code review to help the author write better software. Review the source file below and suggest concrete, high-value improvements across these dimensions:
- "data-structures": a better-suited data structure or algorithm (give Big-O reasoning where relevant).
- "performance": complexity/performance issues — hot loops, needless allocations/copies, N+1 patterns, quadratic behavior — and faster approaches.
- "design": more idiomatic, readable, or simpler equivalents in this language.
- "maintainability": coupling, duplication, error handling, and test-coverage gaps worth addressing.
- "architecture": system design and design-pattern improvements (the right pattern to apply, or an over-engineered one to drop).

Only material, actionable advice — skip trivial style nits and anything purely cosmetic. If the code is already sound, return [].

Return ONLY a JSON array (no prose, no markdown fences). Each element:
{"line": <int>, "category": "data-structures|performance|design|maintainability|architecture", "priority": "high|medium|low", "title": "<short recommendation>", "explanation": "<why it matters, 1-2 sentences>", "recommendation": "<specifically what to change>"}

%sFile: %s
Content:
%s`, ctxLine, f.Path, content)

	text, err := complete(ctx, cfg, prompt)
	if err != nil {
		return nil
	}

	var items []struct {
		Line           int    `json:"line"`
		Category       string `json:"category"`
		Priority       string `json:"priority"`
		Title          string `json:"title"`
		Explanation    string `json:"explanation"`
		Recommendation string `json:"recommendation"`
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
			ID:            "ai-advice",
			Title:         strings.TrimSpace(it.Title),
			Layer:         findings.LayerAdvice,
			Severity:      parsePriority(it.Priority),
			Asset:         asset,
			Evidence:      categoryLabel(it.Category),
			AIExplanation: strings.TrimSpace(it.Explanation),
			AIRemediation: strings.TrimSpace(it.Recommendation),
		})
	}
	return out
}

// parsePriority maps an advice priority to the shared severity scale so the
// existing reporter can render and sort it (high > medium > low).
func parsePriority(p string) findings.Severity {
	switch strings.ToLower(strings.TrimSpace(p)) {
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

// categoryLabel turns a machine category into a human label shown as the
// finding's "evidence" line.
func categoryLabel(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "data-structures":
		return "Data structures & algorithms"
	case "performance":
		return "Performance & complexity"
	case "design":
		return "Idiomatic design & readability"
	case "maintainability":
		return "Maintainability & tests"
	case "architecture":
		return "System design & patterns"
	default:
		return "Advice"
	}
}
