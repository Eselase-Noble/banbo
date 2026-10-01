// Package banbo is the public Go API for the banbo security scanner. It lets
// other Go programs run the same layered live-system scan and source-code audit
// that the banbo CLI performs, and receive the results as plain Go values.
//
// The heavy lifting lives in internal packages; this package is a small, stable
// facade with its own exported types so callers never depend on internal ones.
//
//	res, err := banbo.Scan(ctx, "example.com.gh", nil)
//	if err != nil { log.Fatal(err) }
//	for _, f := range res.Findings {
//	    fmt.Printf("[%s] %s (%s)\n", f.Severity, f.Title, f.Asset)
//	}
//
// AI enrichment (Claude, with OpenAI as a fallback) runs automatically when an
// API key is configured via the environment or ~/.banbo/config.json, unless
// DisableAI is set. See the banbo CLI docs for key configuration.
package banbo

import (
	"context"
	"time"

	"github.com/Eselase-Noble/banbo/internal/ai"
	"github.com/Eselase-Noble/banbo/internal/codescan"
	"github.com/Eselase-Noble/banbo/internal/compliance"
	"github.com/Eselase-Noble/banbo/internal/config"
	"github.com/Eselase-Noble/banbo/internal/findings"
	dnsmod "github.com/Eselase-Noble/banbo/internal/modules/dns"
	httpmod "github.com/Eselase-Noble/banbo/internal/modules/http"
	netmod "github.com/Eselase-Noble/banbo/internal/modules/network"
	tlsmod "github.com/Eselase-Noble/banbo/internal/modules/tls"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

// Severity ranks how urgently a finding should be addressed. Values are the
// lowercase labels also used in JSON: "info", "low", "medium", "high", "critical".
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Layer identifies which part of the stack a finding belongs to.
type Layer string

const (
	LayerDNS         Layer = "dns"
	LayerNetwork     Layer = "network"
	LayerTransport   Layer = "transport"
	LayerApplication Layer = "application"
	LayerCode        Layer = "code"
)

// Finding is a single normalized observation from a scan or code review.
type Finding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Layer          Layer    `json:"layer"`
	Severity       Severity `json:"severity"`
	Asset          string   `json:"asset"`
	Evidence       string   `json:"evidence,omitempty"`
	Description    string   `json:"description,omitempty"`
	Remediation    string   `json:"remediation,omitempty"`
	References     []string `json:"references,omitempty"`
	CVSS           float64  `json:"cvss,omitempty"`
	Compliance     []string `json:"compliance,omitempty"`
	AIExplanation  string   `json:"ai_explanation,omitempty"`
	AIRemediation  string   `json:"ai_remediation,omitempty"`
	BusinessImpact string   `json:"business_impact,omitempty"`
}

// Counts summarizes findings by severity.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// ModuleError records that a scan module failed without aborting the run.
type ModuleError struct {
	Module string `json:"module"`
	Error  string `json:"error"`
}

// Result is the full outcome of a scan or code review.
type Result struct {
	Target    string        `json:"target"`
	Host      string        `json:"host"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ms"`
	Findings  []Finding     `json:"findings"`
	Summary   Counts        `json:"summary"`
	Errors    []ModuleError `json:"errors,omitempty"`
}

// ScanOptions tunes a live-system scan. The zero value is valid: it scans the
// default common ports with a 5s per-connection timeout and runs AI enrichment
// when a key is configured.
type ScanOptions struct {
	Ports     []int         // ports to probe; nil means banbo's default common-ports set
	Timeout   time.Duration // per-connection timeout; 0 means 5s
	Active    bool          // enable deeper (still non-destructive) checks
	DisableAI bool          // skip AI enrichment even if a key is configured
}

// ReviewOptions tunes a source-code review. The zero value audits the 15
// highest-risk files with AI when a key is configured.
type ReviewOptions struct {
	DisableAI  bool // skip AI review (pattern rules only)
	Full       bool // AI-audit the entire codebase, not just the riskiest files
	AIMaxFiles int  // max files to AI-audit (highest-risk first); 0 with Full=false means 15
}

const defaultScanTimeout = 5 * time.Second
const defaultAIMaxFiles = 15

// Scan probes a live target (host, IP or URL) across the DNS, network,
// transport (TLS) and application (HTTP) layers, applies Ghana compliance
// mapping, optionally enriches findings with AI, and returns a normalized,
// de-duplicated Result.
//
// Only scan systems you own or are explicitly authorized to test.
func Scan(ctx context.Context, target string, opts *ScanOptions) (*Result, error) {
	if opts == nil {
		opts = &ScanOptions{}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultScanTimeout
	}

	t, err := scanner.ParseTarget(target, opts.Ports, timeout, opts.Active)
	if err != nil {
		return nil, err
	}

	s := scanner.New(dnsmod.New(), netmod.New(), tlsmod.New(), httpmod.New())
	res := s.Run(ctx, t, time.Now)

	compliance.Apply(res.Findings)
	if !opts.DisableAI {
		if cfg, _ := config.Load(); cfg.AIEnabled() {
			_, _ = ai.Enrich(ctx, cfg, res.Findings) // best-effort; non-fatal
		}
	}
	return convertResult(res), nil
}

// ReviewCode audits a directory of source code for security issues using
// built-in pattern rules and, when an API key is configured, a deeper AI
// review. It returns a normalized, de-duplicated Result.
func ReviewCode(ctx context.Context, path string, opts *ReviewOptions) (*Result, error) {
	if opts == nil {
		opts = &ReviewOptions{}
	}
	start := time.Now()

	res, err := codescan.Scan(path)
	if err != nil {
		return nil, err
	}
	all := res.Findings

	if !opts.DisableAI {
		if cfg, _ := config.Load(); cfg.AIEnabled() {
			files, _ := codescan.Collect(path)
			project := codescan.DetectProject(path, files)
			flagged := flaggedFiles(all)
			ordered := codescan.RiskOrder(files, flagged)

			cfiles := make([]ai.CodeFile, 0, len(ordered))
			for _, sf := range ordered {
				cfiles = append(cfiles, ai.CodeFile{Path: sf.Path, Content: sf.Content})
			}

			maxFiles := opts.AIMaxFiles
			if maxFiles <= 0 {
				maxFiles = defaultAIMaxFiles
			}
			if opts.Full {
				maxFiles = 0 // audit everything
			}
			if _, aiFindings, aerr := ai.ReviewCode(ctx, cfg, cfiles, maxFiles, project.Summary()); aerr == nil {
				all = append(all, aiFindings...)
			}
		}
	}

	all = findings.Dedupe(all)
	compliance.Apply(all)

	return convertResult(scanner.Result{
		Target:    path,
		Host:      path,
		StartedAt: start,
		Duration:  time.Since(start),
		Findings:  all,
		Summary:   findings.Summarize(all),
	}), nil
}

// flaggedFiles returns the set of file paths that already have pattern findings.
func flaggedFiles(fs []findings.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		if f.Layer != findings.LayerCode {
			continue
		}
		path := f.Asset
		if i := lastColon(path); i > 0 {
			path = path[:i]
		}
		out[path] = true
	}
	return out
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// convertResult maps the internal scanner.Result into the public Result type so
// callers never depend on internal packages.
func convertResult(r scanner.Result) *Result {
	out := &Result{
		Target:    r.Target,
		Host:      r.Host,
		StartedAt: r.StartedAt,
		Duration:  r.Duration,
		Summary:   Counts(r.Summary),
		Findings:  make([]Finding, 0, len(r.Findings)),
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, Finding{
			ID:             f.ID,
			Title:          f.Title,
			Layer:          Layer(f.Layer),
			Severity:       Severity(f.Severity.String()),
			Asset:          f.Asset,
			Evidence:       f.Evidence,
			Description:    f.Description,
			Remediation:    f.Remediation,
			References:     f.References,
			CVSS:           f.CVSS,
			Compliance:     f.Compliance,
			AIExplanation:  f.AIExplanation,
			AIRemediation:  f.AIRemediation,
			BusinessImpact: f.BusinessImpact,
		})
	}
	for _, e := range r.Errors {
		out.Errors = append(out.Errors, ModuleError{Module: e.Module, Error: e.Err})
	}
	return out
}
