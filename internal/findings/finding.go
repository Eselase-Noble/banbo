// Package findings defines the normalized result type that every scan module
// produces. Keeping a single shared shape means the orchestrator, reporters,
// AI enrichment and compliance mapper never need to know which module a result
// came from.
package findings

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Severity ranks how urgently a finding should be addressed.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the lowercase label for a severity.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// MarshalJSON renders the severity as its label rather than an integer.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Layer identifies which part of the stack a finding belongs to. This drives
// the layer-by-layer grouping in reports (network -> application).
type Layer string

const (
	LayerDNS         Layer = "dns"
	LayerNetwork     Layer = "network"
	LayerTransport   Layer = "transport"
	LayerApplication Layer = "application"
)

// Order returns a stable sort rank so reports read bottom-up through the stack.
func (l Layer) Order() int {
	switch l {
	case LayerDNS:
		return 0
	case LayerNetwork:
		return 1
	case LayerTransport:
		return 2
	case LayerApplication:
		return 3
	default:
		return 4
	}
}

// Finding is a single normalized observation from a scan module. Fields in the
// "enrichment" group are populated later by the AI and compliance passes and
// are safe to leave empty.
type Finding struct {
	ID       string   `json:"id"`                 // stable check id, e.g. "http-missing-hsts"
	Title    string   `json:"title"`              // short human headline
	Layer    Layer    `json:"layer"`              // network / transport / application / dns
	Severity Severity `json:"severity"`           // how urgent
	Asset    string   `json:"asset"`              // host:port or URL the finding applies to
	Evidence string   `json:"evidence,omitempty"` // what we actually observed

	Description string   `json:"description,omitempty"` // static baseline explanation
	Remediation string   `json:"remediation,omitempty"` // static baseline fix
	References  []string `json:"references,omitempty"`  // links to standards/CVEs
	CVSS        float64  `json:"cvss,omitempty"`        // 0-10 if known

	// Enrichment — filled in by later passes, optional.
	Compliance     []string `json:"compliance,omitempty"`      // mapped control tags
	AIExplanation  string   `json:"ai_explanation,omitempty"`  // Claude plain-English explanation
	AIRemediation  string   `json:"ai_remediation,omitempty"`  // Claude step-by-step fix
	BusinessImpact string   `json:"business_impact,omitempty"` // Claude business-impact summary
}

// Key is used to de-duplicate findings that multiple modules might report for
// the same issue on the same asset.
func (f Finding) Key() string {
	return fmt.Sprintf("%s|%s", f.ID, f.Asset)
}

// Dedupe removes duplicate findings (same check on the same asset), keeping the
// highest-severity copy, and returns a stable, report-ready ordering:
// severity desc, then layer bottom-up, then asset.
func Dedupe(in []Finding) []Finding {
	best := make(map[string]Finding, len(in))
	for _, f := range in {
		if existing, ok := best[f.Key()]; !ok || f.Severity > existing.Severity {
			best[f.Key()] = f
		}
	}
	out := make([]Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Layer.Order() != out[j].Layer.Order() {
			return out[i].Layer.Order() < out[j].Layer.Order()
		}
		return out[i].Asset < out[j].Asset
	})
	return out
}

// Counts summarizes findings by severity for headline reporting.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Summarize tallies a slice of findings by severity.
func Summarize(fs []Finding) Counts {
	var c Counts
	for _, f := range fs {
		switch f.Severity {
		case SeverityCritical:
			c.Critical++
		case SeverityHigh:
			c.High++
		case SeverityMedium:
			c.Medium++
		case SeverityLow:
			c.Low++
		default:
			c.Info++
		}
	}
	c.Total = len(fs)
	return c
}

// Worst returns the highest severity present, or SeverityInfo if empty. Used to
// set the process exit code so the tool is CI/CD friendly.
func Worst(fs []Finding) Severity {
	worst := SeverityInfo
	for _, f := range fs {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}
