// Package report renders a scan Result for humans (colorized terminal) and
// machines (JSON). Findings are grouped by layer so the output reads bottom-up
// through the stack: dns -> network -> transport -> application.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Eselase-Noble/banbo/internal/findings"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

// ANSI color codes; disabled when useColor is false.
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	purple = "\033[35m"
	cyan   = "\033[36m"
)

// colorizer applies (or strips) ANSI codes.
type colorizer struct{ on bool }

func (c colorizer) wrap(code, s string) string {
	if !c.on {
		return s
	}
	return code + s + reset
}

func severityColor(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical:
		return purple
	case findings.SeverityHigh:
		return red
	case findings.SeverityMedium:
		return yellow
	case findings.SeverityLow:
		return blue
	default:
		return dim
	}
}

// JSON writes the result as indented JSON.
func JSON(w io.Writer, res scanner.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// Text writes a colorized, human-readable report. Set useColor=false for plain
// output (e.g. when piping to a file).
func Text(w io.Writer, res scanner.Result, useColor bool) {
	c := colorizer{on: useColor}

	fmt.Fprintln(w, c.wrap(bold+cyan, "┌─ banbo security scan ─────────────────────────────"))
	fmt.Fprintf(w, "%s  target : %s\n", c.wrap(cyan, "│"), res.Target)
	fmt.Fprintf(w, "%s  host   : %s\n", c.wrap(cyan, "│"), res.Host)
	fmt.Fprintf(w, "%s  took   : %s\n", c.wrap(cyan, "│"), res.Duration.Round(1e6))
	fmt.Fprintln(w, c.wrap(bold+cyan, "└───────────────────────────────────────────────────"))
	fmt.Fprintln(w)

	// Headline summary line.
	s := res.Summary
	fmt.Fprintf(w, "%s %s  %s  %s  %s  %s\n\n",
		c.wrap(bold, "Summary:"),
		c.wrap(purple, fmt.Sprintf("%d critical", s.Critical)),
		c.wrap(red, fmt.Sprintf("%d high", s.High)),
		c.wrap(yellow, fmt.Sprintf("%d medium", s.Medium)),
		c.wrap(blue, fmt.Sprintf("%d low", s.Low)),
		c.wrap(dim, fmt.Sprintf("%d info", s.Info)),
	)

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, c.wrap(green, "No findings. (Note: a clean scan is not a guarantee of security.)"))
	}

	// Group findings by layer, preserving the bottom-up layer order.
	byLayer := map[findings.Layer][]findings.Finding{}
	for _, f := range res.Findings {
		byLayer[f.Layer] = append(byLayer[f.Layer], f)
	}
	layers := []findings.Layer{findings.LayerDNS, findings.LayerNetwork, findings.LayerTransport, findings.LayerApplication, findings.LayerCode, findings.LayerAdvice}
	for _, layer := range layers {
		fs := byLayer[layer]
		if len(fs) == 0 {
			continue
		}
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
		fmt.Fprintln(w, c.wrap(bold+cyan, "▸ "+layerTitle(layer)))
		for _, f := range fs {
			printFinding(w, c, f)
		}
		fmt.Fprintln(w)
	}

	if len(res.Errors) > 0 {
		fmt.Fprintln(w, c.wrap(dim, "Module notes:"))
		for _, e := range res.Errors {
			fmt.Fprintf(w, "  %s %s: %s\n", c.wrap(dim, "-"), e.Module, e.Err)
		}
	}
}

func printFinding(w io.Writer, c colorizer, f findings.Finding) {
	tag := c.wrap(bold+severityColor(f.Severity), strings.ToUpper(f.Severity.String()))
	fmt.Fprintf(w, "  [%s] %s\n", tag, c.wrap(bold, f.Title))
	fmt.Fprintf(w, "        %s %s\n", c.wrap(dim, "asset:"), f.Asset)
	if f.Evidence != "" {
		fmt.Fprintf(w, "        %s %s\n", c.wrap(dim, "evidence:"), f.Evidence)
	}

	// Prefer the AI explanation when present, else the static description.
	if f.AIExplanation != "" {
		fmt.Fprintf(w, "        %s %s\n", c.wrap(dim, "what:"), f.AIExplanation)
	} else if f.Description != "" {
		fmt.Fprintf(w, "        %s %s\n", c.wrap(dim, "what:"), f.Description)
	}
	if f.BusinessImpact != "" {
		fmt.Fprintf(w, "        %s %s\n", c.wrap(dim, "impact:"), f.BusinessImpact)
	}

	remediation := f.Remediation
	if f.AIRemediation != "" {
		remediation = f.AIRemediation
	}
	if remediation != "" {
		fmt.Fprintf(w, "        %s %s\n", c.wrap(green, "fix:"), indentFollow(remediation))
	}
	if len(f.Compliance) > 0 {
		fmt.Fprintf(w, "        %s %s\n", c.wrap(dim, "compliance:"), strings.Join(f.Compliance, "; "))
	}
	fmt.Fprintln(w)
}

// indentFollow keeps multi-line remediation aligned under the "fix:" label.
func indentFollow(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := 1; i < len(lines); i++ {
		lines[i] = "              " + strings.TrimSpace(lines[i])
	}
	return strings.Join(lines, "\n")
}

func layerTitle(l findings.Layer) string {
	switch l {
	case findings.LayerDNS:
		return "DNS / Email security"
	case findings.LayerNetwork:
		return "Network layer"
	case findings.LayerTransport:
		return "Transport layer (TLS)"
	case findings.LayerApplication:
		return "Application layer (HTTP)"
	case findings.LayerCode:
		return "Source code review"
	case findings.LayerAdvice:
		return "Design & engineering advice"
	default:
		return string(l)
	}
}
