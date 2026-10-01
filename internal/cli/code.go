package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Eselase-Noble/banbo/internal/ai"
	"github.com/Eselase-Noble/banbo/internal/codescan"
	"github.com/Eselase-Noble/banbo/internal/compliance"
	"github.com/Eselase-Noble/banbo/internal/config"
	"github.com/Eselase-Noble/banbo/internal/findings"
	"github.com/Eselase-Noble/banbo/internal/report"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

type codeFlags struct {
	output     string
	noColor    bool
	noAI       bool
	aiMaxFiles int
}

func newCodeCommand() *cobra.Command {
	f := &codeFlags{}
	cmd := &cobra.Command{
		Use:   "code [path]",
		Short: "Review source code for security issues (SAST + optional AI review)",
		Long: `Walk a directory of source code and report security problems: hardcoded
secrets, disabled TLS verification, injection-prone patterns, unsafe
deserialization and more. With a Claude API key configured, it also performs a
deeper AI-assisted security and quality review.

Defaults to the current directory.`,
		Args: cobra.MaximumNArgs(1),
		Example: `  banbo code .
  banbo code ./src -o json > code-report.json
  banbo code /path/to/project --no-ai`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runCode(path, f)
		},
	}
	cmd.Flags().StringVarP(&f.output, "output", "o", "text", "output format: text or json")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "disable colored output")
	cmd.Flags().BoolVar(&f.noAI, "no-ai", false, "skip Claude AI review even if an API key is configured")
	cmd.Flags().IntVar(&f.aiMaxFiles, "ai-max-files", 15, "max files to send for AI review")
	return cmd
}

func runCode(path string, f *codeFlags) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	fmt.Fprintf(os.Stderr, "Reviewing source in %s …\n", path)

	res, err := codescan.Scan(path)
	if err != nil {
		return err
	}
	all := res.Findings
	fmt.Fprintf(os.Stderr, "Scanned %d file(s); %d pattern finding(s).\n", res.FilesScanned, len(all))

	// Optional AI review.
	if !f.noAI {
		cfg, _ := config.Load()
		if cfg.AIEnabled() {
			files, _ := codescan.Collect(path)
			cfiles := make([]ai.CodeFile, 0, len(files))
			for _, s := range files {
				cfiles = append(cfiles, ai.CodeFile{Path: s.Path, Content: s.Content})
			}
			fmt.Fprintln(os.Stderr, "Running Claude code review …")
			reviewed, aiFindings, aerr := ai.ReviewCode(ctx, cfg, cfiles, f.aiMaxFiles)
			if aerr != nil {
				fmt.Fprintf(os.Stderr, "AI review skipped: %v\n", aerr)
			} else {
				fmt.Fprintf(os.Stderr, "AI reviewed %d file(s); %d finding(s).\n", reviewed, len(aiFindings))
				all = append(all, aiFindings...)
			}
		} else {
			fmt.Fprintln(os.Stderr, "No API key configured — running pattern rules only. (Run 'banbo config' for AI setup.)")
		}
	}

	all = findings.Dedupe(all)
	compliance.Apply(all)

	result := scanner.Result{
		Target:    path,
		Host:      path,
		StartedAt: start,
		Duration:  time.Since(start),
		Findings:  all,
		Summary:   findings.Summarize(all),
	}

	switch strings.ToLower(f.output) {
	case "json":
		if err := report.JSON(os.Stdout, result); err != nil {
			return err
		}
	case "text", "":
		report.Text(os.Stdout, result, useColor(f.noColor))
	default:
		return fmt.Errorf("unknown output format %q (use text or json)", f.output)
	}

	switch findings.Worst(all) {
	case findings.SeverityCritical, findings.SeverityHigh:
		os.Exit(2)
	case findings.SeverityMedium, findings.SeverityLow:
		os.Exit(1)
	}
	return nil
}
