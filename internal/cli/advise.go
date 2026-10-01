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
	"github.com/Eselase-Noble/banbo/internal/config"
	"github.com/Eselase-Noble/banbo/internal/findings"
	"github.com/Eselase-Noble/banbo/internal/report"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

type adviseFlags struct {
	output     string
	noColor    bool
	aiMaxFiles int
	full       bool
}

func newAdviseCommand() *cobra.Command {
	f := &adviseFlags{}
	cmd := &cobra.Command{
		Use:   "advise [path]",
		Short: "AI code advisor: recommend better data structures, algorithms, and design",
		Long: `Review a directory of source code and suggest how to write it better. Unlike
'banbo code' (which hunts for security and quality bugs), 'advise' focuses on
engineering craft:

  • data structures & algorithms (with Big-O reasoning)
  • performance & complexity
  • idiomatic design & readability
  • maintainability & tests
  • system design & design patterns

This command requires an AI provider key (Claude, or OpenAI as a fallback);
run 'banbo config' to set one up. Defaults to the current directory.`,
		Args: cobra.MaximumNArgs(1),
		Example: `  banbo advise .
  banbo advise ./src --full
  banbo advise . -o json > advice.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			return runAdvise(path, f)
		},
	}
	cmd.Flags().StringVarP(&f.output, "output", "o", "text", "output format: text or json")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "disable colored output")
	cmd.Flags().IntVar(&f.aiMaxFiles, "ai-max-files", 15, "max files to advise on (highest-risk first); ignored with --full")
	cmd.Flags().BoolVar(&f.full, "full", false, "advise on the ENTIRE codebase, not just the highest-value files")
	return cmd
}

func runAdvise(path string, f *adviseFlags) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot read %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}

	cfg, _ := config.Load()
	if !cfg.AIEnabled() {
		return fmt.Errorf("the advise command needs an AI provider key — set ANTHROPIC_API_KEY or OPENAI_API_KEY (run 'banbo config' for setup)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	fmt.Fprintf(os.Stderr, "Reviewing source in %s for engineering advice …\n", path)

	files, err := codescan.Collect(path)
	if err != nil {
		return err
	}

	project := codescan.DetectProject(path, files)
	ordered := codescan.RiskOrder(files, map[string]bool{})

	cfiles := make([]ai.CodeFile, 0, len(ordered))
	for _, s := range ordered {
		cfiles = append(cfiles, ai.CodeFile{Path: s.Path, Content: s.Content})
	}

	maxFiles := f.aiMaxFiles
	if f.full {
		maxFiles = 0
	}
	if summary := project.Summary(); summary != "" {
		fmt.Fprintf(os.Stderr, "Detected: %s\n", summary)
	}

	reviewed, advice, err := ai.Advise(ctx, cfg, cfiles, maxFiles, project.Summary())
	if err != nil {
		return fmt.Errorf("advice failed: %w", err)
	}
	all := findings.Dedupe(advice)

	eligible := 0
	for _, s := range ordered {
		if ai.Reviewable(s.Path) {
			eligible++
		}
	}
	fmt.Fprintf(os.Stderr, "Advised on %d of %d eligible source file(s); %d recommendation(s).\n", reviewed, eligible, len(all))
	if !f.full && reviewed < eligible {
		fmt.Fprintf(os.Stderr, "Note: %d file(s) not covered. Re-run with --full to advise on the entire codebase.\n", eligible-reviewed)
	}

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
		return report.JSON(os.Stdout, result)
	case "text", "":
		report.Text(os.Stdout, result, useColor(f.noColor))
	default:
		return fmt.Errorf("unknown output format %q (use text or json)", f.output)
	}
	// advise is guidance, not a pass/fail gate — always exit 0.
	return nil
}
