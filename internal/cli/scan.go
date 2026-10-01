package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Eselase-Noble/banbo/internal/ai"
	"github.com/Eselase-Noble/banbo/internal/compliance"
	"github.com/Eselase-Noble/banbo/internal/config"
	"github.com/Eselase-Noble/banbo/internal/findings"
	dnsmod "github.com/Eselase-Noble/banbo/internal/modules/dns"
	httpmod "github.com/Eselase-Noble/banbo/internal/modules/http"
	netmod "github.com/Eselase-Noble/banbo/internal/modules/network"
	tlsmod "github.com/Eselase-Noble/banbo/internal/modules/tls"
	"github.com/Eselase-Noble/banbo/internal/report"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

type scanFlags struct {
	output     string
	ports      string
	timeout    time.Duration
	active     bool
	authorized bool
	noColor    bool
	noAI       bool
}

func newScanCommand() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Scan a target (host, IP or URL) across all layers",
		Args:  cobra.ExactArgs(1),
		Example: `  banbo scan example.com.gh --i-am-authorized
  banbo scan https://app.example.com -o json > report.json
  banbo scan 192.0.2.10 --ports 22,80,443 --timeout 5s -y`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args[0], f)
		},
	}
	cmd.Flags().StringVarP(&f.output, "output", "o", "text", "output format: text or json")
	cmd.Flags().StringVar(&f.ports, "ports", "", "comma-separated ports to scan (default: common ports)")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 5*time.Second, "per-connection timeout")
	cmd.Flags().BoolVar(&f.active, "active", false, "enable deeper (still non-destructive) checks")
	cmd.Flags().BoolVarP(&f.authorized, "i-am-authorized", "y", false, "confirm you are authorized to scan the target")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "disable colored output")
	cmd.Flags().BoolVar(&f.noAI, "no-ai", false, "skip Claude AI enrichment even if an API key is configured")
	return cmd
}

func runScan(cmd *cobra.Command, rawTarget string, f *scanFlags) error {
	// Authorization gate — scanning without permission may be illegal.
	if !f.authorized {
		ok, err := confirmAuthorization(rawTarget)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("aborted: authorization not confirmed")
		}
	}

	ports, err := parsePorts(f.ports)
	if err != nil {
		return err
	}

	target, err := scanner.ParseTarget(rawTarget, ports, f.timeout, f.active)
	if err != nil {
		return err
	}

	// Graceful cancellation on Ctrl-C.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	s := scanner.New(
		dnsmod.New(),
		netmod.New(),
		tlsmod.New(),
		httpmod.New(),
	)

	// Progress goes to stderr so JSON on stdout stays clean.
	fmt.Fprintf(os.Stderr, "Scanning %s …\n", target.Host)
	res := s.Run(ctx, target, time.Now)

	// Compliance tagging (static, always on).
	compliance.Apply(res.Findings)

	// Optional AI enrichment.
	if !f.noAI {
		cfg, _ := config.Load()
		if cfg.AIEnabled() {
			fmt.Fprintln(os.Stderr, "Enriching findings with Claude …")
			if n, err := ai.Enrich(ctx, cfg, res.Findings); err != nil {
				fmt.Fprintf(os.Stderr, "AI enrichment skipped: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Enriched %d finding(s).\n", n)
			}
		} else {
			fmt.Fprintln(os.Stderr, "No API key configured — using built-in remediation guidance. (Run 'banbo config' for setup.)")
		}
	}

	// Render.
	switch strings.ToLower(f.output) {
	case "json":
		if err := report.JSON(os.Stdout, res); err != nil {
			return err
		}
	case "text", "":
		report.Text(os.Stdout, res, useColor(f.noColor))
	default:
		return fmt.Errorf("unknown output format %q (use text or json)", f.output)
	}

	// Exit code reflects worst severity so banbo is CI/CD friendly.
	switch findings.Worst(res.Findings) {
	case findings.SeverityCritical, findings.SeverityHigh:
		os.Exit(2)
	case findings.SeverityMedium, findings.SeverityLow:
		os.Exit(1)
	}
	return nil
}

// confirmAuthorization prints the legal notice and asks the operator to confirm.
func confirmAuthorization(target string) (bool, error) {
	fmt.Fprintln(os.Stderr, "⚠  LEGAL NOTICE")
	fmt.Fprintln(os.Stderr, "   Scanning systems without explicit authorization may be illegal.")
	fmt.Fprintf(os.Stderr, "   Only proceed if you own %q or have written permission to test it.\n", target)
	fmt.Fprint(os.Stderr, "   Are you authorized to scan this target? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		// Non-interactive (e.g. piped) with no confirmation: refuse.
		return false, nil
	}
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes", nil
}

// parsePorts turns "22,80,443" into []int. Empty input yields nil (defaults).
func parsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var ports []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// useColor decides whether to emit ANSI codes: off if requested, if NO_COLOR is
// set, or if stdout is not a terminal.
func useColor(noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
