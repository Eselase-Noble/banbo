// Package cli wires banbo's command-line interface together using Cobra.
package cli

import (
	"github.com/spf13/cobra"
)

// Version is overridden at build time via -ldflags "-X ...cli.Version=...".
var Version = "0.1.0-dev"

// NewRootCommand builds the top-level `banbo` command with its subcommands.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "banbo",
		Short: "banbo — layered security scanner (network → application) with AI-explained fixes",
		Long: `banbo scans a system across layers — DNS/email, network, transport (TLS) and
application (HTTP) — reports vulnerabilities with severity, maps them to Ghana's
Bank of Ghana Cyber Directive and Data Protection Act, 2012, and (optionally)
uses Claude to explain each issue and how to fix it in plain English.

Only scan systems you own or are explicitly authorized to test.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCommand())
	root.AddCommand(newCodeCommand())
	root.AddCommand(newConfigCommand())
	root.AddCommand(newVersionCommand())
	return root
}
