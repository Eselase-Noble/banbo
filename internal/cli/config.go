package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Eselase-Noble/banbo/internal/config"
)

func newConfigCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Show configuration and how to enable AI enrichment",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := config.Load()
			path, _ := config.Path()

			fmt.Println("banbo configuration")
			fmt.Println("-------------------")
			fmt.Printf("config file : %s\n", path)
			fmt.Printf("model       : %s\n", cfg.Model)
			if cfg.AIEnabled() {
				fmt.Println("AI enrichment: ENABLED (API key found)")
			} else {
				fmt.Println("AI enrichment: disabled (no API key)")
			}

			fmt.Println()
			fmt.Println("To enable Claude-powered explanations and fixes, either:")
			fmt.Println("  1) export BANBO_API_KEY=sk-ant-...        (or ANTHROPIC_API_KEY)")
			fmt.Printf("  2) create %s with:\n", path)
			fmt.Println(`     { "api_key": "sk-ant-...", "model": "claude-opus-4-8" }`)
			fmt.Println()
			fmt.Println("Without a key, banbo still works and uses built-in remediation guidance.")

			_ = os.Stdout.Sync()
			return nil
		},
	}
}
