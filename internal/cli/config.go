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
			fmt.Printf("config file  : %s\n", path)
			fmt.Printf("claude model : %s\n", cfg.Model)
			fmt.Printf("openai model : %s\n", cfg.OpenAIModel)
			if cfg.AIEnabled() {
				fmt.Printf("AI enrichment: ENABLED (provider: %s)\n", cfg.Provider())
			} else {
				fmt.Println("AI enrichment: disabled (no API key)")
			}

			fmt.Println()
			fmt.Println("To enable AI-powered explanations and fixes, set a key for either")
			fmt.Println("provider (Claude is preferred, OpenAI is the fallback):")
			fmt.Println("  1) export BANBO_API_KEY=sk-ant-...        (or ANTHROPIC_API_KEY)")
			fmt.Println("     export OPENAI_API_KEY=sk-...           (or BANBO_OPENAI_API_KEY)")
			fmt.Printf("  2) create %s with:\n", path)
			fmt.Println(`     { "api_key": "sk-ant-...", "model": "claude-opus-4-8",`)
			fmt.Println(`       "openai_api_key": "sk-...", "openai_model": "gpt-4o-mini" }`)
			fmt.Println()
			fmt.Println("Without any key, banbo still works and uses built-in remediation guidance.")

			_ = os.Stdout.Sync()
			return nil
		},
	}
}
