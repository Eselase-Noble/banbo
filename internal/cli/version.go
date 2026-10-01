package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the banbo version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("banbo %s\n", Version)
			return nil
		},
	}
}
