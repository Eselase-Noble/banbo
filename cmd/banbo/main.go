// Command banbo is a layered security scanner: it probes a target across the
// DNS, network, transport (TLS) and application (HTTP) layers, reports
// vulnerabilities with severity and Ghana-relevant compliance mapping, and can
// use Claude to explain each finding and its fix in plain English.
package main

import (
	"fmt"
	"os"

	"github.com/Eselase-Noble/banbo/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
