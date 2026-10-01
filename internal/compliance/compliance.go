// Package compliance tags findings with the Ghana-relevant controls they relate
// to, so a report can double as a lightweight compliance gap view. The mapping
// is intentionally coarse (MVP): it ties finding categories to the Bank of Ghana
// Cyber & Information Security Directive (CISD) and the Data Protection Act, 2012
// (Act 843). It is guidance, not a certified compliance assessment.
package compliance

import (
	"strings"

	"github.com/Eselase-Noble/banbo/internal/findings"
)

// rule maps a finding-id prefix to the compliance control tags it implicates.
type rule struct {
	prefix string
	tags   []string
}

// rules are evaluated in order; all matching prefixes contribute their tags.
var rules = []rule{
	{"tls-", []string{
		"BoG CISD: Encryption of data in transit",
		"Data Protection Act 2012 (Act 843) s.28: Security safeguards",
	}},
	{"http-", []string{
		"BoG CISD: Secure application configuration",
		"Data Protection Act 2012 (Act 843) s.28: Security safeguards",
	}},
	{"dns-", []string{
		"BoG CISD: Protection against email spoofing/phishing",
	}},
	{"net-open-port-", []string{
		"BoG CISD: Network segmentation & attack-surface management",
	}},
}

// Apply annotates each finding in place with any compliance tags it maps to.
func Apply(fs []findings.Finding) {
	for i := range fs {
		var tags []string
		for _, r := range rules {
			if strings.HasPrefix(fs[i].ID, r.prefix) {
				tags = append(tags, r.tags...)
			}
		}
		if len(tags) > 0 {
			fs[i].Compliance = tags
		}
	}
}
