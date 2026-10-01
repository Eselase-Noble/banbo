// Package dns checks email-security DNS records (SPF and DMARC) which, when
// missing or weak, let attackers spoof mail from the domain — a very common
// vector for fraud and phishing. Lookups are ordinary DNS queries.
package dns

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Eselase-Noble/banbo/internal/findings"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

// Module performs DNS email-security checks.
type Module struct{}

// New returns a DNS scan module.
func New() *Module { return &Module{} }

// Name identifies the module.
func (m *Module) Name() string { return "dns" }

// Scan inspects SPF and DMARC records for the target domain. IP targets are
// skipped since they have no email domain policy to evaluate.
func (m *Module) Scan(ctx context.Context, t scanner.Target) ([]findings.Finding, error) {
	if t.IsIP() || t.Host == "" {
		return nil, nil
	}
	domain := apexish(t.Host)
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resolver := &net.Resolver{}
	var out []findings.Finding

	// SPF — a TXT record beginning with "v=spf1".
	txts, _ := resolver.LookupTXT(ctx, domain)
	spf := firstWithPrefix(txts, "v=spf1")
	switch {
	case spf == "":
		out = append(out, findings.Finding{
			ID: "dns-spf-missing", Title: "No SPF record published",
			Layer: findings.LayerDNS, Severity: findings.SeverityMedium, Asset: domain,
			Evidence:    "no TXT record starting with 'v=spf1' was found",
			Description: "Without SPF, receivers cannot verify which servers may send mail for your domain, making spoofing easy.",
			Remediation: "Publish an SPF TXT record listing authorized senders and ending in '-all' (hard fail).",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7208"},
		})
	case strings.Contains(spf, "+all"):
		out = append(out, findings.Finding{
			ID: "dns-spf-permissive", Title: "SPF record is dangerously permissive (+all)",
			Layer: findings.LayerDNS, Severity: findings.SeverityHigh, Asset: domain,
			Evidence:    spf,
			Description: "An SPF policy of '+all' authorizes the entire internet to send mail as your domain.",
			Remediation: "Replace '+all' with '-all' (hard fail) or '~all' (soft fail) and list only legitimate senders.",
		})
	}

	// DMARC — a TXT record at _dmarc.<domain>.
	dmarcTXT, _ := resolver.LookupTXT(ctx, "_dmarc."+domain)
	dmarc := firstWithPrefix(dmarcTXT, "v=DMARC1")
	switch {
	case dmarc == "":
		out = append(out, findings.Finding{
			ID: "dns-dmarc-missing", Title: "No DMARC record published",
			Layer: findings.LayerDNS, Severity: findings.SeverityMedium, Asset: "_dmarc." + domain,
			Evidence:    "no TXT record starting with 'v=DMARC1' was found",
			Description: "Without DMARC, there is no policy telling receivers what to do with mail that fails SPF/DKIM, enabling spoofing and phishing.",
			Remediation: "Publish a DMARC record at _dmarc." + domain + ", starting with 'p=none' for monitoring and moving to 'p=reject'.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc7489"},
		})
	case strings.Contains(strings.ToLower(dmarc), "p=none"):
		out = append(out, findings.Finding{
			ID: "dns-dmarc-monitor-only", Title: "DMARC policy is monitor-only (p=none)",
			Layer: findings.LayerDNS, Severity: findings.SeverityLow, Asset: "_dmarc." + domain,
			Evidence:    dmarc,
			Description: "A DMARC policy of 'p=none' only reports abuse; it does not stop spoofed mail from being delivered.",
			Remediation: "After reviewing DMARC reports, tighten the policy to 'p=quarantine' and then 'p=reject'.",
		})
	}

	return out, nil
}

// firstWithPrefix returns the first record (case-insensitive) whose trimmed form
// begins with prefix.
func firstWithPrefix(records []string, prefix string) string {
	lp := strings.ToLower(prefix)
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), lp) {
			return strings.TrimSpace(r)
		}
	}
	return ""
}

// apexish strips a leading "www." so that, e.g., www.example.com is checked as
// example.com. It is a heuristic, not a full public-suffix parse.
func apexish(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	host = strings.TrimPrefix(host, "www.")
	return host
}
