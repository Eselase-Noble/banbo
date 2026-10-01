// Package http checks application-layer HTTP hygiene: missing security response
// headers, verbose server/version disclosure, insecure cookie flags, and overly
// permissive CORS. It performs a single GET request and inspects the response —
// no fuzzing, no payloads.
package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Eselase-Noble/banbo/internal/findings"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

// Module performs HTTP security-header and response checks.
type Module struct{}

// New returns an HTTP scan module.
func New() *Module { return &Module{} }

// Name identifies the module.
func (m *Module) Name() string { return "http" }

// headerCheck describes a security header we expect and the finding to raise if
// it is absent.
type headerCheck struct {
	header      string
	id          string
	title       string
	severity    findings.Severity
	description string
	remediation string
}

var expectedHeaders = []headerCheck{
	{
		header: "Strict-Transport-Security", id: "http-missing-hsts",
		title: "Missing HTTP Strict-Transport-Security (HSTS)", severity: findings.SeverityMedium,
		description: "Without HSTS, browsers can be downgraded to plain HTTP, exposing users to man-in-the-middle attacks.",
		remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS responses.",
	},
	{
		header: "Content-Security-Policy", id: "http-missing-csp",
		title: "Missing Content-Security-Policy (CSP)", severity: findings.SeverityMedium,
		description: "A Content-Security-Policy is a primary defense against cross-site scripting (XSS) and data injection.",
		remediation: "Define a Content-Security-Policy restricting script, style and frame sources to trusted origins.",
	},
	{
		header: "X-Frame-Options", id: "http-missing-xfo",
		title: "Missing X-Frame-Options / frame-ancestors", severity: findings.SeverityLow,
		description: "Without clickjacking protection, the site can be embedded in a malicious frame.",
		remediation: "Set 'X-Frame-Options: DENY' (or a CSP 'frame-ancestors' directive).",
	},
	{
		header: "X-Content-Type-Options", id: "http-missing-xcto",
		title: "Missing X-Content-Type-Options", severity: findings.SeverityLow,
		description: "Browsers may MIME-sniff responses, enabling some content-type confusion attacks.",
		remediation: "Set 'X-Content-Type-Options: nosniff' on all responses.",
	},
	{
		header: "Referrer-Policy", id: "http-missing-referrer-policy",
		title: "Missing Referrer-Policy", severity: findings.SeverityInfo,
		description: "A permissive referrer policy can leak URLs (and any secrets in them) to third parties.",
		remediation: "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
	},
}

// Scan requests the target over HTTPS (falling back to the scheme the user gave)
// and evaluates the response.
func (m *Module) Scan(ctx context.Context, t scanner.Target) ([]findings.Finding, error) {
	if t.Host == "" {
		return nil, fmt.Errorf("no host to scan")
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	scheme := t.Scheme
	if scheme == "" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s", scheme, t.Host)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// We are auditing, so do not fail on cert problems here — the TLS
			// module reports certificate issues separately.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "banbo-scanner/0.1 (+security audit)")
	// A benign Origin lets us observe CORS reflection without being intrusive.
	req.Header.Set("Origin", "https://banbo-probe.example")

	resp, err := client.Do(req)
	if err != nil {
		// Target may simply not serve HTTP; not a scan-level error.
		return nil, nil
	}
	defer resp.Body.Close()

	asset := url
	var out []findings.Finding

	// Missing security headers.
	for _, hc := range expectedHeaders {
		if resp.Header.Get(hc.header) == "" {
			out = append(out, findings.Finding{
				ID: hc.id, Title: hc.title, Layer: findings.LayerApplication,
				Severity: hc.severity, Asset: asset,
				Evidence:    fmt.Sprintf("response from %s did not include %s", url, hc.header),
				Description: hc.description, Remediation: hc.remediation,
				References: []string{"https://owasp.org/www-project-secure-headers/"},
			})
		}
	}

	// Server/version disclosure.
	if server := resp.Header.Get("Server"); server != "" && hasVersion(server) {
		out = append(out, findings.Finding{
			ID: "http-server-version-disclosure", Title: "Server banner discloses software version",
			Layer: findings.LayerApplication, Severity: findings.SeverityLow, Asset: asset,
			Evidence:    "Server: " + server,
			Description: "Exposing exact software versions helps attackers match known exploits to your stack.",
			Remediation: "Suppress or genericize the 'Server' header (and 'X-Powered-By') at the web server or proxy.",
		})
	}
	if xp := resp.Header.Get("X-Powered-By"); xp != "" {
		out = append(out, findings.Finding{
			ID: "http-x-powered-by", Title: "X-Powered-By header discloses technology",
			Layer: findings.LayerApplication, Severity: findings.SeverityInfo, Asset: asset,
			Evidence:    "X-Powered-By: " + xp,
			Description: "The X-Powered-By header reveals backend technology unnecessarily.",
			Remediation: "Remove the 'X-Powered-By' header.",
		})
	}

	// Overly permissive CORS.
	if aco := resp.Header.Get("Access-Control-Allow-Origin"); aco == "*" {
		out = append(out, findings.Finding{
			ID: "http-cors-wildcard", Title: "Permissive CORS (Access-Control-Allow-Origin: *)",
			Layer: findings.LayerApplication, Severity: findings.SeverityMedium, Asset: asset,
			Evidence:    "Access-Control-Allow-Origin: *",
			Description: "A wildcard CORS policy lets any website read responses; combined with credentials this can leak data.",
			Remediation: "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins.",
			References:  []string{"https://developer.mozilla.org/docs/Web/HTTP/CORS"},
		})
	}

	// Insecure cookies.
	for _, c := range resp.Cookies() {
		var missing []string
		if !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if len(missing) > 0 {
			out = append(out, findings.Finding{
				ID: "http-insecure-cookie", Title: "Cookie missing security flags",
				Layer: findings.LayerApplication, Severity: findings.SeverityLow,
				Asset:       asset + " (cookie: " + c.Name + ")",
				Evidence:    fmt.Sprintf("cookie %q is missing: %s", c.Name, strings.Join(missing, ", ")),
				Description: "Cookies without Secure/HttpOnly can be stolen over plaintext or via client-side scripts.",
				Remediation: "Set the Secure and HttpOnly flags (and SameSite) on session and auth cookies.",
			})
		}
	}

	return out, nil
}

// hasVersion heuristically detects a version number inside a Server banner.
func hasVersion(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '/' && s[i+1] >= '0' && s[i+1] <= '9' {
			return true
		}
	}
	return false
}
