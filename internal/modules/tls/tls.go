// Package tls inspects a host's TLS/SSL configuration: certificate validity and
// expiry, and whether the server still accepts legacy protocol versions
// (TLS 1.0 / 1.1). All checks are passive handshakes — nothing is sent beyond a
// normal client hello.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/Eselase-Noble/banbo/internal/findings"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

// Module performs TLS configuration checks.
type Module struct{}

// New returns a TLS scan module.
func New() *Module { return &Module{} }

// Name identifies the module.
func (m *Module) Name() string { return "tls" }

// Scan checks the primary HTTPS port (443) for the target host.
func (m *Module) Scan(ctx context.Context, t scanner.Target) ([]findings.Finding, error) {
	if t.Host == "" {
		return nil, fmt.Errorf("no host to scan")
	}
	// For the MVP we focus on 443. The network module surfaces other TLS ports.
	port := 443
	addr := net.JoinHostPort(t.Host, fmt.Sprintf("%d", port))
	asset := addr

	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var out []findings.Finding

	// 1) Normal handshake to read the certificate chain.
	cert, err := leafCertificate(ctx, addr, t.Host, timeout)
	if err != nil {
		// No TLS on 443 is itself worth noting at info level, but not an error
		// that should abort the scan.
		return nil, nil
	}

	now := time.Now()
	switch {
	case now.After(cert.NotAfter):
		out = append(out, findings.Finding{
			ID: "tls-cert-expired", Title: "TLS certificate has expired",
			Layer: findings.LayerTransport, Severity: findings.SeverityHigh, Asset: asset,
			Evidence:    fmt.Sprintf("certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
			Description: "The server is presenting an expired TLS certificate. Browsers and clients will show security warnings or refuse to connect.",
			Remediation: "Renew and install a valid certificate (e.g. via Let's Encrypt or your CA) and automate renewal.",
			References:  []string{"https://letsencrypt.org/"},
		})
	case now.Add(21 * 24 * time.Hour).After(cert.NotAfter):
		out = append(out, findings.Finding{
			ID: "tls-cert-expiring", Title: "TLS certificate expires soon",
			Layer: findings.LayerTransport, Severity: findings.SeverityMedium, Asset: asset,
			Evidence:    fmt.Sprintf("certificate expires on %s", cert.NotAfter.Format("2006-01-02")),
			Description: "The TLS certificate will expire within 21 days.",
			Remediation: "Renew the certificate now and verify automated renewal is working.",
		})
	}

	// 2) Probe legacy protocol versions. If a handshake succeeds with a max
	// version pinned to an old protocol, the server still accepts it.
	for _, lv := range []struct {
		name string
		ver  uint16
	}{
		{"TLS 1.0", tls.VersionTLS10},
		{"TLS 1.1", tls.VersionTLS11},
	} {
		if acceptsVersion(ctx, addr, t.Host, lv.ver, timeout) {
			out = append(out, findings.Finding{
				ID: "tls-legacy-" + sanitizeVer(lv.name), Title: "Server accepts legacy " + lv.name,
				Layer: findings.LayerTransport, Severity: findings.SeverityMedium, Asset: asset,
				Evidence:    fmt.Sprintf("handshake succeeded using %s", lv.name),
				Description: lv.name + " is deprecated and has known weaknesses. Modern clients should use TLS 1.2 or 1.3.",
				Remediation: "Disable TLS 1.0 and 1.1 on the server; require TLS 1.2 as a minimum (TLS 1.3 preferred).",
				References:  []string{"https://datatracker.ietf.org/doc/rfc8996/"},
			})
		}
	}

	return out, nil
}

// leafCertificate performs a standard handshake and returns the server's leaf
// certificate. InsecureSkipVerify is set only so we can still inspect expired or
// self-signed certs — we are auditing, not trusting.
func leafCertificate(ctx context.Context, addr, serverName string, timeout time.Duration) (cert leaf, err error) {
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return leaf{}, err
	}
	conn := tls.Client(raw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.HandshakeContext(ctx); err != nil {
		return leaf{}, err
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return leaf{}, fmt.Errorf("no peer certificates")
	}
	return leaf{NotAfter: certs[0].NotAfter}, nil
}

// leaf is the small subset of certificate data we need.
type leaf struct {
	NotAfter time.Time
}

// acceptsVersion reports whether the server completes a handshake when the
// client is pinned to exactly one legacy protocol version.
func acceptsVersion(ctx context.Context, addr, serverName string, ver uint16, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         ver,
		MaxVersion:         ver,
	})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn.HandshakeContext(ctx) == nil
}

func sanitizeVer(name string) string {
	switch name {
	case "TLS 1.0":
		return "tls10"
	case "TLS 1.1":
		return "tls11"
	default:
		return "legacy"
	}
}
