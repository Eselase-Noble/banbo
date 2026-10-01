// Package network implements a non-intrusive TCP connect port scan. It opens a
// normal TCP connection to each port (the same thing any client does), so it is
// safe and does not require raw sockets or elevated privileges. Open ports
// running risky or legacy services are flagged with higher severity.
package network

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Eselase-Noble/banbo/internal/findings"
	"github.com/Eselase-Noble/banbo/internal/scanner"
)

// Module performs TCP connect scanning.
type Module struct{}

// New returns a network scan module.
func New() *Module { return &Module{} }

// Name identifies the module.
func (m *Module) Name() string { return "network" }

// service describes what we expect to find on a port and how much we should
// worry when it is exposed to the internet.
type service struct {
	name     string
	severity findings.Severity
	note     string
}

// knownServices maps common ports to their service and a baseline risk level.
// Legacy/cleartext/admin services are intentionally ranked higher.
var knownServices = map[int]service{
	21:   {"FTP", findings.SeverityMedium, "FTP transmits credentials and data in cleartext."},
	22:   {"SSH", findings.SeverityInfo, "SSH is expected; ensure key-based auth and no root login."},
	23:   {"Telnet", findings.SeverityHigh, "Telnet is unencrypted and should be replaced with SSH."},
	25:   {"SMTP", findings.SeverityLow, "Mail server exposed; ensure it is not an open relay."},
	53:   {"DNS", findings.SeverityLow, "DNS exposed; ensure recursion is restricted."},
	80:   {"HTTP", findings.SeverityLow, "Plain HTTP exposed; traffic should be redirected to HTTPS."},
	110:  {"POP3", findings.SeverityMedium, "POP3 without TLS exposes mailbox credentials."},
	143:  {"IMAP", findings.SeverityMedium, "IMAP without TLS exposes mailbox credentials."},
	443:  {"HTTPS", findings.SeverityInfo, "HTTPS is expected."},
	445:  {"SMB", findings.SeverityHigh, "SMB should never be exposed to the internet."},
	587:  {"SMTP (submission)", findings.SeverityInfo, "Mail submission port."},
	993:  {"IMAPS", findings.SeverityInfo, "IMAP over TLS."},
	995:  {"POP3S", findings.SeverityInfo, "POP3 over TLS."},
	3306: {"MySQL", findings.SeverityHigh, "Databases should not be directly exposed to the internet."},
	3389: {"RDP", findings.SeverityHigh, "RDP exposed to the internet is a common ransomware entry point."},
	5432: {"PostgreSQL", findings.SeverityHigh, "Databases should not be directly exposed to the internet."},
	6379: {"Redis", findings.SeverityCritical, "Redis often has no auth by default and must never be exposed."},
	8080: {"HTTP-alt", findings.SeverityLow, "Alternate HTTP port exposed."},
	8443: {"HTTPS-alt", findings.SeverityInfo, "Alternate HTTPS port."},
}

// OpenPort is recorded in a finding's evidence; also used by other modules that
// want to know which ports were open (via the context value below).
type OpenPort struct {
	Port    int
	Service string
	Banner  string
}

// Scan probes each configured port with a bounded pool of goroutines.
func (m *Module) Scan(ctx context.Context, t scanner.Target) ([]findings.Finding, error) {
	if t.Host == "" {
		return nil, fmt.Errorf("no host to scan")
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var (
		mu   sync.Mutex
		open []OpenPort
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, 50) // cap concurrent dials

	for _, port := range t.Ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if op, ok := probe(ctx, t.Host, port, timeout); ok {
				mu.Lock()
				open = append(open, op)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })

	out := make([]findings.Finding, 0, len(open))
	for _, op := range open {
		svc := knownServices[op.Port]
		if svc.name == "" {
			svc = service{name: "unknown", severity: findings.SeverityInfo, note: "Open port with unrecognized service."}
		}
		evidence := fmt.Sprintf("tcp/%d open (%s)", op.Port, svc.name)
		if op.Banner != "" {
			evidence += " banner: " + op.Banner
		}
		out = append(out, findings.Finding{
			ID:          fmt.Sprintf("net-open-port-%d", op.Port),
			Title:       fmt.Sprintf("Open port %d/tcp (%s)", op.Port, svc.name),
			Layer:       findings.LayerNetwork,
			Severity:    svc.severity,
			Asset:       fmt.Sprintf("%s:%d", t.Host, op.Port),
			Evidence:    evidence,
			Description: svc.note,
			Remediation: "Confirm this service must be reachable from its current network scope. Close the port, firewall it to trusted ranges, or place it behind a VPN if exposure is not required.",
			References:  []string{"https://owasp.org/www-project-top-ten/"},
		})
	}
	return out, nil
}

// probe opens a TCP connection and attempts a short, passive banner read.
func probe(ctx context.Context, host string, port int, timeout time.Duration) (OpenPort, bool) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return OpenPort{}, false
	}
	defer conn.Close()

	banner := readBanner(conn, timeout)
	svc := knownServices[port]
	return OpenPort{Port: port, Service: svc.name, Banner: banner}, true
}

// readBanner reads whatever the service volunteers on connect, without sending
// anything. Many services (SSH, SMTP, FTP) announce themselves; others stay
// silent, which is fine.
func readBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(min(timeout, 1500*time.Millisecond)))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return sanitize(string(buf[:n]))
}

// sanitize trims control characters so a banner cannot garble terminal output.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}
