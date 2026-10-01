package scanner

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Target describes what a single scan run operates on. Modules read the fields
// they care about (e.g. the network module reads Ports, the HTTP module reads
// Scheme/Host) and ignore the rest.
type Target struct {
	Raw     string        // exactly what the user typed
	Host    string        // hostname or IP, no scheme/port
	Scheme  string        // "http" or "https" if the user gave a URL, else ""
	Ports   []int         // ports the network module should probe
	Timeout time.Duration // per-connection timeout
	Active  bool          // whether deeper (still non-destructive) checks are allowed
}

// DefaultPorts is a small, safe set of commonly exposed service ports used when
// the user does not supply their own list.
var DefaultPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443}

// ParseTarget normalizes raw user input (a bare host, an IP, or a full URL)
// into a Target. It deliberately rejects CIDR ranges and multi-host inputs for
// the MVP so a single run always maps to a single host.
func ParseTarget(raw string, ports []int, timeout time.Duration, active bool) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("empty target")
	}

	t := Target{Raw: raw, Timeout: timeout, Active: active, Ports: ports}
	if len(t.Ports) == 0 {
		t.Ports = DefaultPorts
	}

	// Full URL form, e.g. https://example.com/path
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return Target{}, fmt.Errorf("invalid URL %q: %w", raw, err)
		}
		t.Scheme = u.Scheme
		t.Host = u.Hostname()
		if t.Host == "" {
			return Target{}, fmt.Errorf("could not determine host from %q", raw)
		}
		return t, nil
	}

	// host:port form — treat as application target on that port.
	if host, port, err := net.SplitHostPort(raw); err == nil {
		t.Host = host
		if port == "443" {
			t.Scheme = "https"
		} else {
			t.Scheme = "http"
		}
		return t, nil
	}

	// Bare host or IP.
	t.Host = raw
	return t, nil
}

// IsIP reports whether the target host is a literal IP address.
func (t Target) IsIP() bool {
	return net.ParseIP(t.Host) != nil
}
