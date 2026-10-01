package scanner

import (
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantHost   string
		wantScheme string
		wantIP     bool
	}{
		{"bare host", "example.com", "example.com", "", false},
		{"full https url", "https://app.example.com/path", "app.example.com", "https", false},
		{"full http url", "http://example.com", "example.com", "http", false},
		{"host with port 443", "example.com:443", "example.com", "https", false},
		{"host with port 8080", "example.com:8080", "example.com", "http", false},
		{"literal ip", "192.0.2.10", "192.0.2.10", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTarget(tc.raw, nil, time.Second, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Host != tc.wantHost {
				t.Errorf("host: got %q want %q", got.Host, tc.wantHost)
			}
			if got.Scheme != tc.wantScheme {
				t.Errorf("scheme: got %q want %q", got.Scheme, tc.wantScheme)
			}
			if got.IsIP() != tc.wantIP {
				t.Errorf("IsIP: got %v want %v", got.IsIP(), tc.wantIP)
			}
			if len(got.Ports) == 0 {
				t.Errorf("expected default ports to be populated")
			}
		})
	}
}

func TestParseTargetEmpty(t *testing.T) {
	if _, err := ParseTarget("  ", nil, time.Second, false); err == nil {
		t.Error("expected error for empty target")
	}
}

func TestParseTargetCustomPorts(t *testing.T) {
	got, err := ParseTarget("example.com", []int{22, 80}, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Ports) != 2 || got.Ports[0] != 22 || got.Ports[1] != 80 {
		t.Errorf("custom ports not honored: %v", got.Ports)
	}
}
