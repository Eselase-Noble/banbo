package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Eselase-Noble/banbo/internal/scanner"
)

// TestScanDetectsCommonIssues spins up a deliberately insecure TLS test server
// and asserts the module flags the expected application-layer problems.
func TestScanDetectsCommonIssues(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately omit HSTS/CSP/etc., disclose a version, allow any origin,
		// and set a cookie with no security flags.
		w.Header().Set("Server", "nginx/1.2.3")
		w.Header().Set("X-Powered-By", "PHP/7.0")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// srv.URL is like https://127.0.0.1:PORT — strip the scheme and keep host:port
	// in Target.Host so the module hits the test server.
	hostPort := strings.TrimPrefix(srv.URL, "https://")

	m := New()
	target := scanner.Target{Host: hostPort, Scheme: "https", Timeout: 5 * time.Second}
	fs, err := m.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	want := map[string]bool{
		"http-missing-hsts":              false,
		"http-missing-csp":               false,
		"http-cors-wildcard":             false,
		"http-insecure-cookie":           false,
		"http-server-version-disclosure": false,
		"http-x-powered-by":              false,
	}
	for _, f := range fs {
		if _, ok := want[f.ID]; ok {
			want[f.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected finding %q was not reported", id)
		}
	}
}
