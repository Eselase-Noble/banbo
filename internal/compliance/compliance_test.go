package compliance

import (
	"strings"
	"testing"

	"github.com/Eselase-Noble/banbo/internal/findings"
)

func TestApplyTagsFindings(t *testing.T) {
	fs := []findings.Finding{
		{ID: "tls-cert-expired"},
		{ID: "http-missing-hsts"},
		{ID: "dns-spf-missing"},
		{ID: "net-open-port-23"},
		{ID: "unknown-check"},
	}
	Apply(fs)

	if len(fs[0].Compliance) == 0 || !containsSubstr(fs[0].Compliance, "Data Protection Act") {
		t.Errorf("tls finding not tagged with Data Protection Act: %v", fs[0].Compliance)
	}
	if len(fs[1].Compliance) == 0 {
		t.Errorf("http finding should be tagged")
	}
	if len(fs[2].Compliance) == 0 || !containsSubstr(fs[2].Compliance, "spoofing") {
		t.Errorf("dns finding not tagged for spoofing: %v", fs[2].Compliance)
	}
	if len(fs[3].Compliance) == 0 {
		t.Errorf("open-port finding should be tagged")
	}
	if len(fs[4].Compliance) != 0 {
		t.Errorf("unknown finding should not be tagged, got %v", fs[4].Compliance)
	}
}

func containsSubstr(tags []string, sub string) bool {
	for _, tag := range tags {
		if strings.Contains(tag, sub) {
			return true
		}
	}
	return false
}
