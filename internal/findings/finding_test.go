package findings

import "testing"

func TestDedupeKeepsHighestSeverityAndSorts(t *testing.T) {
	in := []Finding{
		{ID: "a", Asset: "x", Severity: SeverityLow, Layer: LayerApplication},
		{ID: "a", Asset: "x", Severity: SeverityHigh, Layer: LayerApplication}, // dup, higher
		{ID: "b", Asset: "y", Severity: SeverityCritical, Layer: LayerNetwork},
		{ID: "c", Asset: "z", Severity: SeverityInfo, Layer: LayerDNS},
	}
	out := Dedupe(in)

	if len(out) != 3 {
		t.Fatalf("expected 3 findings after dedupe, got %d", len(out))
	}
	// Highest severity first.
	if out[0].ID != "b" || out[0].Severity != SeverityCritical {
		t.Errorf("expected critical 'b' first, got %q (%s)", out[0].ID, out[0].Severity)
	}
	// The duplicate 'a' must have kept the High severity copy.
	for _, f := range out {
		if f.ID == "a" && f.Severity != SeverityHigh {
			t.Errorf("dedupe kept wrong severity for 'a': got %s", f.Severity)
		}
	}
}

func TestSummarizeAndWorst(t *testing.T) {
	in := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
		{Severity: SeverityInfo},
	}
	c := Summarize(in)
	if c.Total != 5 || c.Critical != 1 || c.High != 2 || c.Medium != 1 || c.Info != 1 {
		t.Errorf("unexpected counts: %+v", c)
	}
	if w := Worst(in); w != SeverityCritical {
		t.Errorf("expected worst=critical, got %s", w)
	}
	if w := Worst(nil); w != SeverityInfo {
		t.Errorf("expected worst of empty=info, got %s", w)
	}
}

func TestSeverityJSON(t *testing.T) {
	b, err := SeverityHigh.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"high"` {
		t.Errorf("expected \"high\", got %s", b)
	}
}
