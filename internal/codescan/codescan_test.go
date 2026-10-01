package codescan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDetectsPatterns(t *testing.T) {
	dir := t.TempDir()

	// A JS file with several planted issues.
	js := `const token = "AKIAABCDEFGHIJKLMNOP";
const opts = { rejectUnauthorized: false };
const id = Math.random();
element.innerHTML = userInput; // not flagged
node.dangerouslySetInnerHTML = { __html: data };
const api_key = "super-secret-value-123";
eval(userCode);
`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}

	// A file inside a skipped directory must be ignored.
	nm := filepath.Join(dir, "node_modules", "pkg")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nm, "secret.js"), []byte(`eval(x)`), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 1 {
		t.Errorf("expected 1 file scanned (node_modules skipped), got %d", res.FilesScanned)
	}

	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.ID] = true
	}
	for _, want := range []string{
		"code-secret-aws-key",
		"code-tls-disabled-node",
		"code-insecure-random",
		"code-react-dangerous-html",
		"code-secret-generic",
		"code-eval",
	} {
		if !got[want] {
			t.Errorf("expected rule %q to fire", want)
		}
	}
}

func TestScanSkipsBinary(t *testing.T) {
	dir := t.TempDir()
	// A file with a NUL byte should be treated as binary and skipped.
	if err := os.WriteFile(filepath.Join(dir, "blob.dat"), []byte("eval(\x00)"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 0 {
		t.Errorf("expected binary file to be skipped, scanned %d", res.FilesScanned)
	}
}
