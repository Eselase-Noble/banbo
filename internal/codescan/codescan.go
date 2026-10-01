package codescan

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Eselase-Noble/banbo/internal/findings"
)

// Defaults bounding the walk so huge repos stay fast and safe.
const (
	maxFileSize = 1 << 20 // 1 MiB — skip larger files
	maxLineLen  = 4000    // truncate very long lines (minified bundles)
)

// skipDirs are never descended into.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, ".next": true, "out": true, "target": true,
	"__pycache__": true, ".venv": true, "venv": true, ".idea": true,
	".vscode": true, "coverage": true, ".cache": true,
}

// SourceFile is a text file eligible for review.
type SourceFile struct {
	Path    string // path relative to the scan root
	AbsPath string
	Content string
}

// Result holds the outcome of a code scan.
type Result struct {
	Root         string
	FilesScanned int
	Findings     []findings.Finding
}

// Collect walks root and returns the reviewable text files.
func Collect(root string) ([]SourceFile, error) {
	var files []SourceFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || isBinary(data) {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		files = append(files, SourceFile{Path: rel, AbsPath: path, Content: string(data)})
		return nil
	})
	return files, err
}

// Scan collects files under root and runs the built-in pattern rules against
// them. AI review (if desired) is layered on by the caller via the ai package.
func Scan(root string) (Result, error) {
	files, err := Collect(root)
	if err != nil {
		return Result{}, err
	}
	var all []findings.Finding
	for _, f := range files {
		all = append(all, scanFile(f)...)
	}
	return Result{Root: root, FilesScanned: len(files), Findings: findings.Dedupe(all)}, nil
}

// scanFile applies every applicable rule to a single file, line by line.
func scanFile(f SourceFile) []findings.Finding {
	ext := strings.ToLower(filepath.Ext(f.Path))
	var out []findings.Finding

	sc := bufio.NewScanner(strings.NewReader(f.Content))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if len(line) > maxLineLen {
			line = line[:maxLineLen]
		}
		for i := range rules {
			rule := &rules[i]
			if !rule.applies(ext) {
				continue
			}
			loc := rule.Re.FindStringSubmatchIndex(line)
			if loc == nil {
				continue
			}
			out = append(out, findings.Finding{
				ID:          rule.ID,
				Title:       rule.Title,
				Layer:       findings.LayerCode,
				Severity:    rule.Severity,
				Asset:       f.Path + ":" + itoa(lineNo),
				Evidence:    evidence(line),
				Description: rule.Description,
				Remediation: rule.Remediation,
			})
		}
	}
	return out
}

// applies reports whether a rule targets the given file extension.
func (r *Rule) applies(ext string) bool {
	if len(r.Exts) == 0 {
		return true
	}
	for _, e := range r.Exts {
		if e == ext {
			return true
		}
	}
	return false
}

// isBinary uses the classic "contains a NUL byte in the first chunk" heuristic.
func isBinary(data []byte) bool {
	n := min(len(data), 8000)
	return bytes.IndexByte(data[:n], 0) != -1
}

// evidence trims and length-limits a matched line for display.
func evidence(line string) string {
	s := strings.TrimSpace(line)
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

// itoa is a tiny strconv.Itoa to avoid an extra import here.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
