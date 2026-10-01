package codescan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Project summarizes the detected tech stack so AI auditing can be
// context-aware (knowing it's a Next.js app vs a Go service changes what to look
// for).
type Project struct {
	Languages  []string `json:"languages"`
	Frameworks []string `json:"frameworks"`
}

// Summary renders the project context as a short one-line string for prompts.
func (p Project) Summary() string {
	var parts []string
	if len(p.Languages) > 0 {
		parts = append(parts, "Languages: "+strings.Join(p.Languages, ", "))
	}
	if len(p.Frameworks) > 0 {
		parts = append(parts, "Frameworks: "+strings.Join(p.Frameworks, ", "))
	}
	return strings.Join(parts, ". ")
}

// extLang maps a file extension to a language label.
var extLang = map[string]string{
	".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
	".ts": "TypeScript", ".tsx": "TypeScript",
	".go": "Go", ".py": "Python", ".rb": "Ruby", ".php": "PHP",
	".java": "Java", ".cs": "C#", ".c": "C", ".cpp": "C++", ".rs": "Rust",
}

// DetectProject infers languages from file extensions and frameworks from
// manifest files at the project root.
func DetectProject(root string, files []SourceFile) Project {
	langSet := map[string]bool{}
	for _, f := range files {
		if l := extLang[strings.ToLower(filepath.Ext(f.Path))]; l != "" {
			langSet[l] = true
		}
	}
	langs := keys(langSet)
	sort.Strings(langs)

	fwSet := map[string]bool{}
	// package.json dependencies
	if data, err := os.ReadFile(filepath.Join(root, "package.json")); err == nil {
		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(data, &pkg) == nil {
			for name := range merge(pkg.Dependencies, pkg.DevDependencies) {
				switch {
				case name == "next":
					fwSet["Next.js"] = true
				case name == "react":
					fwSet["React"] = true
				case name == "express":
					fwSet["Express"] = true
				case name == "@nestjs/core":
					fwSet["NestJS"] = true
				case name == "vue":
					fwSet["Vue"] = true
				case name == "svelte":
					fwSet["Svelte"] = true
				case name == "fastify":
					fwSet["Fastify"] = true
				case strings.HasPrefix(name, "@prisma"):
					fwSet["Prisma"] = true
				}
			}
		}
	}
	// go.mod
	if data, err := os.ReadFile(filepath.Join(root, "go.mod")); err == nil {
		s := string(data)
		for dep, label := range map[string]string{
			"gin-gonic/gin": "Gin", "labstack/echo": "Echo",
			"gofiber/fiber": "Fiber", "go-chi/chi": "chi",
		} {
			if strings.Contains(s, dep) {
				fwSet[label] = true
			}
		}
	}
	// Python / PHP manifests
	for _, probe := range []struct{ file, fw string }{
		{"manage.py", "Django"}, {"requirements.txt", ""}, {"pyproject.toml", ""},
		{"artisan", "Laravel"}, {"composer.json", ""},
	} {
		if _, err := os.Stat(filepath.Join(root, probe.file)); err == nil && probe.fw != "" {
			fwSet[probe.fw] = true
		}
	}

	fws := keys(fwSet)
	sort.Strings(fws)
	return Project{Languages: langs, Frameworks: fws}
}

// riskKeywords mark security-sensitive files that should be audited first.
var riskKeywords = []string{
	"auth", "login", "logout", "session", "password", "passwd", "secret",
	"token", "cred", "oauth", "jwt", "payment", "pay", "checkout", "billing",
	"api", "route", "router", "controller", "handler", "endpoint", "admin",
	"upload", "download", "sql", "query", "db", "database", "model", "schema",
	"config", "env", "middleware", "crypto", "security", "user", "account",
	"permission", "role", "webhook", "graphql", "cookie",
}

// RiskOrder returns files sorted by estimated security relevance (highest
// first), so a limited AI budget covers the most important files. flagged marks
// files that already have pattern findings (they get a boost).
func RiskOrder(files []SourceFile, flagged map[string]bool) []SourceFile {
	type scored struct {
		f     SourceFile
		score int
		idx   int
	}
	arr := make([]scored, len(files))
	for i, f := range files {
		arr[i] = scored{f: f, score: riskScore(f.Path, flagged[f.Path]), idx: i}
	}
	sort.SliceStable(arr, func(a, b int) bool {
		if arr[a].score != arr[b].score {
			return arr[a].score > arr[b].score
		}
		return arr[a].idx < arr[b].idx
	})
	out := make([]SourceFile, len(arr))
	for i, s := range arr {
		out[i] = s.f
	}
	return out
}

func riskScore(path string, flagged bool) int {
	p := strings.ToLower(path)
	score := 0
	for _, kw := range riskKeywords {
		if strings.Contains(p, kw) {
			score++
		}
	}
	if flagged {
		score += 3
	}
	return score
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k := range a {
		out[k] = a[k]
	}
	for k := range b {
		out[k] = b[k]
	}
	return out
}
