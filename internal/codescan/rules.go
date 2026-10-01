// Package codescan reviews source code on disk for security problems. It walks a
// directory, runs a set of built-in pattern rules against each text file, and
// (optionally) asks Claude for a deeper review. Results use the same normalized
// findings.Finding type as the live network scanner.
package codescan

import (
	"regexp"

	"github.com/Eselase-Noble/banbo/internal/findings"
)

// Rule is a single pattern-based code check. Re is matched line-by-line; the
// first capturing group (if any) is used as evidence, otherwise the whole match.
type Rule struct {
	ID          string
	Title       string
	Severity    findings.Severity
	Description string
	Remediation string
	Exts        []string // file extensions this rule applies to; empty = all text files
	Re          *regexp.Regexp
}

// mustRules compiles the built-in rule set. Patterns favour high signal over
// exhaustiveness — the optional AI pass handles the long tail.
var rules = buildRules()

func buildRules() []Rule {
	r := func(id, title string, sev findings.Severity, desc, fix, pat string, exts ...string) Rule {
		return Rule{id, title, sev, desc, fix, exts, regexp.MustCompile(pat)}
	}

	js := []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	py := []string{".py"}
	// src is the set of source-code extensions, used to keep broad rules from
	// matching documentation, markdown or fixtures.
	src := []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".py",
		".rb", ".php", ".java", ".cs", ".c", ".cpp", ".h", ".rs"}

	return []Rule{
		// --- Secrets (any file) ---
		r("code-secret-private-key", "Private key committed in source", findings.SeverityCritical,
			"A private key is embedded in the codebase. Anyone with repo access can impersonate the service or decrypt traffic.",
			"Remove the key, rotate it immediately, and load secrets from environment variables or a secrets manager.",
			`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		r("code-secret-aws-key", "Hardcoded AWS access key ID", findings.SeverityHigh,
			"An AWS access key ID is hardcoded. If paired with its secret, attackers can access your AWS account.",
			"Remove and rotate the key in AWS IAM; use IAM roles or environment-provided credentials instead.",
			`\b(AKIA[0-9A-Z]{16})\b`),
		r("code-secret-google-api", "Hardcoded Google API key", findings.SeverityHigh,
			"A Google API key is hardcoded and can be abused or billed against your account.",
			"Remove and rotate the key; restrict it by referrer/IP and load it from configuration.",
			`\b(AIza[0-9A-Za-z\-_]{35})\b`),
		r("code-secret-slack-token", "Hardcoded Slack token", findings.SeverityHigh,
			"A Slack token is hardcoded, granting access to a workspace.",
			"Revoke the token and load it from a secret store.",
			`\b(xox[baprs]-[0-9A-Za-z-]{10,})\b`),
		r("code-secret-jwt", "Hardcoded JWT / bearer token", findings.SeverityMedium,
			"A JSON Web Token is embedded in source. If still valid it grants whatever access it was issued for.",
			"Remove the token; never commit live tokens. Rotate if it is a real credential.",
			`\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`),
		r("code-secret-generic", "Possible hardcoded secret", findings.SeverityMedium,
			"A variable that looks like a credential is assigned a hardcoded string literal.",
			"Move the value to an environment variable or secrets manager; do not commit secrets.",
			`(?i)(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|passwd|password)\s*[:=]\s*['"][^'"\s]{8,}['"]`),

		// --- Transport / crypto ---
		r("code-tls-disabled-node", "TLS certificate verification disabled", findings.SeverityHigh,
			"Disabling certificate verification exposes the connection to man-in-the-middle attacks.",
			"Never disable verification in production. Fix the underlying certificate trust issue instead.",
			`rejectUnauthorized\s*:\s*false`, js...),
		r("code-tls-disabled-env", "TLS verification disabled via env toggle", findings.SeverityHigh,
			"Setting NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS verification process-wide.",
			"Remove this override; address the real certificate problem.",
			`NODE_TLS_REJECT_UNAUTHORIZED`, js...),
		r("code-tls-disabled-go", "TLS verification disabled (InsecureSkipVerify)", findings.SeverityHigh,
			"InsecureSkipVerify:true disables certificate checking in Go TLS clients.",
			"Avoid in production; if used for scanning/auditing, isolate it and never ship it in service code.",
			`InsecureSkipVerify\s*:\s*true`, ".go"),
		r("code-weak-hash", "Weak hash algorithm (MD5/SHA1)", findings.SeverityLow,
			"MD5 and SHA-1 are broken for security use (e.g. password hashing or integrity against tampering).",
			"Use SHA-256+ for integrity and bcrypt/argon2/scrypt for passwords.",
			`(?i)(hashlib\.(?:md5|sha1)|createHash\(\s*['"](?:md5|sha1)|\b(?:md5|sha1)\.(?:New|Sum)\b|DigestUtils\.(?:md5|sha1))`, src...),

		// --- Injection / dangerous sinks ---
		r("code-eval", "Use of eval()", findings.SeverityMedium,
			"eval() executes arbitrary code and is a common path to remote code execution if input is attacker-influenced.",
			"Remove eval(); use JSON.parse or explicit logic instead.",
			`\beval\s*\(`, js...),
		r("code-react-dangerous-html", "React dangerouslySetInnerHTML", findings.SeverityMedium,
			"Injecting raw HTML can introduce cross-site scripting (XSS) if the content is not strictly sanitized.",
			"Avoid raw HTML; if unavoidable, sanitize with a vetted library (e.g. DOMPurify).",
			`dangerouslySetInnerHTML`, js...),
		r("code-sql-concat", "Possible SQL injection (string-built query)", findings.SeverityMedium,
			"A SQL statement appears to be built with string concatenation or interpolation, which enables SQL injection.",
			"Use parameterized queries / prepared statements instead of building SQL from variables.",
			`(?i)(?:SELECT|INSERT|UPDATE|DELETE)\b[^;'"]*(?:\+|\$\{|%s|%d|' \+)`),
		r("code-py-shell-true", "subprocess with shell=True", findings.SeverityMedium,
			"shell=True runs the command through a shell, enabling command injection if any argument is untrusted.",
			"Pass arguments as a list and avoid shell=True; validate/whitelist inputs.",
			`shell\s*=\s*True`, py...),
		r("code-py-yaml-load", "Unsafe yaml.load()", findings.SeverityMedium,
			"yaml.load without SafeLoader can execute arbitrary Python objects from untrusted YAML.",
			"Use yaml.safe_load() instead.",
			`yaml\.load\s*\(`, py...),
		r("code-py-pickle", "Unsafe pickle deserialization", findings.SeverityMedium,
			"pickle.loads on untrusted data can execute arbitrary code.",
			"Avoid pickle for untrusted input; use JSON or a safe serialization format.",
			`pickle\.loads?\s*\(`, py...),

		// --- Hygiene / informational ---
		r("code-insecure-random", "Math.random() used (not cryptographically secure)", findings.SeverityInfo,
			"Math.random() is predictable and must not be used for tokens, IDs or anything security-sensitive.",
			"Use crypto.randomBytes / crypto.getRandomValues for security-sensitive randomness.",
			`Math\.random\s*\(`, js...),
		r("code-http-url", "Plaintext http:// endpoint in code", findings.SeverityInfo,
			"A plaintext http:// endpoint is used as a request/connection target; traffic to it is unencrypted.",
			"Use https:// endpoints.",
			`(?i)(?:fetch|axios[.\w]*|request|\.(?:get|post|put|patch)|(?:base)?url\s*[:=]|endpoint\s*[:=])\s*\(?\s*['"\x60]http://`, src...),
	}
}
