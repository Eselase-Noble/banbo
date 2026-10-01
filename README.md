# banbo

**banbo** (Twi: *to protect / defend*) is a security scanner with three modes:

- **`banbo scan`** — probes a **live system** you own or are authorized to test across
  the stack (DNS/email, network, transport/TLS, application/HTTP).
- **`banbo code`** — reviews **source code on disk** for security issues (hardcoded
  secrets, disabled TLS verification, injection-prone patterns, unsafe deserialization,
  and more), with an optional deeper AI review.
- **`banbo advise`** — an AI **code advisor** that recommends better data structures and
  algorithms, performance/complexity fixes, idiomatic design, maintainability, and the
  right system-design & design patterns.

The scan and code modes report findings with severity ratings, map them to Ghana's **Bank
of Ghana Cyber & Information Security Directive** and the **Data Protection Act, 2012 (Act
843)**, and can use an AI provider (**Claude**, with **OpenAI** as a fallback) to explain
each issue and exactly how to fix it in plain English.

banbo is a single self-contained binary that runs natively on **macOS, Linux, and Windows**
(amd64 and arm64).

> Scan. Understand. Fortify.

It ships as a **single, self-contained binary** — no runtime, no dependencies to install.

---

## Research context

banbo is part of a research portfolio spanning **health care**, **system improvement**,
and **fraud detection**. It targets the latter two: it **improves existing systems** by
finding and explaining their weaknesses layer by layer, and it supports **fraud/abuse
prevention** by hardening the infrastructure attackers rely on. In a health-care setting
it can audit clinic and hospital systems and map patient-data exposure to the Data
Protection Act, 2012 (Act 843).

---

## ⚠️ Legal & responsible use

Scanning systems you do not own or lack written permission to test may be **illegal**.
`banbo` is built for **authorized** security testing only:

- Every scan requires you to confirm authorization (`--i-am-authorized`, or an
  interactive prompt).
- Checks are **passive and non-destructive** by default — `banbo` detects issues, it does
  not exploit them, and it never launches denial-of-service or destructive payloads.

You are responsible for how you use this tool.

---

## Installation

### Download a prebuilt binary (no Go required)

Grab the archive for your OS/arch from the
[Releases](https://github.com/Eselase-Noble/banbo/releases/latest) page, extract it, and
run it:

```bash
# macOS / Linux example (adjust the file name for your platform)
tar -xzf banbo_darwin_arm64.tar.gz
./banbo version
# optional: move it onto your PATH
sudo mv banbo /usr/local/bin/
```

On Windows, download the `.zip`, extract `banbo.exe`, and run it from a terminal.

### From source (Go 1.22+)

```bash
go install github.com/Eselase-Noble/banbo/cmd/banbo@latest
```

### Clone and build

```bash
git clone https://github.com/Eselase-Noble/banbo.git
cd banbo
go build -o banbo ./cmd/banbo
./banbo version
```

---

## Use it from any language, container, or CI

banbo is a single binary, and every integration below is a thin wrapper that
downloads that binary and runs it — one engine, many front doors. Each wrapper
exposes both the CLI and a small programmatic API that returns banbo's JSON
findings as native objects. See the per-ecosystem guides under
[`clients/`](./clients).

| Ecosystem | Install | Guide |
|-----------|---------|-------|
| **Go** (import) | `go get github.com/Eselase-Noble/banbo/pkg/banbo` | [`pkg/banbo`](./pkg/banbo) |
| **Java / Maven** | `io.github.eselase-noble:banbo:0.1.2` in `pom.xml` | [`clients/java`](./clients/java) |
| **JavaScript / npm** | `npm install banbo` | [`clients/npm`](./clients/npm) |
| **Python / PyPI** | `pip install banbo` | [`clients/python`](./clients/python) |
| **PHP / Composer** | `composer require eselase-noble/banbo` | [`clients/php`](./clients/php) |
| **C# / NuGet** | `dotnet add package Banbo` | [`clients/dotnet`](./clients/dotnet) |

```go
// Go
import "github.com/Eselase-Noble/banbo/pkg/banbo"

res, _ := banbo.ReviewCode(ctx, ".", nil)
for _, f := range res.Findings {
    fmt.Printf("[%s] %s — %s\n", f.Severity, f.Title, f.Asset)
}
```

### Run with Docker

The image is published to the GitHub Container Registry for `linux/amd64` and
`linux/arm64`:

```bash
# Audit the current directory
docker run --rm -v "$PWD:/src" -w /src ghcr.io/eselase-noble/banbo:latest code .

# Scan a target you're authorized to test (pass an AI key to enrich findings)
docker run --rm -e ANTHROPIC_API_KEY ghcr.io/eselase-noble/banbo:latest scan example.com.gh -y
```

### Use as a GitHub Action

Run banbo in any repository's CI; its exit code (`0`/`1`/`2`) gates the job:

```yaml
- uses: Eselase-Noble/banbo@v1
  with:
    args: "code ."
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}   # optional, enables AI review
```

---

## Usage

```bash
# Scan a domain (you'll be asked to confirm authorization)
banbo scan example.com.gh

# Skip the prompt when you know you're authorized
banbo scan example.com.gh --i-am-authorized

# Machine-readable output for pipelines / dashboards
banbo scan https://app.example.com -o json > report.json

# Scan specific ports with a custom timeout
banbo scan 192.0.2.10 --ports 22,80,443 --timeout 5s -y
```

### Reviewing source code

```bash
# Review the current project for security issues
banbo code .

# AUDIT THE ENTIRE codebase with AI (every eligible file)
banbo code . --full

# Review a specific directory, save JSON
banbo code ./src -o json > code-report.json

# Pattern rules only (skip AI even if a key is set)
banbo code . --no-ai
```

`banbo code` walks the directory (skipping `node_modules`, `.git`, `vendor`, `dist`,
etc.), runs built-in pattern rules offline on **every** file, and — when an API key
is configured — adds a deeper AI security/quality audit. It is read-only; it never
modifies your code.

**Whole-codebase audit & prioritization.** The AI audit is **risk-prioritized**: banbo
detects the project's languages/frameworks (e.g. Next.js, Prisma, Go) and audits the most
security-sensitive files first — auth, payments, API routes, database, config,
middleware, and anything the pattern rules already flagged. By default it audits the
highest-risk `--ai-max-files` (15) and **tells you exactly how many files were not
covered**; pass `--full` to audit the entire codebase. Coverage is never silently
truncated.

### AI code advice

Where `banbo code` hunts for security and quality bugs, `banbo advise` is a **code
advisor** focused on engineering craft — it recommends better data structures and
algorithms (with Big-O reasoning), performance/complexity fixes, idiomatic design,
maintainability and test gaps, and the right system-design & design patterns.

```bash
# Advise on the current project (needs an AI key — Claude or OpenAI)
banbo advise .

# Advise on the entire codebase, as JSON
banbo advise ./src --full -o json > advice.json
```

`banbo advise` requires an AI provider key (run `banbo config` for setup); it is
read-only and always exits `0` (it is guidance, not a pass/fail gate).

### Commands

| Command          | Description                                              |
|------------------|----------------------------------------------------------|
| `banbo scan <target>` | Scan a live host, IP or URL across all layers       |
| `banbo code [path]`   | Review source code for security issues (default `.`) |
| `banbo advise [path]` | AI code advisor: data structures, algorithms, design (default `.`) |
| `banbo config`   | Show configuration and how to enable AI enrichment       |
| `banbo version`  | Print the version                                        |

### Key flags for `scan`

| Flag                   | Description                                             |
|------------------------|--------------------------------------------------------|
| `-o, --output`         | `text` (default) or `json`                             |
| `--ports`              | Comma-separated ports (default: a common-ports set)    |
| `--timeout`            | Per-connection timeout (default `5s`)                  |
| `-y, --i-am-authorized`| Confirm you are authorized to scan the target          |
| `--active`             | Enable deeper (still non-destructive) checks           |
| `--no-ai`              | Skip AI enrichment even if a key is configured         |
| `--no-color`           | Disable colored output                                 |

**Exit codes** (CI/CD friendly): `0` clean/info only · `1` low/medium findings ·
`2` high/critical findings.

---

## AI-powered explanations (optional)

Without any setup, `banbo` reports findings using built-in remediation guidance.
Add an API key to also get plain-English explanations, business-impact summaries
and step-by-step fixes. **Claude is preferred; OpenAI is used as a fallback** — set
either one (or both):

```bash
export BANBO_API_KEY=sk-ant-...      # Claude  (or ANTHROPIC_API_KEY)
export OPENAI_API_KEY=sk-...         # OpenAI  (or BANBO_OPENAI_API_KEY)
```

or create `~/.banbo/config.json`:

```json
{
  "api_key": "sk-ant-...",
  "model": "claude-opus-4-8",
  "openai_api_key": "sk-...",
  "openai_model": "gpt-4o-mini"
}
```

Keys are read from the environment or `~/.banbo/config.json` only — **never commit them
to the repo**. Run `banbo config` to check which provider is active.

---

## How it works

`banbo` runs each layer's checks concurrently, normalizes every result into a common
finding, then enriches and reports:

1. **DNS / email** — SPF & DMARC records (spoofing / phishing exposure).
2. **Network** — open TCP ports and the services behind them (risky/legacy services
   flagged higher).
3. **Transport (TLS)** — certificate validity/expiry and acceptance of legacy
   TLS 1.0/1.1.
4. **Application (HTTP)** — missing security headers, version disclosure, permissive
   CORS, insecure cookies.
5. **Normalize → enrich → report** — de-duplicate, score, map to compliance, optionally
   explain with AI (Claude or OpenAI), and print to the terminal or as JSON.

### Architecture

```
cmd/banbo            CLI entry point
internal/
  cli/               command wiring (scan, code, config, version)
  scanner/           target parsing + concurrent orchestrator + Module interface
  modules/           pluggable live checks: network, tls, http, dns
  codescan/          source-code review engine + built-in pattern rules
  findings/          normalized Finding model, severity, de-dup & summary
  ai/                AI enrichment (Claude + OpenAI) + AI code review (optional)
  compliance/        BoG Directive & Data Protection Act mapping
  report/            terminal + JSON renderers
  config/            config file + environment loading
```

Adding a new check means implementing one interface:

```go
type Module interface {
    Name() string
    Scan(ctx context.Context, t scanner.Target) ([]findings.Finding, error)
}
```

---

## Roadmap

- Embed ProjectDiscovery engines (`naabu`, `httpx`, `dnsx`, `tlsx`, `nuclei`) for deeper,
  template-based vulnerability detection.
- Subdomain enumeration and multi-host / CIDR scanning.
- HTML and PDF reports.
- Homebrew tap and `curl | sh` installer.
- Optional web dashboard.

---

## Development

```bash
go build ./...     # build
go test ./...      # run tests
go vet ./...       # static checks
```

## License

[MIT](./LICENSE)
