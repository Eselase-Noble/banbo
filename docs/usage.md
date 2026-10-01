# Commands

Every command accepts `-o text` (default) or `-o json`. Exit codes are CI-friendly: `0` clean/info only, `1` low/medium findings, `2` high/critical findings (`advise` always exits `0`).

## `banbo scan <target>`

Probe a live host, IP, or URL across all layers.

```bash
banbo scan example.com.gh --i-am-authorized
banbo scan https://app.example.com -o json > report.json
banbo scan 192.0.2.10 --ports 22,80,443 --timeout 5s -y
```

| Flag | Description |
|------|-------------|
| `-o, --output` | `text` (default) or `json` |
| `--ports` | Comma-separated ports (default: common-ports set) |
| `--timeout` | Per-connection timeout (default `5s`) |
| `-y, --i-am-authorized` | Confirm you are authorized to scan the target |
| `--active` | Enable deeper (still non-destructive) checks |
| `--no-ai` | Skip AI enrichment even if a key is configured |
| `--no-color` | Disable colored output |

## `banbo code [path]`

Audit source code on disk for security issues (defaults to `.`). Pattern rules run offline on every file; with an AI key it adds a risk-prioritized AI audit.

```bash
banbo code .
banbo code . --full                 # AI-audit the entire codebase
banbo code ./src -o json > code-report.json
banbo code . --no-ai                # pattern rules only
```

| Flag | Description |
|------|-------------|
| `-o, --output` | `text` or `json` |
| `--full` | AI-audit the entire codebase, not just the riskiest files |
| `--ai-max-files` | Max files to AI-audit, highest-risk first (default `15`) |
| `--no-ai` | Skip the AI audit |
| `--no-color` | Disable colored output |

The AI audit is **risk-prioritized** (auth, payments, API routes, DB, config first) and tells you exactly how many files were not covered — coverage is never silently truncated.

## `banbo advise [path]`

An AI **code advisor** for engineering craft rather than security (defaults to `.`). Requires an AI key.

```bash
banbo advise .
banbo advise ./src --full -o json > advice.json
```

Covers: data structures & algorithms (with Big-O), performance/complexity, idiomatic design, maintainability & tests, and system design & patterns.

| Flag | Description |
|------|-------------|
| `-o, --output` | `text` or `json` |
| `--full` | Advise on the entire codebase |
| `--ai-max-files` | Max files, highest-value first (default `15`) |
| `--no-color` | Disable colored output |

## `banbo config` / `banbo version`

`config` shows the active AI provider and how to set a key (see [AI setup](ai-setup.md)); `version` prints the build version.
