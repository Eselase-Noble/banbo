# banbo (Python client)

A pure-Python wrapper for [**banbo**](https://github.com/Eselase-Noble/banbo), a
layered security scanner. The wrapper does **not** reimplement any scanning: it
downloads the prebuilt banbo Go binary for your platform on first use, caches it,
and execs it — exposing banbo both as a CLI and as a typed Python library.

- Works on Linux, macOS, and Windows (amd64 / arm64).
- Pure Python, **no runtime dependencies** (standard library only).
- Python 3.8+.

## Install

```bash
pip install banbo
```

The banbo binary itself is **not** bundled in the wheel. It is downloaded lazily
from GitHub Releases the first time you run a scan, then cached under your
per-user cache directory (e.g. `~/.cache/banbo/<version>/` on Linux,
`~/Library/Caches/banbo/<version>/` on macOS, `%LOCALAPPDATA%\banbo\<version>\`
on Windows) and reused.

## CLI usage

The installed `banbo` command is a transparent passthrough to the native binary,
so every flag works exactly as documented upstream:

```bash
# Scan a target (JSON output), confirming you are authorized
banbo scan example.com -o json --i-am-authorized

# Narrow the ports and tighten the timeout, with active probing
banbo scan example.com -o json -y --ports 80,443 --timeout 5s --active

# Review source code for issues
banbo code ./src -o json --full

# Print the binary's version
banbo version
```

`python -m banbo ...` is equivalent to the `banbo` command.

**Exit codes** match banbo: `0` (clean / info only), `1` (low/medium findings),
and `2` (high/critical findings) all mean the scan *ran OK*. Any other exit code
indicates an error.

## Library usage

```python
import banbo

# Run a network/service scan and get a typed result back
result = banbo.scan(
    "example.com",
    i_am_authorized=True,
    ports=[80, 443],      # or "80,443"
    timeout="5s",
    active=True,
)

print(result.target, result.host, "in", result.duration_ms, "ms")
print("totals:", result.summary.total, "critical:", result.summary.critical)

for f in result.findings:
    print(f"[{f.severity.value}] {f.title} @ {f.asset}")
    if f.remediation:
        print("  fix:", f.remediation)

# Only the serious stuff
from banbo import Severity
for f in result.findings_at_least(Severity.HIGH):
    print("urgent:", f.title)

# Static source-code review
code_result = banbo.code("./src", full=True)
print(code_result.summary)
```

### Raw passthrough

For flags the typed helpers don't cover, drive the binary directly:

```python
import banbo

cp = banbo.run(["scan", "example.com", "-o", "json", "-y", "--no-ai"])
print(cp.returncode, cp.ran_ok)
print(cp.stdout)

# `check=True` raises banbo.BanboError on any non-"ran OK" exit code
banbo.run(["version"], check=True)
```

### Return types

`banbo.scan()` and `banbo.code()` return a `ScanResult` dataclass:

| Type          | Fields |
|---------------|--------|
| `ScanResult`  | `target`, `host`, `started_at`, `duration_ms`, `findings: list[Finding]`, `summary: Counts`, `errors: list[ModuleError]`, `exit_code`, `raw`, `ok` |
| `Finding`     | `id`, `title`, `layer`, `severity: Severity`, `asset`, `evidence?`, `description?`, `remediation?`, `references`, `cvss?`, `compliance`, `ai_explanation?`, `ai_remediation?`, `business_impact?` |
| `Severity`    | `str` enum: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (with `.rank`) |
| `Counts`      | `critical`, `high`, `medium`, `low`, `info`, `total` |
| `ModuleError` | `module`, `error` |

## Pointing at a specific binary

Set `BANBO_BINARY` to skip the download entirely and use an existing binary
(handy for development, pinned versions, air-gapped hosts, or CI caches):

```bash
export BANBO_BINARY=/usr/local/bin/banbo
banbo version
```

You can also relocate the download cache with `BANBO_CACHE_DIR`:

```bash
export BANBO_CACHE_DIR=/opt/banbo-cache
```

## Integrity

When possible, the downloaded archive is verified against the release's
`checksums.txt` (SHA-256) before extraction. If the checksum file is unavailable
the download still proceeds (verification is best-effort). Downloads are written
atomically and archives are extracted defensively against path traversal.

---

## Publishing (maintainers)

Releases are built and published by
[`.github/workflows/publish-pypi.yml`](../../.github/workflows/publish-pypi.yml),
triggered when a tag matching `v*` is pushed. The workflow builds an sdist and a
wheel from `clients/python/` with `python -m build` and uploads them with
[`pypa/gh-action-pypi-publish`](https://github.com/pypa/gh-action-pypi-publish).

The workflow is **dormant by default**: the publish job is guarded by a repo
variable so it will not attempt to upload until you opt in. Set the repository
variable `PYPI_PUBLISH_ENABLED` to `true`
(**Settings → Secrets and variables → Actions → Variables**) once one of the two
auth methods below is configured.

### Option A — Trusted Publishing (recommended, no secrets)

Uses OpenID Connect; no long-lived API token is stored in GitHub.

1. Create the `banbo` project on PyPI (upload once manually, or pre-register).
2. On PyPI: **Your projects → banbo → Settings → Publishing → Add a pending
   publisher** (or **Publishing** for an existing project) with:
   - **Owner:** `Eselase-Noble`
   - **Repository:** `banbo`
   - **Workflow name:** `publish-pypi.yml`
   - **Environment:** `pypi`
3. The workflow already requests `permissions: id-token: write` and runs the
   publish job in the GitHub Environment named `pypi`. No secret is needed.
4. Set repo variable `PYPI_PUBLISH_ENABLED=true`.

### Option B — API token fallback

1. Create a PyPI API token scoped to the `banbo` project
   (**PyPI → Account settings → API tokens**).
2. Add it as a repository secret named `PYPI_API_TOKEN`
   (**Settings → Secrets and variables → Actions → Secrets**).
3. In `publish-pypi.yml`, comment out the trusted-publishing step and uncomment
   the token-based step (both are present; see the inline comments).
4. Set repo variable `PYPI_PUBLISH_ENABLED=true`.

### Cutting a release

The distribution version comes from `pyproject.toml` (currently `0.1.1`). Bump it
to match the tag, then:

```bash
git tag v0.1.1
git push origin v0.1.1
```

> Tip: test against TestPyPI first by temporarily setting the publish action's
> `repository-url` to `https://test.pypi.org/legacy/` (and configuring a matching
> trusted publisher / `TEST_PYPI_API_TOKEN`).
