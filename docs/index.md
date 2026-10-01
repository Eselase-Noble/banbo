# banbo

**banbo** (Twi: *to protect / defend*) is a layered security scanner with three modes, shipped as a single self-contained binary that runs natively on **macOS, Linux, and Windows** (amd64 & arm64).

- **`banbo scan`** — probe a **live system** you own or are authorized to test across DNS/email, network, transport (TLS) and application (HTTP).
- **`banbo code`** — audit **source code on disk** for security issues (secrets, disabled TLS verification, injection, unsafe deserialization…), with an optional deeper AI review.
- **`banbo advise`** — an AI **code advisor** that recommends better data structures & algorithms, performance/complexity fixes, idiomatic design, maintainability, and the right system-design & design patterns.

Findings are rated by severity, mapped to Ghana's **Bank of Ghana Cyber & Information Security Directive** and the **Data Protection Act, 2012 (Act 843)**, and can be explained in plain English by an AI provider (**Claude**, with **OpenAI** as a fallback).

> Scan. Understand. Fortify.

## Quick start

```bash
# Install (any platform with Go), then audit the current project
go install github.com/Eselase-Noble/banbo/cmd/banbo@latest
banbo code .
```

Or grab a prebuilt binary from the [latest release](https://github.com/Eselase-Noble/banbo/releases/latest), or run it with Docker:

```bash
docker run --rm -v "$PWD:/src" -w /src ghcr.io/eselase-noble/banbo:latest code .
```

## Where to next

- [Install](installation.md) — binaries, `go install`, Docker, and language package managers.
- [Commands](usage.md) — `scan`, `code`, and `advise` with every flag.
- [AI setup](ai-setup.md) — bring your own Claude or OpenAI key.
- [Docker](docker.md) · [GitHub Action](github-action.md) · [Language SDKs](languages.md) · [Compliance](compliance.md).

!!! warning "Authorized use only"
    Scanning systems you do not own or lack written permission to test may be illegal. `banbo scan` requires you to confirm authorization. Checks are passive and non-destructive by default.
