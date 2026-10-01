# Install

banbo is one static binary. Pick whichever fits your workflow.

## Prebuilt binary (no toolchain)

Download the archive for your OS/arch from the [latest release](https://github.com/Eselase-Noble/banbo/releases/latest), extract, and run:

=== "macOS / Linux"

    ```bash
    tar -xzf banbo_darwin_arm64.tar.gz    # adjust for your platform
    ./banbo version
    sudo mv banbo /usr/local/bin/          # optional: put it on PATH
    ```

=== "Windows"

    Download the `.zip`, extract `banbo.exe`, and run it from a terminal.

Verify integrity against `checksums.txt` on the release.

## With Go

```bash
go install github.com/Eselase-Noble/banbo/cmd/banbo@latest
```

## With Docker

```bash
docker run --rm ghcr.io/eselase-noble/banbo:latest version
```

See [Docker](docker.md) for mounting a project and passing keys.

## From a language package manager

banbo is consumable from Java, JavaScript, Python, PHP, C#, and Go — each wrapper downloads the matching binary and exposes a CLI plus a typed API. See [Language SDKs](languages.md).

## Supported platforms

| OS | amd64 | arm64 |
|----|:-----:|:-----:|
| Linux | ✅ | ✅ |
| macOS | ✅ | ✅ (+ universal) |
| Windows | ✅ | ✅ |
