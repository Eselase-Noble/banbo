# Docker

The image is published to the GitHub Container Registry for `linux/amd64` and `linux/arm64`:

```
ghcr.io/eselase-noble/banbo:latest      # also :0.1.3, :0.1, :0
```

## Audit a project

Mount your project and run `code` (or `advise`):

```bash
docker run --rm -v "$PWD:/src" -w /src ghcr.io/eselase-noble/banbo:latest code .
```

## Scan a target

```bash
docker run --rm ghcr.io/eselase-noble/banbo:latest scan example.com.gh -y
```

## Enable AI

Pass your key through to the container:

```bash
docker run --rm -e ANTHROPIC_API_KEY \
  -v "$PWD:/src" -w /src \
  ghcr.io/eselase-noble/banbo:latest code . --full
```

## Notes

- The image is `distroless` and runs as a non-root user.
- Pin a version (`:0.1.3`) for reproducible CI; `:latest` tracks the newest release.
