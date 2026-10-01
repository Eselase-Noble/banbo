# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------------
# Build on the native platform and cross-compile with Go (fast, no QEMU needed
# for the compiler); the resulting binary is static (CGO disabled).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /src

# Cache module downloads separately from the source for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags "-s -w -X github.com/Eselase-Noble/banbo/internal/cli.Version=${VERSION}" \
    -o /out/banbo ./cmd/banbo

# ---- runtime stage ----------------------------------------------------------
# distroless/static is minimal and ships CA certificates (needed for TLS scans
# and the Claude/OpenAI API calls). :nonroot runs as an unprivileged user.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/banbo /usr/local/bin/banbo

# Projects to audit are mounted here (e.g. `-v "$PWD:/src"` or the GitHub Action).
WORKDIR /src

ENTRYPOINT ["/usr/local/bin/banbo"]
