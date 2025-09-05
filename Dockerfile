# syntax=docker/dockerfile:1.7

# Usage:
# VERSION=$(git describe --tags --always --dirty)
# docker buildx build \
#   --platform linux/amd64,linux/arm64 \
#   --build-arg "VERSION=${VERSION}" \
#   -t ghcr.io/deep-rent/vouch:latest \
#   . --push

ARG GO_VERSION=1.25
ARG VERSION=dev

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

ARG VERSION
WORKDIR /src

# Go module download (cached)
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Build the main application binary
COPY . .
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-buildvcs=false
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w -X 'main.version=${VERSION}'" -o /out/vouch ./cmd/vouch

# Build the healthcheck binary
RUN <<EOT
cat > /src/healthcheck.go <<EOF
package main
import ("net/http"; "os")
func main() {
    res, err := http.Get("http://localhost:8080/healthy")
    if err != nil || res.StatusCode != http.StatusOK {
        os.Exit(1)
    }
    os.Exit(0)
}
EOF
go build -trimpath -ldflags="-s -w" -o /out/healthcheck /src/healthcheck.go
EOT

# Final image with CA certs included by base
FROM gcr.io/distroless/base:nonroot
WORKDIR /app
COPY --from=build /out/vouch /vouch
COPY --from=build /out/healthcheck /healthcheck

EXPOSE 8080
USER nonroot:nonroot

# Monitor the server's liveness probe.
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 CMD ["/healthcheck"]

ENTRYPOINT ["/vouch"]
