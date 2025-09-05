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

# Final image with CA certs included by base
FROM gcr.io/distroless/base:nonroot
WORKDIR /app
COPY --from=build /out/vouch /vouch

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/vouch"]
