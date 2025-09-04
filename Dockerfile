# syntax=docker/dockerfile:1.7
# Usage: docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/deep-rent/vouch:latest . --push

ARG GO_VERSION=1.25

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Go module download (cached)
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Build
COPY . .
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOFLAGS=-buildvcs=false
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/vouch ./cmd/vouch

# Final image with CA certs included by base
FROM gcr.io/distroless/base:nonroot
WORKDIR /app
COPY --from=build /out/vouch /vouch

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/vouch"]
