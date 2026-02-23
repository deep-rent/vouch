VERSION ?= $(or $(shell git describe --tags --always --dirty 2>/dev/null),dev)

BINDIR ?= bin
BINARY_NAME=vouch
BINARY_PATH=./cmd/vouch
LDFLAGS = -ldflags="-s -w -X 'main.version=${VERSION}'"

IMAGE ?= ghcr.io/deep-rent/vouch
PLATFORMS ?= linux/amd64,linux/arm64

.DEFAULT_GOAL := help
.PHONY: all test build clean lint up down logs help tidy run publish

all: tidy lint test build ## Run all checks, tests, and build

tidy: ## Tidy go modules
	go mod tidy

test: ## Run tests with race detector and coverage
	go test -v -race -cover -covermode=atomic -coverprofile=coverage.out ./...

cover: test ## Open the HTML coverage report
	go tool cover -html=coverage.out

build: ## Build the application binary
	go build -trimpath $(LDFLAGS) -o $(BINDIR)/$(BINARY_NAME) $(BINARY_PATH)

run: ## Run the application locally
	go run $(BINARY_PATH)

release: BINDIR=dist
release: clean build ## Build release artifact into dist/

clean: ## Remove the built binary and test cache
	rm -rf $(BINDIR) dist coverage.out
	go clean -testcache

lint: ## Run golangci-lint
	@command -v golangci-lint >/dev/null 2>&1 || (echo "golangci-lint not found. Please install: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run

image: ## Build the multi-platform Docker image
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg "VERSION=${VERSION}" \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		.

publish: ## Build and push the multi-platform Docker image
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg "VERSION=${VERSION}" \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		--push \
		.

help: ## Show this help message
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
