VERSION ?= $(or $(shell git describe --tags --always --dirty 2>/dev/null),dev)

BINDIR ?= bin
BINARY_NAME=vouch
BINARY_PATH=./cmd/vouch
LDFLAGS = -ldflags="-s -w -X 'main.version=${VERSION}'"

IMAGE ?= ghcr.io/deep-rent/vouch
PLATFORMS ?= linux/amd64,linux/arm64

FLAGS := GOEXPERIMENT=jsonv2
PACKAGES := ./...

.DEFAULT_GOAL := help
.PHONY: all format test build clean lint up down logs help tidy run publish

all: format lint test

tidy:
	go mod tidy

format:
	@echo "Formatting..."
	@$(FLAGS) golangci-lint fmt $(PACKAGES)

lint:
	@echo "Linting..."
	@$(FLAGS) golangci-lint run $(PACKAGES)

test:
	@echo "Testing..."
	@$(FLAGS) go test -v -cover -coverprofile=coverage.out $(PACKAGES)

cover: test
	GOEXPERIMENT=jsonv2 go tool cover -html=coverage.out

build:
	GOEXPERIMENT=jsonv2 go build -trimpath $(LDFLAGS) -o $(BINDIR)/$(BINARY_NAME) $(BINARY_PATH)

run:
	GOEXPERIMENT=jsonv2 go run $(BINARY_PATH)

release: BINDIR=dist
release: clean build

clean:
	rm -rf $(BINDIR) dist coverage.out
	go clean -testcache

image:
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg "VERSION=${VERSION}" \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		.

publish:
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg "VERSION=${VERSION}" \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		--push \
		.

help:
	@echo "Targets:"
	@echo ""
	@echo "  all:            Runs format, lint, and test."
	@echo "  format:         Formats the code."
	@echo "  lint:           Lints the code."
	@echo "  test:           Executes the tests."
	@echo "  tidy:           Tidies go modules."
	@echo "  cover:          Opens the HTML coverage report."
	@echo "  build:          Builds the application binary."
	@echo "  run:            Runs the application locally."
	@echo "  release:        Builds release artifact into dist/."
	@echo "  clean:          Removes the built binary and test cache."
	@echo "  image:          Builds the multi-platform Docker image."
	@echo "  publish:        Builds and pushes the multi-platform Docker image."
	@echo "  help:           Shows this help message."
