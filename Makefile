# AISAC Agent Makefile

# Variables
BINARY_AGENT=aisac-agent
BINARY_SERVER=aisac-server
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod
GOFMT=gofmt

# Directories
BUILD_DIR=build
CMD_AGENT=./cmd/agent
CMD_SERVER=./cmd/server

.PHONY: all build build-agent build-server test lint fmt clean deps run-agent run-server build-all docker-build release help

all: build

## Build
build: build-agent build-server

build-agent:
	@echo "Building agent..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_AGENT) $(CMD_AGENT)

build-server:
	@echo "Building server..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SERVER) $(CMD_SERVER)

## Cross-platform build
build-all: build-linux build-windows build-darwin

build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)/linux-amd64
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux-amd64/$(BINARY_AGENT) $(CMD_AGENT)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux-amd64/$(BINARY_SERVER) $(CMD_SERVER)
	@mkdir -p $(BUILD_DIR)/linux-arm64
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux-arm64/$(BINARY_AGENT) $(CMD_AGENT)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux-arm64/$(BINARY_SERVER) $(CMD_SERVER)

build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BUILD_DIR)/windows-amd64
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows-amd64/$(BINARY_AGENT).exe $(CMD_AGENT)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows-amd64/$(BINARY_SERVER).exe $(CMD_SERVER)

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(BUILD_DIR)/darwin-amd64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin-amd64/$(BINARY_AGENT) $(CMD_AGENT)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin-amd64/$(BINARY_SERVER) $(CMD_SERVER)
	@mkdir -p $(BUILD_DIR)/darwin-arm64
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin-arm64/$(BINARY_AGENT) $(CMD_AGENT)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin-arm64/$(BINARY_SERVER) $(CMD_SERVER)

## Test
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -cover ./...

test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## Lint
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

## Format
fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

## Vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## Dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## Run
run-agent: build-agent
	@echo "Running agent..."
	$(BUILD_DIR)/$(BINARY_AGENT) -c configs/agent.yaml

run-server: build-server
	@echo "Running server..."
	$(BUILD_DIR)/$(BINARY_SERVER) -a :8443

## Docker
docker-build:
	@echo "Building Docker images..."
	docker build -t aisac-agent:$(VERSION) -f Dockerfile.agent .
	docker build -t aisac-server:$(VERSION) -f Dockerfile.server .

## Release
release:
	@echo "Creating release..."
	@which goreleaser > /dev/null || (echo "Please install goreleaser" && exit 1)
	goreleaser release --clean

release-snapshot:
	@echo "Creating snapshot release..."
	goreleaser release --snapshot --clean

## Clean
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

## Generate certificates (for development)
gen-certs:
	@echo "Generating development certificates..."
	@mkdir -p certs
	./scripts/gen-certs.sh

## Install
install: build
	@echo "Installing binaries..."
	cp $(BUILD_DIR)/$(BINARY_AGENT) /usr/local/bin/
	cp $(BUILD_DIR)/$(BINARY_SERVER) /usr/local/bin/

## Help
help:
	@echo "AISAC Agent - Available targets:"
	@echo ""
	@echo "  build          - Build agent and server for current platform"
	@echo "  build-agent    - Build only the agent"
	@echo "  build-server   - Build only the server"
	@echo "  build-all      - Build for all platforms (Linux, Windows, macOS)"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  lint           - Run golangci-lint"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  deps           - Download and tidy dependencies"
	@echo "  run-agent      - Build and run the agent"
	@echo "  run-server     - Build and run the server"
	@echo "  docker-build   - Build Docker images"
	@echo "  release        - Create release with GoReleaser"
	@echo "  clean          - Remove build artifacts"
	@echo "  gen-certs      - Generate development certificates"
	@echo "  install        - Install binaries to /usr/local/bin"
	@echo ""
