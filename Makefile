# SentinelGo Makefile
# Cross-platform build automation

BINARY_NAME=sentinelgo
VERSION=1.0.0
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE) -X main.gitCommit=$(GIT_COMMIT)"

GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
GOFMT=gofmt
GOMOD=$(GOCMD) mod

CMD_DIR=./cmd/sentinelgo
BUILD_DIR=./build
DIST_DIR=./dist

.PHONY: all build clean test bench lint fmt vet deps help
.PHONY: build-linux build-windows build-darwin
.PHONY: release install run

all: clean deps lint test build

## Build Commands

build: ## Build for current platform
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

build-windows: ## Build for Windows (amd64)
	@echo "Building for Windows..."
	@mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)

build-linux: ## Build for Linux (amd64)
	@echo "Building for Linux..."
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)

build-darwin: ## Build for macOS (amd64)
	@echo "Building for macOS..."
	@mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)

release: build-windows build-linux build-darwin ## Build for all platforms
	@echo "Release binaries built in $(DIST_DIR)/"
	@ls -la $(DIST_DIR)/

## Quality Commands

test: ## Run all tests
	@echo "Running tests..."
	$(GOTEST) ./... -v -count=1 -timeout 60s

test-short: ## Run tests (short mode)
	$(GOTEST) ./... -short -count=1

bench: ## Run benchmarks
	@echo "Running benchmarks..."
	$(GOTEST) ./tests/ -bench=. -benchmem -run=^$$ -timeout 120s

coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) ./... -coverprofile=$(BUILD_DIR)/coverage.out -covermode=atomic
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"

lint: vet fmt-check ## Run all linters

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...

fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) -w .

fmt-check: ## Check code formatting
	@echo "Checking formatting..."
	@test -z "$$($(GOFMT) -l .)" || (echo "Code not formatted. Run 'make fmt'" && exit 1)

## Dependency Commands

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

deps-update: ## Update dependencies
	$(GOMOD) get -u ./...
	$(GOMOD) tidy

## Utility Commands

clean: ## Remove build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@rm -f $(BINARY_NAME) $(BINARY_NAME).exe

install: build ## Install to GOPATH/bin
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

run: build ## Build and run analysis on sample data
	@$(BUILD_DIR)/$(BINARY_NAME) analyze testdata/auth.log

run-windows: build ## Analyze Windows sample data
	@$(BUILD_DIR)/$(BINARY_NAME) analyze testdata/windows_security.log

run-harden: build ## Run hardening assessment
	@$(BUILD_DIR)/$(BINARY_NAME) harden

generate-testdata: ## Generate synthetic test datasets
	@echo "Generating test data..."
	$(GOCMD) run scripts/generate_testdata.go

## Information Commands

version: ## Show version info
	@echo "SentinelGo v$(VERSION) ($(GIT_COMMIT)) built $(BUILD_DATE)"

help: ## Show this help
	@echo "SentinelGo v$(VERSION) - Build Targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
