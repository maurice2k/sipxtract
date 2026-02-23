BINARY_NAME := sipxtract

GIT_TAG     := $(shell git describe --tags --abbrev=0 2>/dev/null)
GIT_DIRTY   := $(shell git status --porcelain 2>/dev/null | head -1)
GIT_BRANCH  := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
BASE_VERSION := $(if $(GIT_TAG),$(patsubst v%,%,$(GIT_TAG)),dev)
VERSION     ?= $(if $(GIT_DIRTY),$(BASE_VERSION)-dev-$(GIT_BRANCH),$(BASE_VERSION))

GOCMD   := go
GOBUILD := $(GOCMD) build
GOVET   := $(GOCMD) vet
GOFMT   := gofmt

LDFLAGS := -ldflags "-s -w -X main.VERSION=$(VERSION)"

BUILD_DIR := build

.PHONY: all build linux-amd64 darwin-arm64 build-all clean deps tidy vet fmt fmt-check help

all: build

help:
	@echo "$(BINARY_NAME) Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build for current platform"
	@echo "  make linux-amd64    Cross-compile for Linux x86-64"
	@echo "  make darwin-arm64   Cross-compile for macOS Apple Silicon"
	@echo "  make build-all      Build for all platforms"
	@echo "  make vet            Run go vet"
	@echo "  make fmt            Format code"
	@echo "  make fmt-check      Check code formatting"
	@echo "  make clean          Remove build artifacts"
	@echo "  make deps           Download dependencies"
	@echo "  make tidy           Tidy go.mod"

build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

linux-amd64:
	@echo "Building $(BINARY_NAME) $(VERSION) for linux/amd64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

darwin-arm64:
	@echo "Building $(BINARY_NAME) $(VERSION) for darwin/arm64..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64"

build-all: linux-amd64 darwin-arm64
	@echo "Built all binaries in $(BUILD_DIR)/"
	@ls -la $(BUILD_DIR)/

vet:
	@echo "Running go vet..."
	$(GOVET) ./...

fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

fmt-check:
	@echo "Checking code formatting..."
	@test -z "$$($(GOFMT) -s -l . | tee /dev/stderr)" || (echo "Code is not formatted. Run 'make fmt'" && exit 1)

clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)

deps:
	@echo "Downloading dependencies..."
	$(GOCMD) mod download

tidy:
	@echo "Tidying go.mod..."
	$(GOCMD) mod tidy
