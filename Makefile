BINARY_NAME := gTLSInfo

GO := go
BUILD_DIR := ./bin

LDFLAGS := -ldflags "-s -w"

.PHONY: all build run clean fmt lint

all: build

build:
	@echo "=> Building $(BINARY_NAME)..."
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) 

run:
	@echo "=> Running $(BINARY_NAME)..."
	$(GO) run .

clean:
	@echo "=> Cleaning..."
	rm -rf $(BUILD_DIR)

fmt:
	@echo "=> Formatting..."
	$(GO) fmt ./...

