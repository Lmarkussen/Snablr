APP := snablr
BIN_DIR := bin
DIST_DIR := dist

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X 'snablr/internal/version.Version=$(VERSION)' \
	-X 'snablr/internal/version.Commit=$(COMMIT)' \
	-X 'snablr/internal/version.BuildDate=$(BUILD_DATE)'

GOFLAGS := CGO_ENABLED=0

.PHONY: build test lint release clean

build:
	mkdir -p $(BIN_DIR)
	$(GOFLAGS) go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP) ./cmd/snablr

test:
	$(GOFLAGS) go test ./...

lint:
	$(GOFLAGS) go vet ./...

release:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GOFLAGS) go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP)-linux-amd64 ./cmd/snablr
	GOOS=linux GOARCH=arm64 $(GOFLAGS) go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP)-linux-arm64 ./cmd/snablr
	GOOS=darwin GOARCH=amd64 $(GOFLAGS) go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP)-darwin-amd64 ./cmd/snablr
	GOOS=darwin GOARCH=arm64 $(GOFLAGS) go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP)-darwin-arm64 ./cmd/snablr
	GOOS=windows GOARCH=amd64 $(GOFLAGS) go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP)-windows-amd64.exe ./cmd/snablr
	GOOS=windows GOARCH=arm64 $(GOFLAGS) go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP)-windows-arm64.exe ./cmd/snablr

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
