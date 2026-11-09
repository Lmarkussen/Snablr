APP := snablr
SEED_APP := snablr-seed
BIN_DIR := bin
DIST_DIR := dist
STAGE_DIR := $(DIST_DIR)/stage
CMD := ./cmd/snablr
SEED_CMD := ./cmd/snablr-seed
GO ?= go
ROOT_DIR := $(CURDIR)

VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
RELEASE_VERSION := $(if $(filter dev,$(VERSION)),$(VERSION),$(if $(filter v%,$(VERSION)),$(VERSION),v$(VERSION)))

LDFLAGS := -s -w \
	-X 'snablr/internal/version.Version=$(VERSION)' \
	-X 'snablr/internal/version.Commit=$(COMMIT)' \
	-X 'snablr/internal/version.BuildDate=$(BUILD_DATE)'

CGO_ENABLED ?= 1
GOCACHE ?= $(ROOT_DIR)/.cache/go-build
GOENV := CGO_ENABLED=$(CGO_ENABLED) GOCACHE=$(GOCACHE)
ifneq ($(strip $(GOMODCACHE)),)
GOENV += GOMODCACHE=$(GOMODCACHE)
endif
RELEASE_TARGETS := linux/amd64

.PHONY: build test lint release release-snapshot clean

help:
	@echo "Snablr build targets"
	@echo ""
	@echo "  make build             Build ./bin/$(APP) and ./bin/$(SEED_APP) with version metadata"
	@echo "  make test              Run go test ./..."
	@echo "  make lint              Run go vet ./..."
	@echo "  make release-snapshot  Build verified Linux/amd64 CGO+SQLite archive and checksum under ./dist"

build:
	mkdir -p $(BIN_DIR)
	$(GOENV) $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP) $(CMD)
	$(GOENV) $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SEED_APP) $(SEED_CMD)
	@echo "Built $(BIN_DIR)/$(APP)"
	@echo "Built $(BIN_DIR)/$(SEED_APP)"

test:
	$(GOENV) $(GO) test ./...

lint:
	$(GOENV) $(GO) vet ./...

release:
	$(MAKE) release-snapshot VERSION=$(VERSION) COMMIT=$(COMMIT) BUILD_DATE=$(BUILD_DATE)

release-snapshot:
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR) $(STAGE_DIR)
	@set -eu; \
	: > "$(DIST_DIR)/SHA256SUMS"; \
	for target in $(RELEASE_TARGETS); do \
		os="$${target%/*}"; \
		arch="$${target#*/}"; \
		package_name="$(APP)_$(RELEASE_VERSION)_$${os}_$${arch}"; \
		stage_path="$(STAGE_DIR)/$$package_name"; \
		echo "Building $$package_name"; \
		rm -rf "$$stage_path"; \
		mkdir -p "$$stage_path"; \
		GOOS="$$os" GOARCH="$$arch" CGO_ENABLED=1 GOCACHE=$(GOCACHE) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$$stage_path/$(APP)" $(CMD); \
		cp README.md LICENSE docs/building.md "$$stage_path/"; \
		tar -C "$(STAGE_DIR)" -czf "$(DIST_DIR)/$$package_name.tar.gz" "$$package_name"; \
		sha256sum "$(DIST_DIR)/$$package_name.tar.gz" >> "$(DIST_DIR)/SHA256SUMS"; \
	done; \
	rm -rf "$(STAGE_DIR)"
	@echo "Release snapshot archives written to $(DIST_DIR)/"

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

