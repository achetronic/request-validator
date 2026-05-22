IMG          ?= ghcr.io/achetronic/request-validator:dev
VERSION      ?= dev
BIN_NAME     ?= request-validator
GOOS         ?= $(shell go env GOOS)
GOARCH       ?= $(shell go env GOARCH)
DIST_DIR     ?= dist
BUILD_FLAGS  ?= -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$(VERSION)"
PLATFORMS    ?= linux/amd64,linux/arm64

SHELL := /usr/bin/env bash
.SHELLFLAGS = -ec
.DEFAULT_GOAL := help

##@ Dev

.PHONY: fmt
fmt: ## go fmt
	go fmt ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: test
test: ## go test
	go test -count=1 ./...

.PHONY: race
race: ## go test -race
	go test -race -count=1 ./...

.PHONY: e2e
e2e: ## Binary-level end-to-end tests (build tag e2e)
	go test -tags e2e -timeout 5m -count=1 ./internal/e2e/...

##@ OpenAPI

SWAG ?= $(shell command -v swag 2>/dev/null)
SWAG_DIRS = cmd,internal/adminapi,internal/crdt,internal/quarantine,internal/policy,internal/facts
SWAG_OUT  = internal/adminapi/docs

.PHONY: swagger-install
swagger-install: ## Install swag v2 CLI locally (v2.0.0-rc5)
	go install github.com/swaggo/swag/v2/cmd/swag@v2.0.0-rc5

.PHONY: swagger
swagger: ## Regenerate the OpenAPI 3.1 spec under internal/adminapi/docs
	@if [ -z "$(SWAG)" ]; then \
	  echo "swag not in PATH; run 'make swagger-install' first" >&2; \
	  exit 1; \
	fi
	$(SWAG) init --v3.1 -g main.go -d $(SWAG_DIRS) --parseInternal \
		--output $(SWAG_OUT) --outputTypes go,json

.PHONY: swagger-check
swagger-check: ## CI guard: fail if the committed openapi.json is out of date
	@tmp=$$(mktemp -d); \
	cp -r $(SWAG_OUT) $$tmp/before; \
	$(MAKE) swagger >/dev/null; \
	if ! diff -q $$tmp/before/swagger.json $(SWAG_OUT)/swagger.json >/dev/null; then \
	  echo "ERROR: $(SWAG_OUT)/swagger.json is out of date; run 'make swagger' and commit." >&2; \
	  diff -u $$tmp/before/swagger.json $(SWAG_OUT)/swagger.json | head -100 >&2; \
	  cp -r $$tmp/before/. $(SWAG_OUT); \
	  rm -rf $$tmp; \
	  exit 1; \
	fi; \
	rm -rf $$tmp

##@ Build

.PHONY: build
build: ## Build the binary into bin/<os>/<arch>/<name>
	mkdir -p bin/$(GOOS)/$(GOARCH)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build $(BUILD_FLAGS) -o bin/$(GOOS)/$(GOARCH)/$(BIN_NAME) ./cmd

.PHONY: package
package: build ## Package the built binary as a tar.gz under dist/
	mkdir -p $(DIST_DIR)
	tar -C bin/$(GOOS)/$(GOARCH) -czf \
		$(DIST_DIR)/$(BIN_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz $(BIN_NAME)

.PHONY: package-signature
package-signature: ## Generate MD5 + SHA256 sidecar files for the package
	cd $(DIST_DIR) && \
		md5sum    $(BIN_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz > $(BIN_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz.md5    && \
		sha256sum $(BIN_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz > $(BIN_NAME)-$(VERSION)-$(GOOS)-$(GOARCH).tar.gz.sha256

.PHONY: run
run: ## Run from source with the example policy
	go run -buildvcs=false ./cmd --config examples/policy.yaml --log-level debug

##@ Docker

.PHONY: docker-build
docker-build: ## Build a single-arch container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push the (single-arch) image
	docker push $(IMG)

.PHONY: docker-buildx
docker-buildx: ## Build and push a multi-arch image with buildx
	docker buildx build \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		-t $(IMG) \
		--push .

##@ Misc

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin dist

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS=":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
