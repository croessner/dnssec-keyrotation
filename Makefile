SHELL := /bin/sh
GO ?= go
GOFMT ?= gofmt
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_CACHE ?= /tmp/dnssec-keyrotation-golangci-cache
GOVULNCHECK ?= govulncheck
GOSEC ?= gosec
TRIVY ?= trivy
GOCACHE ?= /tmp/dnssec-keyrotation-gocache
GOENV := env GOCACHE=$(GOCACHE) GOFLAGS=-mod=vendor GOEXPERIMENT=runtimesecret
VERSION ?= dev
IMAGE ?= registry.example.test/example/dnssec-keyrotation
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: all check fmt-check test race vet lint build build-linux govulncheck gosec trivy-config security guardrails release-guardrails openapi-check license-check image
all: check build

fmt-check:
	@files="$$(find . -type d -name vendor -prune -o -type f -name '*.go' -print)"; \
		unformatted="$$($(GOFMT) -l $$files)"; \
		test -z "$$unformatted" || { echo "Unformatted Go files:"; echo "$$unformatted"; exit 1; }

test:
	@mkdir -p $(GOCACHE)
	$(GOENV) $(GO) test -count=1 -coverprofile=coverage.out ./...

race:
	@mkdir -p $(GOCACHE)
	$(GOENV) $(GO) test -race ./...

vet:
	@mkdir -p $(GOCACHE)
	$(GOENV) $(GO) vet ./...

lint:
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { echo 'golangci-lint not found'; exit 1; }
	@mkdir -p $(GOLANGCI_LINT_CACHE)
	env GOLANGCI_LINT_CACHE=$(GOLANGCI_LINT_CACHE) $(GOENV) $(GOLANGCI_LINT) run ./...

openapi-check:
	@test -s api/openapi.yaml
	@grep -Eq '^openapi: 3\.1\.0$$' api/openapi.yaml
	@grep -Eq '^  /v1/rotations/trigger:' api/openapi.yaml
	@grep -Eq '^  /v1/rotations/resume:' api/openapi.yaml
	@grep -Eq '^  /v1/enrollment/arm:' api/openapi.yaml

license-check:
	@test -s LICENSE
	@grep -Eq '^ +GNU AFFERO GENERAL PUBLIC LICENSE$$' LICENSE
	@grep -Eq 'AGPL-3\.0-or-later' README.md Dockerfile
	@grep -Eq 'cp LICENSE README\.md POLICY\.md' .github/workflows/release.yaml

check: fmt-check test vet openapi-check

build:
	@mkdir -p bin $(GOCACHE)
	$(GOENV) CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)" -o bin/dnssecctl ./cmd/dnssecctl

build-linux:
	@mkdir -p dist $(GOCACHE)
	$(GOENV) GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)" -o dist/dnssecctl-linux-amd64 ./cmd/dnssecctl
	@shasum -a 256 dist/dnssecctl-linux-amd64 > dist/dnssecctl-linux-amd64.sha256

govulncheck:
	@command -v $(GOVULNCHECK) >/dev/null 2>&1 || { echo 'govulncheck not found'; exit 1; }
	$(GOENV) $(GOVULNCHECK) ./...

gosec:
	@command -v $(GOSEC) >/dev/null 2>&1 || { echo 'gosec not found'; exit 1; }
	$(GOENV) $(GOSEC) -quiet -exclude-dir=vendor ./...

trivy-config:
	@command -v $(TRIVY) >/dev/null 2>&1 || { echo 'trivy not found'; exit 1; }
	$(TRIVY) config --skip-dirs vendor --skip-dirs temp --severity HIGH,CRITICAL --exit-code 1 .

security: race govulncheck gosec trivy-config

guardrails: fmt-check vet lint test race build-linux openapi-check license-check

release-guardrails: guardrails govulncheck gosec trivy-config

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) -t $(IMAGE):$(VERSION) .
