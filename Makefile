SHELL := /bin/bash
MODULE := github.com/rwhitworth/bedrock
BIN    := bedrock
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Commit=$(COMMIT) \
  -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: all build test test-race lint fuzz vulncheck install clean release-check

all: lint test-race build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

lint:
	golangci-lint run

fuzz:
	@for t in $$(grep -rl '^func Fuzz' --include='*_test.go' . | xargs -I{} dirname {} | sort -u); do \
	  echo "=== $$t ==="; \
	  (cd $$t && go test -run=^$$ -fuzz=. -fuzztime=30s ./...) || exit 1; \
	done

vulncheck:
	govulncheck ./...

install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" .

clean:
	rm -f $(BIN)
	rm -rf dist/

release-check: lint test-race vulncheck
	@echo "ready to tag"
