.PHONY: all generate build clean dev test tidy help

BINARY := dnsttui
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS := -trimpath
LDFLAGS := -s -w -X main.Version=$(VERSION)

all: generate build

## generate: Compile .templ files to Go code
generate:
	go run github.com/a-h/templ/cmd/templ@latest generate

## build: Build the binary with CGO disabled
build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) .

## dev: Generate + build for development
dev: generate
	go build -o $(BINARY) .

## test: Run tests
test:
	go test ./...

## tidy: Run go mod tidy
tidy:
	go mod tidy

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)

## help: Show this help
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
