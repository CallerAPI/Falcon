.PHONY: test build run tidy vet

VERSION ?= dev

test:
	go test ./...

vet:
	go vet ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/falcon ./cmd/falcon

run:
	go run ./cmd/falcon

tidy:
	go mod tidy
