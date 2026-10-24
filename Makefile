.PHONY: test build run tidy vet version

# VERSION is the release. It defaults to the latest release tag in this
# checkout. A build without it is refused. The dashboard and the listen log
# show this string. They must not say dev.
VERSION ?= $(shell git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null | sed 's/^v//')

test:
	go test ./...

vet:
	go vet ./...

version:
	@test -n "$(VERSION)" || { echo "no release tag found. Run git fetch --tags, or set VERSION=<release>" >&2; exit 1; }
	@echo $(VERSION)

build:
	@test -n "$(VERSION)" && test "$(VERSION)" != "dev" || { echo "make build needs VERSION. Run git fetch --tags, or set VERSION=<release>"; exit 1; }
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/falcon ./cmd/falcon

run:
	go run ./cmd/falcon

tidy:
	go mod tidy
