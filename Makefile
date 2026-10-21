.PHONY: test build run tidy vet

# VERSION is the release, such as 0.9.23. A build without it is refused.
# The dashboard and the listen log show this string. They must not say dev.
VERSION ?=

test:
	go test ./...

vet:
	go vet ./...

build:
	@test -n "$(VERSION)" && test "$(VERSION)" != "dev" || { echo "make build needs VERSION. Example: make build VERSION=0.9.23"; exit 1; }
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/falcon ./cmd/falcon

run:
	go run ./cmd/falcon

tidy:
	go mod tidy
