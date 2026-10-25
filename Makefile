VERSION ?= dev

.PHONY: build test vet scan
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/reconciler ./cmd/reconciler

test:
	go test -race ./...

vet:
	go vet ./...

scan:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
