.PHONY: build test test-integration lint release clean

build:
	go build -o bin/bouncing ./cmd/bouncing

test:
	go test ./...

test-integration:
	go test -tags integration ./...

test-coverage:
	go test -coverprofile=coverage.txt ./...
	go tool cover -html=coverage.txt

lint:
	golangci-lint run
	cd sdk/js && pnpm lint

lint-fix:
	golangci-lint run --fix

vet:
	go vet ./...

vulncheck:
	govulncheck ./...

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin/ dist/ coverage.txt

.DEFAULT_GOAL := build
