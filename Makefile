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

gosec:
	gosec -exclude=G101,G118,G124,G202,G304,G306,G602,G703 ./...

scan-fs:
	trivy fs --severity HIGH,CRITICAL .

scan-iac:
	trivy config --severity HIGH,CRITICAL .

sast:
	semgrep scan --config=auto --error .

security: vulncheck gosec scan-fs sast  ## Run all security checks

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin/ dist/ coverage.txt

.DEFAULT_GOAL := build
