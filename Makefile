# Common developer entry points. Every target is also what CI runs.
BIN := bin/idpdoctor

.PHONY: build test vet lint check generate run-mcp clean

build:
	go build -o $(BIN) ./cmd/idpdoctor

test:
	go test ./...

vet:
	go vet ./...

# staticcheck is installed on demand into GOPATH/bin; pinned so CI is reproducible.
lint:
	go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...

check: vet test lint

# Re-renders docs/TAXONOMY.md from internal/finding/codes.go (the single source of truth).
generate:
	go generate ./...

run-mcp: build
	./$(BIN) mcp

clean:
	rm -rf bin dist
