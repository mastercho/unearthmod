BINARIES := unearth unearth-mcp
DIST     := dist

.PHONY: build test cover lint vet fmt tidy install clean mcp

build:
	@mkdir -p $(DIST)
	@for b in $(BINARIES); do \
		echo "building $$b"; \
		CGO_ENABLED=0 go build -o $(DIST)/$$b ./cmd/$$b; \
	done

test:
	go test ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	golangci-lint run

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

install:
	go install ./cmd/...

clean:
	rm -rf $(DIST) coverage.out

# mcp target is wired in Packet 6
mcp:
	@echo "unearth-mcp target reserved for Packet 6"
