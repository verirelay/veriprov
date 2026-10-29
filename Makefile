.PHONY: build test lint check clean

DIST_DIR := dist
VERIPROV := $(DIST_DIR)/veriprov

build:
	mkdir -p $(DIST_DIR)
	go build -o $(VERIPROV) ./cmd/veriprov

test:
	go test ./...

lint:
	golangci-lint run

check: test build lint

clean:
	rm -rf $(DIST_DIR)
