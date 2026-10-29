English | [简体中文](development.zh-CN.md)

# Development

## Prerequisites

- Go, at the version in `go.mod`.
- Docker, for the image build and compose deployment.

## Checks

```bash
go run mvdan.cc/gofumpt@v0.12.0 -l .
actionlint
make check                 # go test, go build, golangci-lint (gofmt + gofumpt)
go vet ./...
go test -race ./...
docker build .
docker compose -f docker-compose.yaml config
```

## CI

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yml` | Pushes to `main`, pull requests, manual dispatch | A single `check` job: gofumpt, `go vet`, golangci-lint, `go test`, a `CGO_ENABLED=0` build, a `docker build`, and `actionlint`. |
| `release.yml` | `v*` tags, manual dispatch | The signed GHCR image with its SBOM and attestations, and a GitHub release. See [deployment.md](deployment.md). |
