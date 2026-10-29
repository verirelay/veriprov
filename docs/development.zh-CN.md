[English](development.md) | 简体中文

# 开发

## 环境要求

- Go，版本以 `go.mod` 为准
- Docker，用于镜像构建和 compose 部署

## 检查

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

| Workflow | 触发 | 内容 |
| --- | --- | --- |
| `ci.yml` | push 到 `main`、pull request、手动 dispatch | 单个 `check` job，覆盖 gofumpt、`go vet`、golangci-lint、`go test`、`CGO_ENABLED=0` 构建、`docker build` 以及 `actionlint` |
| `release.yml` | `v*` tag、手动 dispatch | 签名的 GHCR 镜像及其 SBOM 和 attestation，以及 GitHub release。见 [deployment.zh-CN.md](deployment.zh-CN.md) |
