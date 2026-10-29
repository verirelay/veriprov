# Contributing

## Before opening a pull request

Run these checks (setup in [docs/development.md](docs/development.md)):

```bash
go run mvdan.cc/gofumpt@v0.12.0 -l .
go vet ./...
make check
actionlint
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

## Cross-repo contracts

Some changes touch contracts shared with other repositories and need coordinated changes in every affected repo:

- **`veriprov/1` Provisioning**: challenge and provision messages, `REPORT_DATA` binding, the signed HPKE envelope, and the `verirelay-runtime-config/1` Runtime Config, all defined in [Protocol](https://github.com/verirelay/protocol/blob/main/docs/veriprov1.md). Affected: protocol, the verirelay client.
- **`veriprov-bootstrap/1` Bootstrap**: the Bootstrap and its `HOST_DATA` binding, defined in [Protocol](https://github.com/verirelay/protocol/blob/main/docs/guest.md). Affected: protocol, the verirelay client, the veriforge launch docs.
- **`verirelay-component-build/1` component build report**: written by the release workflow (`veriprov-component-build.json`). Shared with verirelay and veriforge.

verirelay, veriprov, and veriforge must use the same protocol version. Open the companion pull requests together and reference them from each other.

## Reporting security issues

Vulnerabilities go through private reporting. See [SECURITY.md](SECURITY.md).
