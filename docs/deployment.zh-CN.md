[English](deployment.md) | 简体中文

# 部署

## 文件

所有文件都放在已被 gitignore 的 `production-secrets/` 目录，[`docker-compose.yaml`](../docker-compose.yaml) 以只读方式挂载它：

| 文件 | 内容 |
| --- | --- |
| `identity-key.pem` | VeriProv 身份密钥（`VERIPROV_IDENTITY_KEY_FILE`） |
| `challenge-key` | challenge 密钥（`VERIPROV_CHALLENGE_KEY_FILE`） |
| `bootstrap.json` | 一个引导文件 |
| `runtime-config.json` | 下发给用该引导文件启动的 CVM 的运行配置 |
| `deployments.json` | 部署文件（`VERIPROV_DEPLOYMENTS_FILE`） |
| `attestation-policy.json` | 远程证明 policy（`VERIPROV_ATTESTATION_POLICY_FILE`） |

文件格式见 [配置](configuration.zh-CN.md)。每个副本使用相同的文件。

接下来三节的命令都在 `production-secrets/` 中执行。

## 密钥

创建 VeriProv 身份密钥和 challenge 密钥，并按引导文件所需的形式打印该身份密钥的公钥：

```bash
mkdir -p production-secrets && cd production-secrets
openssl genpkey -algorithm ed25519 -out identity-key.pem
openssl rand -out challenge-key 32
openssl pkey -in identity-key.pem -pubout -outform DER | tail -c 32 | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

## 引导文件

运营者为共用同一份运行配置的 CVM 制作一个引导文件，其中 `url` 是本 VeriProv 的 HTTPS origin，`identity_public_key` 是上面打印的公钥：

```bash
identity_public_key="<身份公钥>"
printf '{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"https://veriprov.example.com","identity_public_key":"%s"}' "$identity_public_key" > bootstrap.json
```

字段见 [Guest 文件](https://github.com/verirelay/protocol/blob/main/docs/guest.zh-CN.md)的「引导文件（Bootstrap）」一节。每个部署都需要各自不同的引导文件字节。用 `profile` 区分原本会完全相同的引导文件。

运营者启动每个 CVM 时，把这个文件的原始字节放在配置盘上，并把它的 SHA-256 作为 `host-data`，做法见 VeriForge 的 [QEMU 验证](https://github.com/verirelay/veriforge/blob/main/docs/qemu.zh-CN.md)中「SEV-SNP 启动」一节。

VeriProv 配置的也是同一个文件：任何字节差异（包括空白或末尾换行）都会改变 `HOST_DATA`。`HOST_DATA` 不属于任何部署的 CVM 会收到 `409 policy.denied`。

启动日志以十六进制列出每个部署的 `HOST_DATA`，与 `sha256sum bootstrap.json` 的输出一致。

## 部署

1. 为用该引导文件启动的 CVM 写好运行配置
2. 在部署文件中列出这一对文件
3. 允许这些 CVM 可以运行的启动度量

```bash
printf '{"version":"verirelay-runtime-config/1","admin_token":"%s"}' "$(openssl rand -hex 32)" > runtime-config.json
printf '[{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"}]' > deployments.json
printf '{"allowed_measurements":["%s"]}' "<96 个小写十六进制字符>" > attestation-policy.json
```

每个 release 按 vCPU 数各列出一个启动度量。见 Release 的 [启动度量](https://github.com/verirelay/release/blob/main/docs/launch-measurement.zh-CN.md)。

## docker-compose.yaml

仓库根目录的 [`docker-compose.yaml`](../docker-compose.yaml) 以加固方式运行已发布的镜像 `ghcr.io/verirelay/veriprov:v0.1.0`：

- 只读 rootfs
- drop 全部 capabilities
- `no-new-privileges`
- 端口映射 `127.0.0.1:8080`

容器以 UID 65532（`nonroot`）运行，文件必须对该用户可读。在仓库根目录执行：

```bash
sudo chown -R 65532:65532 production-secrets
docker compose up -d
```

生产环境按 digest 固定镜像：`image: ghcr.io/verirelay/veriprov@sha256:...`。

## Tag 与 digest

| Tag | 含义 |
| --- | --- |
| `sha-<完整 commit>` | 不可变身份，每次构建都推送，不会被改指 |
| `<版本号>`（如 `v0.1.0`） | 正式版本 tag |
| `latest` | 最新的正式版本 |

部署和验证用的身份是 digest `ghcr.io/verirelay/veriprov@sha256:...`。

每个 release 的 `veriprov-component-build.json` 记录：

- 镜像 digest
- 镜像内 `/veriprov` 的 sha256
- 两个基础镜像

签名和 SBOM attestation 只凭拉取权限即可验证：

```bash
cosign verify ghcr.io/verirelay/veriprov@<digest> \
  --certificate-identity-regexp '^https://github\.com/verirelay/veriprov/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation ghcr.io/verirelay/veriprov@<digest> \
  --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/verirelay/veriprov/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

镜像和每个 release 资产还带有 GitHub artifact attestation。用 GitHub CLI 验证镜像的 attestation：

```bash
gh attestation verify oci://ghcr.io/verirelay/veriprov@<digest> \
  --repo verirelay/veriprov \
  --signer-workflow verirelay/veriprov/.github/workflows/release.yml
```

## 可复现性

- **二进制可复现**：同一 commit 和 Dockerfile 在本地和 CI 得到相同的 `/veriprov` sha256
- **镜像 digest 随 builder 固定**：镜像 index digest 在同一 builder 内稳定，release workflow 按 digest 钉死 BuildKit builder
- **溯源信息外挂**：签名、SBOM 和 GitHub artifact attestation 都是 OCI referrer，不改变镜像 digest
