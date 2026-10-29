[English](configuration.md) | 简体中文

# 配置

VeriProv 通过 `VERIPROV_*` 环境变量配置，必填变量缺失或任何值不合法时都不会启动。

它读取的每个文件都必须是不超过 1 MiB 的非空普通文件。

## 服务

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `VERIPROV_ADDR` | `:8080` | HTTP 监听地址 |
| `VERIPROV_LOG_LEVEL` | `info` | 日志级别：`debug`、`info`、`warn` 或 `error` |
| `VERIPROV_READ_TIMEOUT` | `15s` | HTTP read timeout，正 duration |
| `VERIPROV_READ_HEADER_TIMEOUT` | `5s` | HTTP read-header timeout，正 duration |
| `VERIPROV_WRITE_TIMEOUT` | `30s` | HTTP write timeout，正 duration |
| `VERIPROV_IDLE_TIMEOUT` | `60s` | HTTP idle timeout，正 duration |
| `VERIPROV_SHUTDOWN_TIMEOUT` | `10s` | 优雅退出超时，正 duration |
| `VERIPROV_MAX_BODY_BYTES` | `4194304` (4 MiB) | 最大请求 body，正整数 |
| `VERIPROV_MAX_CONCURRENCY` | `64` | 最大并发请求数，正整数 |
| `VERIPROV_CHALLENGE_TTL` | `1m` | challenge 有效期，正整数秒 |

## 密钥

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `VERIPROV_IDENTITY_KEY_FILE` | 必填 | VeriProv 身份密钥：一个 PEM `PRIVATE KEY`（PKCS #8）块中的 Ed25519 私钥 |
| `VERIPROV_CHALLENGE_KEY_FILE` | 必填 | challenge 密钥：恰好 32 字节，用于认证 `challenge_id` |

两个密钥都是 secret。每个副本使用相同的两个密钥。创建方法见 [部署](deployment.zh-CN.md)。

## 部署

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `VERIPROV_DEPLOYMENTS_FILE` | 必填 | 部署文件路径 |

部署文件是非空 JSON 列表。它按严格规则解码：未知字段和重复键都会被拒绝。

每一项把一个引导文件与下发给用它启动的 CVM 的运行配置配成一对：

```json
[{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"}]
```

| 字段 | 规则 |
| --- | --- |
| `bootstrap_file` | 必填，引导文件路径 |
| `runtime_config_file` | 必填，运行配置文件路径 |

两个字段中的相对路径都相对于部署文件所在目录。

启动时 VeriProv 检查每一项：

- 引导文件合法，见 [Guest 文件](https://github.com/verirelay/protocol/blob/main/docs/guest.zh-CN.md)的「引导文件（Bootstrap）」一节
- 引导文件的 `identity_public_key` 是 `VERIPROV_IDENTITY_KEY_FILE` 的公钥
- 任意两项的引导文件字节都不相同
- 运行配置是合法的 `verirelay-runtime-config/1` object，格式见 [Protocol 线协议](https://github.com/verirelay/protocol/blob/main/docs/veriprov1.zh-CN.md)的「运行配置」一节（schema：[`schemas/veriprov1/verirelay_runtime_config.schema.json`](https://github.com/verirelay/protocol/blob/main/schemas/veriprov1/verirelay_runtime_config.schema.json)）

运行配置各字段的作用见 VeriRelay 的 [configuration.zh-CN.md](https://github.com/verirelay/verirelay/blob/main/docs/configuration.zh-CN.md) 中「VeriProv 下发的运行配置」一节。

一个部署的 `HOST_DATA` 是其引导文件原始字节的 SHA-256。证明报告携带该 `HOST_DATA` 的配置下发请求，收到的是该部署运行配置文件的原始字节。

运行配置整体是 secret，包括 `admin_token` 和 store 密码。

## 远程证明

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `VERIPROV_ATTESTATION_POLICY` | 空 | inline 远程证明 policy JSON |
| `VERIPROV_ATTESTATION_POLICY_FILE` | 空 | 远程证明 policy 文件路径 |
| `VERIPROV_SEVSNP_CHECK_REVOCATIONS` | `true` | AMD 吊销检查，`false` 只适合受控的离线部署 |
| `VERIPROV_SEVSNP_KDS_MAX_ATTEMPTS` | `4` | AMD KDS 请求尝试次数 |
| `VERIPROV_SEVSNP_KDS_INITIAL_BACKOFF` | `250ms` | 初始重试退避 |
| `VERIPROV_SEVSNP_KDS_MAX_BACKOFF` | `2s` | 最大重试退避 |
| `VERIPROV_SEVSNP_KDS_ATTEMPT_TIMEOUT` | `10s` | 单次 KDS 请求超时 |
| `VERIPROV_SEVSNP_KDS_MAX_RESPONSE_BYTES` | `1048576` (1 MiB) | KDS 响应最大字节数 |
| `VERIPROV_SEVSNP_KDS_CACHE_DIR` | 空 | 公开 AMD 证书/CRL 缓存目录，放在有界的可写 volume 上 |
| `VERIPROV_SEVSNP_KDS_CACHE_MAX_ENTRIES` | `256` | 缓存条目上限 |
| `VERIPROV_SEVSNP_KDS_CACHE_MAX_BYTES` | `33554432` (32 MiB) | 缓存大小上限 |

两个 policy 变量必须且只能设置一个。

VeriProv 从 AMD KDS（`kdsintf.amd.com`）获取 AMD 证书和 CRL 并缓存。开启吊销检查时，只要拿不到当前有效的 CRL，配置下发请求就返回 `503 service.unavailable`。

### 远程证明 policy

policy 是只有一个字段 `allowed_measurements` 的严格 JSON：VeriProv 接受的启动度量。它是非空且不重复的 48 字节值列表，小写十六进制。

```json
{"allowed_measurements":["<96 个小写十六进制字符>"]}
```
