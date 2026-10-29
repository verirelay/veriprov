[English](api.md) | 简体中文

# 服务 API

VeriProv 是 `veriprov/1` 配置下发的服务端。

[Protocol 线协议](https://github.com/verirelay/protocol/blob/main/docs/veriprov1.zh-CN.md)定义：

- 消息格式
- `REPORT_DATA` 密钥绑定
- HPKE 加密封装
- envelope 签名
- 运行配置格式

## 路由

| 方法 | 路径 | 请求 | 成功响应 |
| --- | --- | --- | --- |
| `POST` | `/v1/challenge` | `ChallengeRequest` | `200`，`ChallengeResponse` |
| `POST` | `/v1/provision` | `ProvisionRequest` | `200`，`ProvisionResponse` |
| `GET` | `/healthz` | 无 | `200`，纯文本 `ok` |
| `GET` | `/readyz` | 无 | `200`，纯文本 `ok` |

## Header

| Header | 规则 |
| --- | --- |
| `Content-Type` | POST 请求要求 `application/json`，`/healthz` 和 `/readyz` 不检查 |
| `Cache-Control` | JSON 响应带 `no-store` |
| `X-Request-ID` | 所有响应都带：请求自带 `X-Request-ID` 时沿用其值，否则由服务生成 |

## Challenge

challenge 在 `VERIPROV_CHALLENGE_TTL` 后过期，过期前可用于任意多次配置下发请求。

VeriProv 不保存 challenge 状态，所以使用相同 `VERIPROV_CHALLENGE_KEY_FILE` 的副本互相接受对方的 challenge。

## 配置下发

证明报告满足以下全部条件时，VeriProv 才接受它：

- 由 VCEK 签名，能用从 AMD KDS 获取的 AMD 证书验证，开启吊销检查时还要通过当前有效的 AMD CRL
- `REPORT_DATA` 与 challenge 绑定一致
- guest policy 禁止调试和迁移代理（允许 SMT）
- VMPL 为 0
- TCB 字段彼此一致，且与 VCEK 一致
- 启动度量在远程证明 policy 中
- `HOST_DATA` 属于某个部署，即它是某个已配置引导文件的 SHA-256

`ProvisionResponse` 的 envelope 携带该部署的运行配置，加密给 `provisioning_public_key`，并用 VeriProv 身份密钥签名。

部署和远程证明 policy 见 [配置](configuration.zh-CN.md)。

## 错误

错误响应 body 是 Protocol 的 `ErrorResponse`，`error.request_id` 与 `X-Request-ID` 相同：

| HTTP | Code | 原因 |
| ---: | --- | --- |
| 400 | `invalid_request.malformed_json` | 请求 body 不是单个 JSON object，有重复键，有键与字段名仅大小写不同，或字段值类型错误 |
| 400 | `invalid_request.invalid_field` | 方法错误，`Content-Type` 缺失或不合法，字段值非法，证明报告格式错误，或路由不存在 |
| 413 | `invalid_request.body_too_large` | 请求 body 超过 `VERIPROV_MAX_BODY_BYTES` |
| 404 | `challenge.not_found` | `challenge_id` 不是用本 challenge 密钥签发的 |
| 409 | `challenge.expired` | challenge 已过期 |
| 409 | `attestation.report_data_mismatch` | `REPORT_DATA` 与 challenge 绑定不一致 |
| 409 | `policy.denied` | 证明报告未通过 [配置下发](#配置下发) 中除 `REPORT_DATA` 以外的某项检查 |
| 503 | `envelope.hpke_failed` | 加密封装或签名运行配置失败 |
| 503 | `service.unavailable` | 达到并发上限，或无法获取 AMD 证书或当前有效的 AMD CRL |
| 500 | `internal.error` | 内部错误 |

## 健康与就绪

`/readyz` 与 `/healthz` 的响应相同。

健康检查也计入并发上限（`VERIPROV_MAX_CONCURRENCY`），负载高时可能返回 `503 service.unavailable`。
