English | [简体中文](configuration.zh-CN.md)

# Configuration

VeriProv is configured through `VERIPROV_*` environment variables and does not start when a required variable is missing or a value is invalid.

Every file it reads must be a non-empty regular file of at most 1 MiB.

## Server

| Variable | Default | Description |
| --- | --- | --- |
| `VERIPROV_ADDR` | `:8080` | HTTP listen address. |
| `VERIPROV_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, or `error`. |
| `VERIPROV_READ_TIMEOUT` | `15s` | HTTP read timeout; positive duration. |
| `VERIPROV_READ_HEADER_TIMEOUT` | `5s` | HTTP read-header timeout; positive duration. |
| `VERIPROV_WRITE_TIMEOUT` | `30s` | HTTP write timeout; positive duration. |
| `VERIPROV_IDLE_TIMEOUT` | `60s` | HTTP idle timeout; positive duration. |
| `VERIPROV_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown timeout; positive duration. |
| `VERIPROV_MAX_BODY_BYTES` | `4194304` (4 MiB) | Maximum request body; positive integer. |
| `VERIPROV_MAX_CONCURRENCY` | `64` | Maximum concurrent requests; positive integer. |
| `VERIPROV_CHALLENGE_TTL` | `1m` | Challenge lifetime; positive whole number of seconds. |

## Keys

| Variable | Default | Description |
| --- | --- | --- |
| `VERIPROV_IDENTITY_KEY_FILE` | required | The VeriProv Identity Key: an Ed25519 private key in one PEM `PRIVATE KEY` (PKCS #8) block. |
| `VERIPROV_CHALLENGE_KEY_FILE` | required | The challenge key: exactly 32 bytes that authenticate `challenge_id`. |

Both keys are secrets. Every replica uses the same two keys. [Deployment](deployment.md) shows how to create them.

## Deployments

| Variable | Default | Description |
| --- | --- | --- |
| `VERIPROV_DEPLOYMENTS_FILE` | required | Path to the deployments file. |

The deployments file is a non-empty JSON list. It is decoded strictly: unknown fields and duplicate keys are rejected.

Each entry pairs a Bootstrap with the Runtime Config provisioned to CVMs launched with it:

```json
[{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"}]
```

| Field | Rule |
| --- | --- |
| `bootstrap_file` | Required. Path to a Bootstrap file. |
| `runtime_config_file` | Required. Path to a Runtime Config file. |

A relative path in either field is relative to the directory of the deployments file.

At startup VeriProv checks every entry:

- The Bootstrap is valid, as specified in [Guest files](https://github.com/verirelay/protocol/blob/main/docs/guest.md), section "Bootstrap".
- The Bootstrap's `identity_public_key` is the public key of `VERIPROV_IDENTITY_KEY_FILE`.
- No two entries have the same Bootstrap bytes.
- The Runtime Config is a valid `verirelay-runtime-config/1` object, as specified in the [Protocol wire contract](https://github.com/verirelay/protocol/blob/main/docs/veriprov1.md), section "Runtime Config" (schema: [`schemas/veriprov1/verirelay_runtime_config.schema.json`](https://github.com/verirelay/protocol/blob/main/schemas/veriprov1/verirelay_runtime_config.schema.json)).

What each Runtime Config field does is described in VeriRelay's [configuration.md](https://github.com/verirelay/verirelay/blob/main/docs/configuration.md), section "Runtime Config from VeriProv".

A deployment's `HOST_DATA` is the SHA-256 of its exact Bootstrap file bytes. A provision request whose Attestation Report carries that `HOST_DATA` receives the exact bytes of the deployment's Runtime Config file.

Runtime Config is a secret, `admin_token` and store passwords included.

## Attestation

| Variable | Default | Description |
| --- | --- | --- |
| `VERIPROV_ATTESTATION_POLICY` | empty | Inline Attestation policy JSON. |
| `VERIPROV_ATTESTATION_POLICY_FILE` | empty | Path to the Attestation policy file. |
| `VERIPROV_SEVSNP_CHECK_REVOCATIONS` | `true` | AMD revocation checking. `false` suits controlled offline deployments only. |
| `VERIPROV_SEVSNP_KDS_MAX_ATTEMPTS` | `4` | AMD KDS request attempts. |
| `VERIPROV_SEVSNP_KDS_INITIAL_BACKOFF` | `250ms` | Initial retry backoff. |
| `VERIPROV_SEVSNP_KDS_MAX_BACKOFF` | `2s` | Maximum retry backoff. |
| `VERIPROV_SEVSNP_KDS_ATTEMPT_TIMEOUT` | `10s` | Per-attempt KDS timeout. |
| `VERIPROV_SEVSNP_KDS_MAX_RESPONSE_BYTES` | `1048576` (1 MiB) | Maximum KDS response size. |
| `VERIPROV_SEVSNP_KDS_CACHE_DIR` | empty | Directory for the public AMD certificate/CRL cache, on a bounded writable volume. |
| `VERIPROV_SEVSNP_KDS_CACHE_MAX_ENTRIES` | `256` | Cache entry cap. |
| `VERIPROV_SEVSNP_KDS_CACHE_MAX_BYTES` | `33554432` (32 MiB) | Cache size cap. |

Exactly one of the two policy variables is required.

VeriProv fetches AMD certificates and CRLs from AMD KDS (`kdsintf.amd.com`) and caches them. With revocation checking on, provision requests fail with `503 service.unavailable` while no current CRL can be obtained.

### Attestation policy

The policy is strict JSON with a single field, `allowed_measurements`: the Launch Measurements VeriProv accepts. It is a non-empty list of unique 48-byte values in lowercase hex.

```json
{"allowed_measurements":["<96 lowercase hex chars>"]}
```
