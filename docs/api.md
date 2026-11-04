English | [简体中文](api.zh-CN.md)

# Service API

VeriProv is the server side of `veriprov/1` Provisioning.

The [Protocol wire contract](https://github.com/verirelay/protocol/blob/main/docs/veriprov1.md) defines:

- The message shapes
- The `REPORT_DATA` key binding
- HPKE sealing
- The envelope signature
- The Runtime Config format

## Routes

| Method | Path | Request | Success response |
| --- | --- | --- | --- |
| `POST` | `/v1/challenge` | `ChallengeRequest` | `200` with `ChallengeResponse` |
| `POST` | `/v1/provision` | `ProvisionRequest` | `200` with `ProvisionResponse` |
| `GET` | `/v1/bootstraps` | none | `200` with the deployments' [Bootstraps](#bootstraps) |
| `GET` | `/healthz` | none | `200` with plain-text `ok` |
| `GET` | `/readyz` | none | `200` with plain-text `ok` |

## Headers

| Header | Rule |
| --- | --- |
| `Content-Type` | POST requests require `application/json`. `/healthz` and `/readyz` do not check it. |
| `Cache-Control` | JSON responses set `no-store`. |
| `X-Request-ID` | Every response carries it: the request's own `X-Request-ID` when it sends one, otherwise a generated ID. |

## Challenge

A challenge expires after `VERIPROV_CHALLENGE_TTL` and serves any number of provision requests until then.

VeriProv keeps no challenge state, so replicas with the same `VERIPROV_CHALLENGE_KEY_FILE` accept each other's challenges.

## Provisioning

VeriProv accepts an Attestation Report when all of these hold:

- Its `REPORT_DATA` matches the challenge binding.
- Its `CHIP_ID` is in the `allowed_chip_ids` of some deployment. VeriProv checks this before it contacts AMD KDS.
- It is VCEK-signed and verifies against the AMD certificates from AMD KDS and, with revocation checking on, a current AMD CRL.
- Its guest policy forbids debugging and migration agents (SMT is allowed).
- Its VMPL is 0.
- Its TCB fields are consistent with each other and with the VCEK.
- It meets the AMD platform baseline in [`avr/1` Receipts](https://github.com/verirelay/protocol/blob/main/docs/avr1.md), section "Platform baseline": its CPU model has a minimum, `REPORTED_TCB` and `LAUNCH_TCB` are at or above it, and `PLATFORM_INFO` has `ALIAS_CHECK_COMPLETE` set.
- Its Launch Measurement is in the Attestation policy.
- Its `HOST_DATA` belongs to a deployment, that is, it is the SHA-256 of one of the configured Bootstraps.
- Its `CHIP_ID` is in that deployment's `allowed_chip_ids`.

The `ProvisionResponse` envelope carries that deployment's Runtime Config, sealed to `provisioning_public_key` and signed with the VeriProv Identity Key.

Deployments and the Attestation policy are described in [Configuration](configuration.md).

VeriProv logs every refused report at `warn` level with its `request_id`:

| Message | Fields |
| --- | --- |
| `attestation verification failed` | `error` names the failed check. A platform baseline failure names the CPU model, its minimum `TCB_VERSION` and the AMD bulletins. |
| `provision rejected: unknown HOST_DATA` | The verified `host_data` and `chip_id`. |
| `provision rejected: CHIP_ID not in the deployment's allowed_chip_ids` | The verified `host_data` and `chip_id`. |

A report whose `CHIP_ID` no deployment allows fails before verification, and its unverified `CHIP_ID` is not logged.

## Bootstraps

`GET /v1/bootstraps` returns the Bootstrap of every deployment, in the order of the deployments file:

```json
{"bootstraps":[{"profile":"","host_data":"<64 hex chars>","bootstrap":"<unpadded base64url>"}]}
```

| Field | Content |
| --- | --- |
| `profile` | The Bootstrap's `profile`, empty when it has none. |
| `host_data` | The SHA-256 of the Bootstrap bytes in hex: the `HOST_DATA` of CVMs launched with it. |
| `bootstrap` | The exact Bootstrap file bytes. |

A host puts these exact bytes on a CVM's Config Disk, and Deploy fetches them here. Bootstraps are public: a CVM discloses its own in every attestation response.

## Errors

Error bodies are the Protocol's `ErrorResponse`, with `error.request_id` equal to `X-Request-ID`:

| HTTP | Code | Cause |
| ---: | --- | --- |
| 400 | `invalid_request.malformed_json` | Body is not a single JSON object, repeats a key, has a key that differs from its field name only in case, or has a value of the wrong type. |
| 400 | `invalid_request.invalid_field` | Wrong method, missing/invalid `Content-Type`, invalid field values, malformed Attestation Report, or unknown route. |
| 413 | `invalid_request.body_too_large` | Body exceeds `VERIPROV_MAX_BODY_BYTES`. |
| 404 | `challenge.not_found` | `challenge_id` was not issued under this challenge key. |
| 409 | `challenge.expired` | Challenge TTL elapsed. |
| 409 | `attestation.report_data_mismatch` | `REPORT_DATA` does not match the challenge binding. |
| 409 | `policy.denied` | The Attestation Report fails a check in [Provisioning](#provisioning) other than `REPORT_DATA`. |
| 503 | `envelope.hpke_failed` | Sealing or signing the Runtime Config failed. |
| 503 | `service.unavailable` | Concurrency limit reached, or AMD certificates or a current AMD CRL could not be obtained. |
| 500 | `internal.error` | Internal failure. |

## Health and readiness

`/readyz` answers like `/healthz`.

Health checks count toward the concurrency limit (`VERIPROV_MAX_CONCURRENCY`), so under load they can get `503 service.unavailable`.
