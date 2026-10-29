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

- It is VCEK-signed and verifies against the AMD certificates from AMD KDS and, with revocation checking on, a current AMD CRL.
- Its `REPORT_DATA` matches the challenge binding.
- Its guest policy forbids debugging and migration agents (SMT is allowed).
- Its VMPL is 0.
- Its TCB fields are consistent with each other and with the VCEK.
- Its Launch Measurement is in the Attestation policy.
- Its `HOST_DATA` belongs to a deployment, that is, it is the SHA-256 of one of the configured Bootstraps.

The `ProvisionResponse` envelope carries that deployment's Runtime Config, sealed to `provisioning_public_key` and signed with the VeriProv Identity Key.

Deployments and the Attestation policy are described in [Configuration](configuration.md).

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
