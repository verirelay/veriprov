English | [简体中文](deployment.zh-CN.md)

# Deployment

## Files

Every file lives in the gitignored `production-secrets/` directory, which [`docker-compose.yaml`](../docker-compose.yaml) mounts read-only:

| File | Content |
| --- | --- |
| `identity-key.pem` | The VeriProv Identity Key (`VERIPROV_IDENTITY_KEY_FILE`). |
| `challenge-key` | The challenge key (`VERIPROV_CHALLENGE_KEY_FILE`). |
| `bootstrap.json` | A Bootstrap. |
| `runtime-config.json` | The Runtime Config for CVMs launched with that Bootstrap. |
| `deployments.json` | The deployments file (`VERIPROV_DEPLOYMENTS_FILE`). |
| `attestation-policy.json` | The Attestation policy (`VERIPROV_ATTESTATION_POLICY_FILE`). |

The formats are in [Configuration](configuration.md). Every replica uses the same files.

The commands in the next three sections run in `production-secrets/`.

## Keys

Create the VeriProv Identity Key and the challenge key, and print the public key of the VeriProv Identity Key in the form a Bootstrap takes:

```bash
mkdir -p production-secrets && cd production-secrets
openssl genpkey -algorithm ed25519 -out identity-key.pem
openssl rand -out challenge-key 32
openssl pkey -in identity-key.pem -pubout -outform DER | tail -c 32 | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

## Bootstrap

The Operator makes one Bootstrap for the CVMs that share a Runtime Config, with this VeriProv's HTTPS origin as `url` and the public key printed above as `identity_public_key`:

```bash
identity_public_key="<identity public key>"
printf '{"version":"veriprov-bootstrap/1","protocol":"veriprov/1","url":"https://veriprov.example.com","identity_public_key":"%s"}' "$identity_public_key" > bootstrap.json
```

The fields are in [Guest files](https://github.com/verirelay/protocol/blob/main/docs/guest.md), section "Bootstrap". Every deployment needs its own Bootstrap bytes. Set `profile` to tell apart Bootstraps that would otherwise be identical.

The Operator launches each CVM with the exact bytes of this file on the Config Disk and their SHA-256 as `host-data`, as shown in VeriForge's [QEMU verification](https://github.com/verirelay/veriforge/blob/main/docs/qemu.md), section "SEV-SNP launch".

VeriProv is configured with the same file: any byte difference, including whitespace or a trailing newline, changes `HOST_DATA`. A CVM whose `HOST_DATA` belongs to no deployment gets `409 policy.denied`.

The startup log lists the `HOST_DATA` of every deployment in hex, as `sha256sum bootstrap.json` prints it.

## Deployments

1. Write the Runtime Config for the CVMs launched with the Bootstrap.
2. List the pair in the deployments file.
3. Allow the Launch Measurements those CVMs may run.

```bash
printf '{"version":"verirelay-runtime-config/1","admin_token":"%s"}' "$(openssl rand -hex 32)" > runtime-config.json
printf '[{"bootstrap_file":"bootstrap.json","runtime_config_file":"runtime-config.json"}]' > deployments.json
printf '{"allowed_measurements":["%s"]}' "<96 lowercase hex chars>" > attestation-policy.json
```

Each release lists its Launch Measurements, one per vCPU count. See Release's [Launch Measurement](https://github.com/verirelay/release/blob/main/docs/launch-measurement.md).

## docker-compose.yaml

The root [`docker-compose.yaml`](../docker-compose.yaml) runs the published image `ghcr.io/verirelay/veriprov:v0.1.0`, hardened:

- Read-only rootfs
- All capabilities dropped
- `no-new-privileges`
- A `127.0.0.1:8080` port mapping

The container runs as UID 65532 (`nonroot`), so the files must be readable by that user. From the repository root:

```bash
sudo chown -R 65532:65532 production-secrets
docker compose up -d
```

In production, pin the image by digest: `image: ghcr.io/verirelay/veriprov@sha256:...`.

## Tags and digests

| Tag | Meaning |
| --- | --- |
| `sha-<full commit>` | Immutable identity, pushed by every build and never re-pointed. |
| `<version>` (e.g. `v0.1.0`) | Formal release tag. |
| `latest` | The latest formal release. |

The digest `ghcr.io/verirelay/veriprov@sha256:...` is the identity for deployment and verification.

Each release's `veriprov-component-build.json` records:

- The image digest
- The sha256 of `/veriprov` inside the image
- Both base images

Signature and SBOM attestation verify with pull access alone:

```bash
cosign verify ghcr.io/verirelay/veriprov@<digest> \
  --certificate-identity-regexp '^https://github\.com/verirelay/veriprov/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation ghcr.io/verirelay/veriprov@<digest> \
  --type spdxjson \
  --certificate-identity-regexp '^https://github\.com/verirelay/veriprov/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The image and each release asset also carry a GitHub artifact attestation. Verify the image's with the GitHub CLI:

```bash
gh attestation verify oci://ghcr.io/verirelay/veriprov@<digest> \
  --repo verirelay/veriprov \
  --signer-workflow verirelay/veriprov/.github/workflows/release.yml
```

## Reproducibility

- **Reproducible binary**: the same commit and Dockerfile yield the same `/veriprov` sha256 locally and in CI.
- **Builder-scoped image digest**: the image index digest is stable within one builder, and the release workflow pins its BuildKit builder by digest.
- **Detached provenance**: the signature, the SBOM and the GitHub artifact attestation are OCI referrers and leave the image digest unchanged.
