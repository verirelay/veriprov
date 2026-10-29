# Security policy

## Reporting a vulnerability

Report vulnerabilities through GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**.

Do not open public issues, pull requests, or discussions for suspected vulnerabilities.

## Scope

Reports are in scope when they affect the code in this repository:

- The `veriprov/1` Provisioning service
- SEV-SNP Attestation verification (VCEK chain, revocations, guest policy, Launch Measurement policy)
- Challenge handling
- Deployment selection by `HOST_DATA`
- HPKE sealing and signing of the Runtime Config

Findings that only concern third-party dependencies should be reported upstream as well.
