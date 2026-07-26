# Security

## Reporting a vulnerability

Use GitHub's
[private vulnerability reporting](https://github.com/enclava-labs/confidential-inference-sdk/security/advisories/new).
Do not open a public issue for an undisclosed vulnerability.

Include:

- the affected version or commit;
- the relevant provider, evidence family, or integration surface;
- steps to reproduce the issue;
- the security impact and any known mitigations.

Do not include API keys, signing keys, production evidence, customer data, or
other secrets. Use minimal synthetic fixtures whenever possible.

## Supported versions

While the SDK is in preview, security fixes target the latest `0.1.x` release
and the `main` branch. Older snapshots are not maintained.

## Security boundary

Fixture evidence and demo signing keys are test material. They are not
production trust roots. Production deployments are responsible for their
policies, trusted signing keys, provider-published artifacts, collateral,
credential handling, and live-conformance review.
