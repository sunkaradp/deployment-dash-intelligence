# Security Policy

## Supported versions

Security fixes are currently provided for the latest version on the default branch. This project is an actively developed MVP; no production support or security SLA is offered.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in public issues or discussions.

Use GitHub's **Report a vulnerability** flow in the repository's Security tab if private vulnerability reporting is enabled. If it is unavailable, contact the maintainer privately through the GitHub profile: https://github.com/sunkaradp

Include:
- A concise description and impact.
- Affected version or commit.
- Reproduction steps or a minimal proof of concept.
- Any suggested mitigation.

Please allow reasonable time for investigation and a coordinated fix before public disclosure. Do not access, modify, or exfiltrate data that is not yours while validating a report.

## Security expectations

- Never submit real credentials, kubeconfigs, tokens, private keys, customer manifests, or production data in issues, pull requests, demos, or screenshots.
- Rotate any credential that may have been exposed; deleting it from a later commit is not sufficient.
- Treat all findings as advisory until independently validated against the target cluster and workload.
- The browser application is intended to analyze files locally. The optional FastAPI service currently has no authentication or rate limiting and must not be exposed to the public internet without additional controls.

## Scope and limitations

This project is not a Kubernetes admission controller, runtime security product, compliance certification, or substitute for cluster-specific security review. See [the limitations](docs/LIMITATIONS.md) and [threat model](THREAT_MODEL.md).
