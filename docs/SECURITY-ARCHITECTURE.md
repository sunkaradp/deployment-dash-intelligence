# Security Architecture

## Intended browser workflow

The frontend is designed to parse and analyze pasted or locally selected Kubernetes YAML in the browser. Kubescape SARIF/JSON import is also a local file operation. The user explicitly exports a JSON report when desired.

The application should not transmit manifest contents to third parties. Any future telemetry, hosted analysis, crash reporting, or remote integration must be documented and opt-in before release.

## Optional API

The repository includes a FastAPI endpoint:

- `GET /healthz`
- `POST /api/v1/analyze`

The request model limits the YAML string to 500,000 characters and the analyzer uses PyYAML's safe loader. These are useful baseline controls, not a complete abuse-resistance strategy.

The API currently has no authentication, authorization, rate limiting, request timeout policy, or tenant isolation. Do not expose it on a public network. A production service would additionally need transport security, identity and access controls, quotas, request and parser limits, safe logging, monitoring, and an operational response plan.

## Parsing and rendering

Both browser and backend parsers process untrusted user input. Parser safety must be tested independently in both implementations. Add strict input byte limits, document-count limits, nesting/alias protections, and bounded result rendering. Never render user-controlled content as raw HTML.

## CI/CD

Workflows should use least-privilege token permissions and pin third-party Actions to full commit SHAs. Workflow changes must be reviewed for untrusted pull-request input, shell interpolation, artifact handling, and permission escalation. Do not expose repository secrets to workflows triggered by untrusted fork pull requests.

## Data minimization

Do not log manifest bodies, SARIF contents, credentials, or other sensitive user input. Do not add persistent storage of uploaded files without a documented retention and deletion policy.
