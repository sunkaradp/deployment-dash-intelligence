# Threat Model

**Status:** Initial, documentation-based model. This is not an independent security assessment.

## Product boundary

Deployment Dash Intelligence analyzes supported Kubernetes workload manifests and imported Kubescape SARIF reports. The intended browser workflow is local and read-only. It does not need Kubernetes credentials and does not connect to a cluster.

The repository also contains an optional FastAPI analysis endpoint. The endpoint accepts YAML and returns analysis results. It has no authentication, authorization, rate limiting, or tenant isolation and must remain private/local.

## Assets to protect

- User-supplied manifests, which may contain internal names, image references, environment values, annotations, or accidentally embedded secrets.
- Imported SARIF reports, which may contain repository paths and infrastructure details.
- Repository integrity, release artifacts, GitHub Actions permissions, and maintainer credentials.
- Availability of the browser, CLI, GitHub Action, and optional API analyzer.
- Accuracy and integrity of findings and recommendations.

## Trust boundaries and data flows

1. A user pastes YAML or selects a local file in the browser.
2. The browser parses and analyzes manifest content locally.
3. A user may import a SARIF/JSON report from a local file.
4. A user may export a JSON report to their device.
5. The CLI or composite GitHub Action reads files in the caller's workspace and emits findings.
6. Separately, a caller may send YAML to the optional FastAPI endpoint.

The browser, CLI, GitHub Action, and API are separate execution paths. Shared TypeScript rules are used by the browser, CLI, and action. The Python API has a separate implementation; parity is tested against shared fixtures, not formally guaranteed for every possible YAML input.

## Threats and mitigations

| Threat | Current assessment | Required mitigation |
|---|---|---|
| Accidental disclosure through manifests | Browser workflow is designed for local processing; files may still contain sensitive values | Do not upload secrets or customer data; verify network behavior before relying on local-only processing for sensitive workloads; keep telemetry out of manifest paths |
| Denial of service via complex YAML | Browser and backend enforce a 1 MB input bound and 100-document limit; backend also bounds aliases and nesting; both analyzers bound findings | Keep limits covered by adversarial tests; fuzz parser behavior; review limits whenever parser versions change |
| SARIF/JSON resource exhaustion or unsafe rendering | SARIF import caps result count at 5,000 and validates external help links as HTTPS URLs; not every nested field/string is comprehensively schema-validated | Add structural validation and per-field string/array bounds; test malformed and adversarial SARIF |
| Public abuse of API | No authentication, authorization, rate limiting, or tenant isolation is present | Keep API local/private until identity controls, quotas, timeouts, safe logging, and deployment controls exist |
| Analyzer disagreement | Browser/CLI use TypeScript; API uses an independent Python implementation; shared fixtures compare selected behavior | Expand cross-engine fixtures and edge cases; document unsupported differences; do not claim universal parity |
| Supply-chain compromise in CI | Workflows use least-privilege permissions and many third-party actions are pinned to full commit SHAs; action pinning still needs periodic review | Audit every workflow and composite action; pin reviewed SHAs; update through reviewed changes; use lockfiles and reproducible installs |
| Secret exposure in repository history | A scheduled Gitleaks workflow scans reachable Git history | Review findings, rotate any exposed credential, and independently verify historical refs and forks where relevant |
| Misleading security conclusions | Rules are heuristic and manifest-only | Clearly state scope, rationale, false-positive risk, and limitations |
| Unsafe recommendations | Workload needs and cluster policy vary | Require human review; never auto-apply changes |
| Untrusted PR workflow behavior | CI and scanner workflows run on pull requests with restricted permissions | Keep least-privilege permissions, avoid secrets in fork PR workflows, review action code and shell interpolation |
| Browser UI injection | User-controlled values are rendered in the interface; help links are restricted to HTTPS | Keep React text rendering (not raw HTML); validate URLs and add adversarial rendering tests |

## Security invariants

- Browser analysis does not require cluster credentials.
- No cluster resource is created, patched, restarted, or deleted.
- The browser must not send manifest contents to an external service without explicit, documented consent.
- Findings are advisory, not proof of exploitability.
- The optional API must not be advertised as a public hosted service until separately hardened.
- Proposed YAML snippets are advisory and are never automatically applied.

## Out of scope for this initial version

Live cluster inspection, runtime detection, admission enforcement, image vulnerability scanning, cloud account security, and compliance certification.

## Review cadence

Revisit this model when adding network calls, persistence, authentication, a hosted API, integrations, automated remediation, or new file formats. Re-run the threat review after material parser, dependency, or workflow changes.
