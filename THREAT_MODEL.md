# Threat Model

**Status:** Initial, documentation-based model. This is not an independent security assessment.

## Product boundary

Deployment Dash Intelligence analyzes Kubernetes workload manifests and imported Kubescape SARIF reports. The intended browser workflow is local and read-only. It does not need Kubernetes credentials and does not connect to a cluster.

The repository also contains an optional FastAPI analysis endpoint. The current endpoint accepts a YAML string and returns analysis results. It has no authentication, authorization, rate limiting, or tenant isolation.

## Assets to protect

- User-supplied manifests, which may contain internal names, image references, environment values, annotations, or accidentally embedded secrets.
- Imported SARIF reports, which may contain repository paths and infrastructure details.
- Repository integrity, release artifacts, GitHub Actions permissions, and maintainer credentials.
- Availability of the browser and optional API analyzer.
- Accuracy and integrity of findings and recommendations.

## Trust boundaries and data flows

1. A user pastes YAML or selects a local file in the browser.
2. The browser parses and analyzes manifest content and renders findings.
3. A user may import a SARIF/JSON report from a local file.
4. A user may export a JSON report to their device.
5. Separately, a caller may send YAML to the optional FastAPI endpoint.

The browser UI and API are separate execution paths. Do not assume that local browser behavior provides security controls for a separately deployed API.

## Threats and mitigations

| Threat | Current assessment | Required mitigation |
|---|---|---|
| Accidental disclosure through uploaded manifests | Manifests can contain sensitive values; browser workflow is intended to be local | Warn users before import; keep data out of telemetry and logs; test network behavior |
| Denial of service via oversized or complex YAML/SARIF | API has a 500,000-character model limit; browser file path has no visible size guard in the reviewed source | Enforce byte, document, nesting, alias, and finding-count limits in both paths |
| Public abuse of API | No authentication or rate limiting is present | Keep API local/private until authentication, quotas, request limits, and deployment controls exist |
| Malformed YAML and parser edge cases | Backend uses PyYAML safe_load_all; browser uses js-yaml loadAll | Fuzz and test parser limits, duplicate keys, aliases, deeply nested structures, and malformed input |
| Supply-chain compromise in CI | Several Actions use mutable version tags; Kubescape action uses @main | Pin actions to reviewed full commit SHAs; automate update review |
| Secret exposure in repository history | Current files reviewed are not a complete history scan | Run secret scanning across every reachable commit and rotate any exposed credential |
| Misleading security conclusions | Rules are heuristic and manifest-only | Clearly state scope, rationale, false-positive risk, and limitations |
| Unsafe recommendations | Workload needs and cluster policy vary | Require human review; never auto-apply changes |
| Untrusted PR workflow behavior | CI and scanner workflows run on pull_request | Keep least-privilege permissions, avoid secrets in fork PR workflows, pin actions, review action code |
| SARIF/JSON input abuse | Imported JSON is parsed client-side | Bound file size and result counts; validate structure and string lengths before rendering |

## Security invariants

- No cluster credentials are required for browser analysis.
- No cluster resource is created, patched, restarted, or deleted.
- User-supplied manifests must not be sent to an external service by the browser without explicit, documented consent.
- Findings are advisory, not proof of exploitability.
- The optional API must not be advertised as a public hosted service until separately hardened.

## Out of scope for this initial version

Live cluster inspection, runtime detection, admission enforcement, image vulnerability scanning, cloud account security, and compliance certification.

## Review cadence

Revisit this model when adding network calls, persistence, authentication, a hosted API, integrations, automated remediation, or new file formats.
