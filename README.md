# Deployment Dash Intelligence

A read-only Kubernetes manifest analyzer for catching configuration and security issues before deployment.

**[Open the live demo](https://sunkaradp.github.io/deployment-dash-intelligence/)** · **[View the source](https://github.com/sunkaradp/deployment-dash-intelligence)** · **[Report a bug](https://github.com/sunkaradp/deployment-dash-intelligence/issues)**

Deployment Dash Intelligence reviews Kubernetes YAML and JSON manifests, explains findings, and suggests what to look at next. It is an early-stage open-source project; findings are advisory and are not a substitute for a full policy engine, admission controls, or runtime security.

## What it does

- Analyzes Kubernetes YAML and JSON manifests in the browser.
- Handles multi-document YAML.
- Reports configuration and container-hardening findings with severity, evidence paths, and remediation suggestions.
- Calculates a transparent, heuristic 0–100 risk score from explicit rule weights.
- Imports Kubescape SARIF reports for review in the dashboard.
- Provides a Node.js CLI and a composite GitHub Action using the shared TypeScript rules engine.
- Includes an optional FastAPI endpoint for private/local integrations.

## Try it

Open the [live demo](https://sunkaradp.github.io/deployment-dash-intelligence/) and load a Kubernetes YAML or JSON manifest.

The browser uses the TypeScript rules engine locally by default. The public static demo does not require Kubernetes credentials or a hosted API. Do not upload secrets, kubeconfigs, private keys, customer manifests, or production data to the public demo.

## Checks included

The built-in deterministic checks cover:

- Replica count and CPU/memory requests and memory limits.
- Required container images and image tag pinning.
- Readiness and liveness probes.
- Privileged mode and privilege escalation.
- Non-root execution and UID 0.
- Read-only root filesystems and Linux capabilities.
- Seccomp profiles.
- Host namespaces, host networking, host ports, and hostPath volumes.
- Explicit service-account-token automounting.

These rules intentionally flag configurations that may deserve review, including missing hardening settings. A finding is not automatically proof of exploitability. Validate recommendations against application requirements, cluster defaults, and your admission policy.

The analyzer checks Pod-level and container-level security-context settings where Kubernetes supports inheritance or overrides. It does not inspect live cluster defaults, service-account configuration, admission policies, image contents, or runtime state.

## Run locally

### Frontend

Requirements: Node.js and npm.

```bash
git clone https://github.com/sunkaradp/deployment-dash-intelligence.git
cd deployment-dash-intelligence/frontend
npm ci
npm run dev
```

Vite prints the local development URL after startup.

### CLI

The CLI uses the same TypeScript rules module as the browser and composite GitHub Action.

From the `frontend/` directory:

```bash
npm ci
npm run deploydash -- ../path/to/kubernetes/manifests
```

For machine-readable output:

```bash
npm run deploydash -- ../path/to/kubernetes/manifests --json
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | No findings |
| `1` | Findings were detected |
| `2` | Input or analysis error |

The CLI scans YAML/JSON files with per-file and file-count limits. It does not connect to a cluster or modify files.

### GitHub Actions

Add the composite action to a workflow after checking out your repository:

```yaml
- uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
- uses: sunkaradp/deployment-dash-intelligence/.github/actions/deploydash@48933bca7a6bdf6a87be49f36a1c61a50e543294
  with:
    path: ./k8s
    fail-on-findings: "true"
```

- Set `path` to the file or directory containing your manifests.
- Set `fail-on-findings: "true"` to fail the step when findings are detected.
- Set `fail-on-findings: "false"` to report findings without failing the step.
- Set `output: "json"` for machine-readable output.

The action currently runs the read-only scan. It does not post inline pull-request comments or publish its own SARIF report. Pin the action to a reviewed commit SHA in production workflows and review updates before changing the pin.

### Optional FastAPI backend

The API is a separate, optional integration surface. It is not required by the public browser demo.

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload --host 127.0.0.1
```

Available endpoints:

- Health check: `GET /healthz`
- Analyze a manifest: `POST /api/v1/analyze`
- Interactive API docs: `http://127.0.0.1:8000/docs` while the API is running.

**Keep this API private and bound to loopback.** Do not bind it to `0.0.0.0` or expose it through a public reverse proxy. It currently has no authentication, authorization, or rate limiting.

If you build and run the container image, publish the port only on loopback:

```bash
docker build -t deployment-dash-intelligence .
docker run --rm -p 127.0.0.1:8000:8000 deployment-dash-intelligence
```

Loopback binding is a deployment precaution, not a substitute for missing access controls.

## Kubescape pull-request review

The `.github/workflows/kubescape-review.yml` workflow runs Kubescape against repository configuration when a pull request or push changes Kubernetes YAML, Helm chart metadata, or Kustomize files. It evaluates the NSA and MITRE frameworks, publishes SARIF to GitHub Code Scanning, and retains a downloadable SARIF artifact for 14 days.

This is a manifest-only workflow; it does not require Kubernetes cluster credentials or a Kubescape cloud account. Findings are advisory in this first iteration, so the Kubescape step is allowed to complete while teams assess signal quality.

### Import a Kubescape report

1. Open the repository's **Actions** tab and select the **Deployment Dash — Kubescape review** run.
2. Download and extract the `kubescape-sarif-report` artifact.
3. Open Deployment Dash and choose **Upload YAML / SARIF**.
4. Select `kubescape-results.sarif` (or its JSON report file).
5. Review the imported findings.

Severity and score shown in the dashboard are display mappings; they are not Kubescape's compliance score. GitHub Code Scanning results are also available under **Security → Code scanning** when enabled for the repository.

The dashboard does not currently connect to GitHub or fetch reports automatically. Import is a deliberate local file action.

## How the analyzer works

| Part | Technology | Responsibility |
|---|---|---|
| Frontend | React, TypeScript, Vite | Manifest editor and analysis results |
| Shared rules engine | TypeScript, js-yaml | Deterministic checks used by the browser, Node CLI, and GitHub Action |
| Optional API | Python, FastAPI, PyYAML | Versioned analysis endpoint |
| Tests and quality | pytest, Ruff, TypeScript, Node test runner, Vite, GitHub Actions | Backend tests and linting, analyzer fixtures, type checks, and frontend build |
| Hosting | GitHub Pages | Public static frontend |

The optional Python API has its own Python implementation. Exact parity between the browser/Node analyzer and Python API is not currently claimed.

## Risk score and limitations

The score is the capped sum of explicit rule weights. Severity and recommendations come from deterministic rules, not an LLM. The score is an advisory prioritization signal, not a probability of outage, a compliance certification, or proof that a workload is safe.

Keep these limitations in mind:

- Analysis is based on submitted manifests only.
- The app does not connect to, deploy to, patch, restart, or otherwise modify a Kubernetes cluster.
- It does not inspect live cluster state, admission policies, image contents, or runtime behavior.
- A missing probe is a prompt for review, not proof that an application is unhealthy.
- Recommendations must be checked against the needs of the workload before being applied.

## Security and responsible use

Please read these documents before using, contributing to, or deploying the project:

- [Security policy](SECURITY.md) — reporting vulnerabilities privately.
- [Threat model](THREAT_MODEL.md) — assets, trust boundaries, threats, and mitigations.
- [Security architecture](docs/SECURITY-ARCHITECTURE.md) — input handling and deployment boundaries.
- [Product limitations](docs/LIMITATIONS.md) — supported scope and what findings do not prove.
- [Contributing guide](CONTRIBUTING.md) — development and pull-request expectations.
- [Code of Conduct](CODE_OF_CONDUCT.md) — community expectations.
- [Public release checklist](docs/RELEASE-CHECKLIST.md) — release gates and outstanding verification.

**Important:** The optional FastAPI endpoint is private/local only and currently has no authentication, authorization, or rate limiting. Do not expose it to the public internet. Do not submit secrets, kubeconfigs, private keys, customer manifests, or production data to the public demo. The browser workflow is intended to process files locally, but verify network behavior before relying on that property for sensitive data.

## Contributing

Bug reports, reproducible examples, and thoughtful suggestions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. When reporting a finding, include a minimal synthetic manifest and expected behavior; do not include credentials or customer data.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Project status

Deployment Dash Intelligence is an actively developed MVP. Some release-readiness checks remain open, including independent security review and observed browser network verification. See the [public release checklist](docs/RELEASE-CHECKLIST.md) for the current status.

The project is built and maintained by **Durga Prasad Sunkara**.
